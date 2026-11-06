"""
PhishGuard Pro AI — raqamli xavfsizlik va kiberhujumlar tahlili ekotizimi.
Ko'p tilli (i18n) va to'liq murakkab versiya: Flask + SQLite (bitta fayl).
"""
import array, ast, base64, email.utils, html, math, sys, hashlib, io, ipaddress, json, operator, os, re, sqlite3, threading, time
import urllib.request, urllib.error, wave, zipfile
from collections import Counter, defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.json.ensure_ascii = False
DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.db"))
MODEL = os.environ.get("PHISHGUARD_MODEL", "claude-sonnet-5-5")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
RETENTION_DAYS = int(os.environ.get("PHISHGUARD_RETENTION_DAYS", "90"))

# ------------------------------------------------------------------ DB
@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()

def init_db():
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                preview_hash TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        con.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))

def save_scan(kind, preview, score, level, reasons):
    digest = hashlib.sha256(str(preview or "").encode("utf-8", "ignore")).hexdigest()
    with db() as con:
        con.execute(
            "INSERT INTO scans(kind, preview_hash, score, level, reasons_json, created_at) VALUES (?,?,?,?,?,?)",
            (str(kind)[:40], digest, int(score), str(level),
             json.dumps(reasons, ensure_ascii=False), datetime.now(timezone.utc).isoformat()))

init_db()

# ------------------------------------------------------------------ Xavfsizlik va Rate Limit
@app.after_request
def add_security_headers(resp):
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    if request.path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(self), geolocation=()")
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                 "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    return resp

_hits, _lock = defaultdict(deque), threading.Lock()
LIMITS = {"/api/chat": 20, "/api/voice": 6}
DEFAULT_LIMIT = 40

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return (xff.split(",")[-1].strip() if xff else request.remote_addr) or "?"

def allowed(bucket, limit, window=60):
    now, key = time.time(), (bucket, client_ip())
    with _lock:
        dq = _hits[key]
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

@app.before_request
def throttle():
    if request.method == "POST" and request.path.startswith("/api/"):
        if not allowed(request.path, LIMITS.get(request.path, DEFAULT_LIMIT)):
            return jsonify(error="Too many requests"), 429

# ------------------------------------------------------------------ Tarjimalar va Tahlil
TEXTS = {
    "uz": {
        "low": "Past xavf", "mid": "O'rta xavf", "high": "Yuqori xavf",
        "adv_low": "Aniq xavf belgisi topilmadi, lekin har doim hushyor bo'ling.",
        "adv_mid": "Shubhali belgilar aniqlandi. Shaxsiy ma'lumot kiritmang va havolani ochmang.",
        "adv_high": "DIQQAT! Bu xavfli fishing yoki kiberhujum vositasi. Darhol tark eting!",
        "invalid_url": "URL manzil xato", "invalid_url_desc": "Kiritilgan manzil formati noto'g'ri tuzilgan.",
        "no_https": "Shifrlanmagan ulanish (HTTP)", "no_https_desc": "Ma'lumotlar ochiq holda uzatiladi, bu trafikni tutib qolish xavfini tug'diradi.",
        "imitation": "'{}' brendiga taqlid", "imitation_desc": "Rasmiy domen: {}. Bu soxta sahifa bo'lishi mumkin.",
        "ip_host": "IP manzil aniqlandi", "ip_host_desc": "Havola to'g'ridan-to'g'ri IP manzilga yo'naltirilgan, bu fishing saytlarga xos.",
        "punycode": "Punycode (xn--) alomati", "punycode_desc": "Domen nomi xalqaro harflarga o'xshatib soxtalashtirilgan bo'lishi mumkin.",
        "at_sign": "Yashirin '@' belgisi", "at_sign_desc": "Havoladagi '@' belgisi brauzerni chalg'itib, boshqa manzilga olib borishi mumkin.",
        "many_sub": "Haddan tashqari ko'p subdomen", "sub_desc": "Ko'p qavatli subdomenlar soxta saytlarni niqoblash uchun ishlatiladi.",
        "bad_tld": "Shubhali domen zonasi", "bad_tld_desc": "Bu TLD (zona) arzon yoki bepul bo'lgani uchun firibgarlar tomonidan ko'p suiiste'mol qilinadi.",
        "shortener": "Qisqartirilgan havola", "shortener_desc": "Asl manzil yashiringan. Uni ochishdan oldin kengaytirib tekshiring.",
        "safe": "Xavfsiz ko'rinadi", "safe_desc": "Tahlil qilingan URL manzilida aniq tahdidlar topilmadi.",
        "urgency": "Shoshiltirish va bosim o'tkazish", "urgency_desc": "Firibgarlar jabrlanuvchini o'ylashga vaqt bermasdan harakat qilishga majburlaydi.",
        "secret_req": "Maxfiy ma'lumot (OTP/Parol) so'rovi", "secret_req_desc": "Banklar va rasmiy xizmatlar hech qachon SMS kod, PIN yoki parolni so'ramaydi.",
        "prize": "Soxta yutuq va sovg'a va'dasi", "prize_desc": "Tez boyib ketish yoki yutuqni olish bahona shaxsiy ma'lumot yig'iladi.",
        "acc_threat": "Hisobni bloklash bilan qo'rqitish", "acc_threat_desc": "Hisobingiz o'chirilishi yoki bloklanishi haqidagi xabarlar soxta vahima uyg'otishga qaratilgan.",
        "no_msg_threat": "Matnda tahdid topilmadi", "no_msg_threat_desc": "Xabarda shubhali iboralar aniqlanmadi.",
        "card_len": "Karta raqami noto'g'ri", "card_len_desc": "13 dan 19 gacha bo'lgan to'g'ri raqam kiriting.",
        "card_note": "Xavfsizlik eslatmasi", "card_note_desc": "Karta raqami maxfiylikni saqlash maqsadida aslo saqlanmaydi.",
        "bad_ext": "Zararli yoki bajariladigan kengaytma: .{}", "bad_ext_desc": "Bu turdagi fayllar tizimga zarar yetkazishi mumkin.",
        "file_clean": "Fayl toza ko'rinadi", "file_clean_desc": "Ma'lum zararli imzolar aniqlanmadi.",
        "voice_clean": "Ovoz tahlili: Toza", "voice_clean_desc": "Ovozli muloqotda vishing yoki sintetik soxtalashtirish alomatlari yo'q.",
        "voice_deepfake": "Sintetik ovoz (Deepfake) xavfi", "voice_deepfake_desc": "Ovoz chastotalari va naqshlarida sun'iy generatsiya izlari topildi.",
        "vishing_warn": "Vishing (Ovozli fishing) xavfi", "vishing_warn_desc": "Muloqot paytida bank yoki davlat idorasi xodimi sifatida aldab ma'lumot olishga urinish.",
        "total": "Jami tekshiruvlar", "last7": "Oxirgi 7 kundagi dinamika", "copy": "Nusxalash", "copied": "Nusxalandi!", "demo_label": "Ekspertiza Natijasi"
    },
    "ru": {
        "low": "Низкий риск", "mid": "Средний риск", "high": "Высокий риск",
        "adv_low": "Явных угроз не обнаружено, но сохраняйте бдительность.",
        "adv_mid": "Обнаружены подозрительные признаки. Не вводите личные данные.",
        "adv_high": "ВНИМАНИЕ! Это фишинг или вредоносная угроза. Немедленно закройте страницу!",
        "invalid_url": "Неверный URL", "invalid_url_desc": "Структура ссылки указана некорректно.",
        "no_https": "Незащищенное соединение (HTTP)", "no_https_desc": "Данные передаются открытым текстом, возможен перехват трафика.",
        "imitation": "Имитация бренда '{}'", "imitation_desc": "Официальный домен: {}. Похоже на подделку.",
        "ip_host": "Прямой IP-адрес в ссылке", "ip_host_desc": "Ссылки на IP вместо домена часто используются фишерами.",
        "punycode": "Признак Punycode (xn--)", "punycode_desc": "Домен замаскирован под легитимный с помощью символов похожих алфавитов.",
        "at_sign": "Символ '@' в адресе", "at_sign_desc": "Символ '@' может скрывать реальный адрес назначения.",
        "many_sub": "Множество поддоменов", "sub_desc": "Длинные цепочки поддоменов маскируют мошеннический ресурс.",
        "bad_tld": "Подозрительная доменная зона", "bad_tld_desc": "Зона часто используется злоумышленниками из-за дешевизны.",
        "shortener": "Сокращенная ссылка", "shortener_desc": "Реальный адрес скрыт сервисом сокращения.",
        "safe": "Выглядит безопасно", "safe_desc": "Явных признаков фишинга не обнаружено.",
        "urgency": "Психологическое давление и срочность", "urgency_desc": "Мошенники требуют немедленных действий без раздумий.",
        "secret_req": "Запрос конфиденциальных данных", "secret_req_desc": "Банки и сервисы никогда не запрашивают пароли и OTP коды.",
        "prize": "Обещание крупного выигрыша", "prize_desc": "Фальшивые призы используются для сбора персональных данных.",
        "acc_threat": "Угроза блокировки счета", "acc_threat_desc": "Запугивание блокировкой аккаунта — частый инструмент манипуляции.",
        "no_msg_threat": "Угроз в тексте не найдено", "no_msg_threat_desc": "Подозрительных конструкций не обнаружено.",
        "card_len": "Неверный номер карты", "card_len_desc": "Введите корректный 13-19 значный номер.",
        "card_note": "Примечание безопасности", "card_note_desc": "Номер карты конфиденциален и никогда не сохраняется.",
        "bad_ext": "Опасное расширение файла: .{}", "bad_ext_desc": "Файл может содержать вредоносный исполняемый код.",
        "file_clean": "Файл выглядит чистым", "file_clean_desc": "Сигнатуры угроз не обнаружены.",
        "voice_clean": "Анализ голоса: Чисто", "voice_clean_desc": "Признаков вишинга или дипфейков не выявлено.",
        "voice_deepfake": "Риск синтетического голоса (Deepfake)", "voice_deepfake_desc": "Обнаружены цифровые артефакты генерации речи.",
        "vishing_warn": "Риск голосового фишинга (Вишинг)", "vishing_warn_desc": "Имитация звонка от сотрудников безопасности или банка с целью кражи данных.",
        "total": "Всего проверок", "last7": "Динамика за 7 дней", "copy": "Копировать", "copied": "Скопировано!", "demo_label": "Результат экспертизы"
    },
    "en": {
        "low": "Low Risk", "mid": "Medium Risk", "high": "High Risk",
        "adv_low": "No clear threats detected, but always stay vigilant.",
        "adv_mid": "Suspicious indicators found. Do not enter sensitive info.",
        "adv_high": "WARNING! This is a severe phishing or malware threat. Leave immediately!",
        "invalid_url": "Invalid URL", "invalid_url_desc": "The URL structure is malformed.",
        "no_https": "Unencrypted connection (HTTP)", "no_https_desc": "Data is transmitted in cleartext, vulnerable to interception.",
        "imitation": "Imitating brand '{}'", "imitation_desc": "Official domain is {}. Likely a spoofed page.",
        "ip_host": "Direct IP Address Host", "ip_host_desc": "Links pointing directly to IP addresses are typical of phishing.",
        "punycode": "Punycode (xn--) detected", "punycode_desc": "Domain uses look-alike characters to spoof legitimate sites.",
        "at_sign": "'@' sign in URL", "at_sign_desc": "The '@' symbol can trick browsers into masking the real destination.",
        "many_sub": "Excessive subdomains", "sub_desc": "Deep subdomain chains are often used in scam architectures.",
        "bad_tld": "Suspicious TLD", "bad_tld_desc": "Frequently abused top-level domains associated with malicious campaigns.",
        "shortener": "URL Shortener detected", "shortener_desc": "Real destination is obscured behind a redirection service.",
        "safe": "Appears Safe", "safe_desc": "No definitive threat indicators detected.",
        "urgency": "Urgency and Psychological Pressure", "urgency_desc": "Scammers force victims to act hastily without thinking.",
        "secret_req": "Confidential Data Request", "secret_req_desc": "Legitimate entities never ask for OTPs, PINs, or passwords.",
        "prize": "Fake Prize Promise", "prize_desc": "Promising unrealistic winnings to harvest credentials.",
        "acc_threat": "Account Lock Threat", "acc_threat_desc": "Intimidation tactics using fabricated account suspension.",
        "no_msg_threat": "No text threats found", "no_msg_threat_desc": "No suspicious patterns detected in text.",
        "card_len": "Invalid card number", "card_len_desc": "Enter a valid 13-19 digit card identifier.",
        "card_note": "Security Notice", "card_note_desc": "Card numbers are strictly private and never stored.",
        "bad_ext": "Dangerous file extension: .{}", "bad_ext_desc": "File type is executable or associated with malware payloads.",
        "file_clean": "File appears clean", "file_clean_desc": "No known threat signatures matched.",
        "voice_clean": "Voice Analysis: Clean", "voice_clean_desc": "No vishing or synthetic voice generation artifacts found.",
        "voice_deepfake": "Synthetic Voice (Deepfake) Risk", "voice_deepfake_desc": "Spectral analysis revealed artificial speech generation patterns.",
        "vishing_warn": "Vishing (Voice Phishing) Alert", "vishing_warn_desc": "Audio attempts impersonation of trusted authorities to extract data.",
        "total": "Total scans", "last7": "Last 7 days activity", "copy": "Copy", "copied": "Copied!", "demo_label": "Expertise Result"
    }
}
TEXTS["kr"] = TEXTS["uz"]

def tr(lang):
    return {**TEXTS["en"], **TEXTS.get(lang, {})}

def get_lang():
    j = request.get_json(silent=True)
    if isinstance(j, dict):
        l = j.get("lang")
    else:
        l = request.form.get("lang") or request.args.get("lang")
    return l if l in TEXTS else "uz"

def out(kind, preview, score, reasons, lang="uz", extra=None):
    score = max(0, min(100, int(score)))
    lv = "low" if score < 30 else "mid" if score < 60 else "high"
    t = tr(lang)
    safe_reasons = []
    for rr in reasons:
        pts = int(rr[2]) if len(rr) > 2 else 0
        safe_reasons.append({"t": str(rr[0])[:160], "why": str(rr[1])[:500], "pts": pts})
    safe_reasons.sort(key=lambda x: -x["pts"])
    try:
        save_scan(kind, preview, score, lv, safe_reasons)
    except Exception:
        pass
    return jsonify(score=score, level=lv, label=t.get(lv, lv), advice=t.get(f"adv_{lv}", ""),
                   reasons=safe_reasons, **(extra or {}))

def txt(n):
    j = request.get_json(silent=True)
    v = j.get("text", "") if isinstance(j, dict) else ""
    return v[:n] if isinstance(v, str) else str(v or "")[:n]

def luhn(n):
    total = 0
    for i, ch in enumerate(reversed(n)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0

# ------------------------------------------------------------------ Qo'shimcha tarjimalar
TEXTS_EXTRA = {
    "uz": {
        "official": "Rasmiy domen", "official_desc": "{} ma'lum rasmiy domenlar ro'yxatida bor.",
        "typosquat": "'{}' ga o'xshatilgan domen", "typosquat_desc": "Rasmiy domen: {}. Harflari almashtirilgan yoki raqamga o'zgartirilgan (masalan o→0).",
        "bad_scheme": "Xavfli havola turi", "bad_scheme_desc": "javascript:, data: kabi havolalar brauzerda kod ishga tushirishi mumkin.",
        "kw_path": "Havolada shubhali so'zlar", "kw_path_desc": "Havola ichida fishingda ko'p uchraydigan so'zlar bor: {}.",
        "odd_port": "Odatiy bo'lmagan port", "odd_port_desc": "Havola {} portidan foydalanadi, oddiy saytlar 80/443 portda ishlaydi.",
        "long_url": "Juda uzun havola", "long_url_desc": "Uzun havolalar haqiqiy manzilni yashirish uchun ishlatilishi mumkin.",
        "hyphens": "Domenda ko'p defis", "hyphens_desc": "Ko'p defisli domenlar ('secure-bank-login-...') ko'pincha soxta saytlarga xos.",
        "link_in_msg": "Xabardagi havola xavfli", "link_in_msg_desc": "{} — {} ({}/100).",
        "impersonation": "Rasmiy tashkilot nomidan yozish", "impersonation_desc": "Bank, davlat yoki texnik yordam xodimi sifatida tanishtirish firibgarlarning keng tarqalgan usuli.",
        "money_req": "Pul o'tkazish yoki to'lov talabi", "money_req_desc": "Oldindan to'lov, komissiya yoki kripto so'rash aldov belgisi.",
        "install_app": "Ilova (APK) o'rnatish talabi", "install_app_desc": "Rasmiy do'kondan tashqari ilova telefoningizni nazorat qilishi va SMS kodlarni o'qishi mumkin.",
        "off_platform": "Boshqa messenjerga o'tishga undash", "off_platform_desc": "Suhbatni Telegram/WhatsApp ga ko'chirish nazoratdan chiqish usulidir.",
        "job_scam": "Tez daromad yoki ish taklifi", "job_scam_desc": "'Uydan turib kuniga $100' kabi va'dalar odatda firibgarlik.",
        "card_req": "Karta ma'lumotlari so'rovi", "card_req_desc": "Karta raqami, amal qilish muddati yoki CVV ni hech kim so'ramasligi kerak.",
        "combo": "Xavfli kombinatsiya", "combo_desc": "Maxfiy ma'lumot so'rovi shoshiltirish yoki qo'rqitish bilan birga kelgan: klassik fishing.",
        "legit_otp": "Odatiy tasdiqlash xabariga o'xshaydi", "legit_otp_desc": "Xabarda kodni hech kimga bermaslik haqida ogohlantirish bor. Lekin kodni o'zingiz so'ramagan bo'lsangiz, ehtiyot bo'ling.",
        "luhn_fail": "Luhn tekshiruvi xatosi", "luhn_fail_desc": "Karta raqami matematik jihatdan noto'g'ri yoki soxtalashtirilgan.",
        "card_len_mismatch": "{} uchun raqam uzunligi mos emas", "card_len_mismatch_desc": "Bunday karta odatda {} raqamdan iborat, siz {} ta kiritdingiz.",
        "test_card": "Test karta raqami", "test_card_desc": "Bu to'lov tizimlarining ochiq test raqami, haqiqiy karta emas.",
        "repeat_digits": "Shubhali raqam naqshi", "repeat_digits_desc": "Raqamlar takrorlanadi yoki ketma-ket kelgan, haqiqiy karta uchun odatiy emas.",
        "card_ok": "Raqam formati to'g'ri", "card_ok_desc": "Luhn tekshiruvidan o'tdi. Bu kartaning faolligini yoki egasini tasdiqlamaydi.",
        "magic_mismatch": "Fayl turi kengaytmaga mos emas", "magic_mismatch_desc": "Nomi '.{}' ko'rinadi, lekin aslida {} fayli.",
        "double_ext": "Ikki kengaytma niqobi", "double_ext_desc": "Fayl nomi hujjat ko'rinishida, aslida bajariladigan fayl.",
        "rtlo": "Yashirin yo'nalish belgisi (RTLO)", "rtlo_desc": "Fayl nomidagi maxsus belgi kengaytmani teskari ko'rsatib aldaydi.",
        "apk_base": "Android ilova (APK)", "apk_base_desc": "Rasmiy do'kondan tashqari APK o'rnatish xavfli. Telegram orqali kelgan APK larga ayniqsa ishonmang.",
        "apk_perms": "APK xavfli ruxsatlar so'rayapti", "apk_perms_desc": "Topildi: {}.",
        "apk_banker": "Bank troyani naqshi", "apk_banker_desc": "SMS o'qish ruxsati bilan birga maxsus imkoniyatlar yoki ekran ustida chizish ruxatsi SMS kodlarni o'g'irlovchi zararli dasturlarda uchraydi.",
        "apk_dropper": "Ichida yashirin ilova yoki kod", "apk_dropper_desc": "Ilova ichida qo'shimcha APK/DEX fayl bor: {}.",
        "archive_exec": "Arxiv ichida bajariladigan fayl", "archive_exec_desc": "Topildi: {}.",
        "zip_slip": "Arxiv yo'llari shubhali", "zip_slip_desc": "Arxiv ichida '..' yoki mutlaq yo'l bor, fayllarni boshqa joyga yozishga urinish bo'lishi mumkin.",
        "archive_enc": "Parol bilan himoyalangan arxiv", "archive_enc_desc": "Shifrlangan arxivlar antivirus tekshiruvidan o'tish uchun ishlatiladi.",
        "macro": "Hujjatda makro (VBA) bor", "macro_desc": "Makroslar zararli kodni ishga tushirishi mumkin. Kutilmagan hujjatda makroni yoqmang.",
        "pdf_active": "PDF ichida faol elementlar", "pdf_active_desc": "Topildi: {}.",
        "script_susp": "Shubhali skript naqshlari", "script_susp_desc": "Topildi: {}.",
        "html_phish": "HTML ichida parol shakli", "html_phish_desc": "Biriktirilgan HTML sahifa login ma'lumotlarini yig'ishi mumkin.",
        "packed": "Yuqori entropiya (siqilgan/shifrlangan)", "packed_desc": "Dastur tarkibi siqilgan yoki shifrlangan, zararli dasturlar buni yashirish uchun ishlatadi.",
        "exec_type": "Bajariladigan fayl", "exec_type_desc": "Fayl tarkibi {} formatida.",
        "voice_noai": "Transkripsiya mavjud emas", "voice_noai_desc": "Nutqni matnga o'tkazish uchun serverda GEMINI_API_KEY kerak yoki so'rov muvaffaqiyatsiz bo'ldi. To'liq xulosa chiqarib bo'lmadi.",
        "voice_format": "Audio formati qo'llab-quvvatlanmaydi", "voice_format_desc": "WAV, MP3, OGG yoki FLAC yuklang.",
        "voice_big": "Audio juda katta", "voice_big_desc": "14 MB gacha va 2 daqiqadan qisqa audio yuklang.",
        "voice_empty": "Nutq topilmadi", "voice_empty_desc": "Audioda tushunarli nutq aniqlanmadi.",
        "voice_synth": "Sintetik ovoz belgilari (taxminiy)", "voice_synth_desc": "AI tahlili sun'iy nutq belgilarini sezdi. Bu ishonchli aniqlash emas, faqat ehtiyot bo'lish uchun signal.",
        "voice_ok": "Nutqda firibgarlik belgilari topilmadi", "voice_ok_desc": "Transkripsiyada shubhali iboralar aniqlanmadi.",
        "voice_info": "Audio ma'lumotlari", "voice_info_desc": "Davomiyligi {} s.",
    },
    "ru": {
        "official": "Официальный домен", "official_desc": "{} есть в списке известных официальных доменов.",
        "typosquat": "Домен, похожий на '{}'", "typosquat_desc": "Официальный домен: {}. Буквы заменены или подменены цифрами (например, o→0).",
        "bad_scheme": "Опасный тип ссылки", "bad_scheme_desc": "Ссылки javascript:, data: могут выполнить код в браузере.",
        "kw_path": "Подозрительные слова в ссылке", "kw_path_desc": "В ссылке есть слова, типичные для фишинга: {}.",
        "odd_port": "Нестандартный порт", "odd_port_desc": "Ссылка использует порт {}, обычные сайты работают на 80/443.",
        "long_url": "Слишком длинная ссылка", "long_url_desc": "Длинные ссылки могут скрывать настоящий адрес.",
        "hyphens": "Много дефисов в домене", "hyphens_desc": "Домены с множеством дефисов ('secure-bank-login-...') часто фальшивые.",
        "link_in_msg": "Опасная ссылка в сообщении", "link_in_msg_desc": "{} — {} ({}/100).",
        "impersonation": "Выдача себя за организацию", "impersonation_desc": "Представляться сотрудником банка, госоргана или поддержки — частый приём мошенников.",
        "money_req": "Требование перевода или оплаты", "money_req_desc": "Предоплата, комиссия или криптовалюта — признак обмана.",
        "install_app": "Требование установить приложение (APK)", "install_app_desc": "Приложение вне официального магазина может управлять телефоном и читать SMS-коды.",
        "off_platform": "Призыв перейти в другой мессенджер", "off_platform_desc": "Перевод общения в Telegram/WhatsApp — способ уйти от контроля.",
        "job_scam": "Быстрый заработок или предложение работы", "job_scam_desc": "Обещания вроде '$100 в день из дома' обычно мошенничество.",
        "card_req": "Запрос данных карты", "card_req_desc": "Номер карты, срок действия или CVV никто не должен спрашивать.",
        "combo": "Опасное сочетание", "combo_desc": "Запрос секретных данных вместе со срочностью или угрозой — классический фишинг.",
        "legit_otp": "Похоже на обычное сообщение с кодом", "legit_otp_desc": "В сообщении есть предупреждение никому не сообщать код. Но если вы не запрашивали код, будьте осторожны.",
        "luhn_fail": "Ошибка проверки Луна", "luhn_fail_desc": "Номер карты математически неверен или подделан.",
        "card_len_mismatch": "Длина номера не подходит для {}", "card_len_mismatch_desc": "Такая карта обычно содержит {} цифр, вы ввели {}.",
        "test_card": "Тестовый номер карты", "test_card_desc": "Это открытый тестовый номер платёжных систем, а не настоящая карта.",
        "repeat_digits": "Подозрительный узор цифр", "repeat_digits_desc": "Цифры повторяются или идут подряд, для настоящей карты это нетипично.",
        "card_ok": "Формат номера корректен", "card_ok_desc": "Проверка Луна пройдена. Это не подтверждает, что карта активна или чья она.",
        "magic_mismatch": "Тип файла не совпадает с расширением", "magic_mismatch_desc": "Имя выглядит как '.{}', но на самом деле это файл {}.",
        "double_ext": "Маскировка двойным расширением", "double_ext_desc": "Имя похоже на документ, а файл исполняемый.",
        "rtlo": "Скрытый символ направления (RTLO)", "rtlo_desc": "Спецсимвол в имени файла переворачивает расширение и вводит в заблуждение.",
        "apk_base": "Приложение Android (APK)", "apk_base_desc": "Установка APK вне официального магазина опасна. Особенно не доверяйте APK из Telegram.",
        "apk_perms": "APK запрашивает опасные разрешения", "apk_perms_desc": "Найдено: {}.",
        "apk_banker": "Признаки банковского трояна", "apk_banker_desc": "Чтение SMS вместе со спецвозможностями или наложением поверх экрана встречается в вредоносах, крадущих SMS-коды.",
        "apk_dropper": "Внутри скрытое приложение или код", "apk_dropper_desc": "Внутри приложения есть дополнительные APK/DEX: {}.",
        "archive_exec": "Исполняемый файл внутри архива", "archive_exec_desc": "Найдено: {}.",
        "zip_slip": "Подозрительные пути в архиве", "zip_slip_desc": "В архиве есть '..' или абсолютный путь, возможна попытка записи файлов в другое место.",
        "archive_enc": "Архив защищён паролем", "archive_enc_desc": "Зашифрованные архивы используют, чтобы обойти проверку антивирусом.",
        "macro": "В документе есть макрос (VBA)", "macro_desc": "Макросы могут запустить вредоносный код. Не включайте макросы в неожиданных документах.",
        "pdf_active": "Активные элементы внутри PDF", "pdf_active_desc": "Найдено: {}.",
        "script_susp": "Подозрительные шаблоны скрипта", "script_susp_desc": "Найдено: {}.",
        "html_phish": "Форма пароля внутри HTML", "html_phish_desc": "Вложенная HTML-страница может собирать данные для входа.",
        "packed": "Высокая энтропия (упаковано/зашифровано)", "packed_desc": "Содержимое сжато или зашифровано, так вредоносы скрывают код.",
        "exec_type": "Исполняемый файл", "exec_type_desc": "Содержимое файла в формате {}.",
        "voice_noai": "Расшифровка недоступна", "voice_noai_desc": "Для преобразования речи в текст на сервере нужен GEMINI_API_KEY, либо запрос не удался. Полный вывод сделать нельзя.",
        "voice_format": "Формат аудио не поддерживается", "voice_format_desc": "Загрузите WAV, MP3, OGG или FLAC.",
        "voice_big": "Аудио слишком большое", "voice_big_desc": "Загрузите аудио до 14 МБ и короче 2 минут.",
        "voice_empty": "Речь не найдена", "voice_empty_desc": "В аудио не обнаружена разборчивая речь.",
        "voice_synth": "Признаки синтетического голоса (предположительно)", "voice_synth_desc": "ИИ-анализ заметил признаки искусственной речи. Это ненадёжное определение, а лишь сигнал быть осторожнее.",
        "voice_ok": "Признаков мошенничества в речи не найдено", "voice_ok_desc": "В расшифровке подозрительных фраз не обнаружено.",
        "voice_info": "Данные аудио", "voice_info_desc": "Длительность {} с.",
    },
    "en": {
        "official": "Official domain", "official_desc": "{} is on the list of known official domains.",
        "typosquat": "Lookalike of '{}'", "typosquat_desc": "Official domain: {}. Letters swapped or replaced with digits (e.g. o→0).",
        "bad_scheme": "Dangerous link type", "bad_scheme_desc": "javascript: and data: links can run code in the browser.",
        "kw_path": "Suspicious words in the link", "kw_path_desc": "The link contains words common in phishing: {}.",
        "odd_port": "Unusual port", "odd_port_desc": "The link uses port {}; normal sites use 80/443.",
        "long_url": "Very long link", "long_url_desc": "Long links can hide the real destination.",
        "hyphens": "Many hyphens in domain", "hyphens_desc": "Domains with many hyphens ('secure-bank-login-...') are often fake.",
        "link_in_msg": "Dangerous link in message", "link_in_msg_desc": "{} — {} ({}/100).",
        "impersonation": "Posing as an organization", "impersonation_desc": "Introducing yourself as bank, government or support staff is a common scam tactic.",
        "money_req": "Payment or transfer demand", "money_req_desc": "Asking for advance payment, fees or crypto is a scam sign.",
        "install_app": "Demand to install an app (APK)", "install_app_desc": "An app from outside the official store can control your phone and read SMS codes.",
        "off_platform": "Push to another messenger", "off_platform_desc": "Moving the chat to Telegram/WhatsApp is a way to escape oversight.",
        "job_scam": "Quick money or job offer", "job_scam_desc": "Promises like '$100 a day from home' are usually scams.",
        "card_req": "Card details request", "card_req_desc": "Nobody should ask for your card number, expiry date or CVV.",
        "combo": "Dangerous combination", "combo_desc": "A request for secrets together with urgency or threats is classic phishing.",
        "legit_otp": "Looks like a normal verification message", "legit_otp_desc": "The message warns not to share the code. But if you did not request a code, be careful.",
        "luhn_fail": "Luhn check failed", "luhn_fail_desc": "The card number is mathematically invalid or forged.",
        "card_len_mismatch": "Length does not fit {}", "card_len_mismatch_desc": "Such a card normally has {} digits, you entered {}.",
        "test_card": "Test card number", "test_card_desc": "This is a public payment-system test number, not a real card.",
        "repeat_digits": "Suspicious digit pattern", "repeat_digits_desc": "Digits repeat or run in sequence, unusual for a real card.",
        "card_ok": "Number format is valid", "card_ok_desc": "Passed the Luhn check. This does not confirm the card is active or whose it is.",
        "magic_mismatch": "File type does not match extension", "magic_mismatch_desc": "The name looks like '.{}', but it is really a {} file.",
        "double_ext": "Double-extension disguise", "double_ext_desc": "The name looks like a document but the file is executable.",
        "rtlo": "Hidden direction character (RTLO)", "rtlo_desc": "A special character in the filename reverses the extension to deceive.",
        "apk_base": "Android app (APK)", "apk_base_desc": "Installing APKs from outside the official store is risky. Do not trust APKs sent over Telegram.",
        "apk_perms": "APK requests dangerous permissions", "apk_perms_desc": "Found: {}.",
        "apk_banker": "Banking-trojan pattern", "apk_banker_desc": "SMS access plus accessibility or screen-overlay powers appears in malware that steals SMS codes.",
        "apk_dropper": "Hidden app or code inside", "apk_dropper_desc": "The app contains extra APK/DEX files: {}.",
        "archive_exec": "Executable inside archive", "archive_exec_desc": "Found: {}.",
        "zip_slip": "Suspicious archive paths", "zip_slip_desc": "The archive has '..' or absolute paths, possibly trying to write files elsewhere.",
        "archive_enc": "Password-protected archive", "archive_enc_desc": "Encrypted archives are used to bypass antivirus scanning.",
        "macro": "Document contains a macro (VBA)", "macro_desc": "Macros can run malicious code. Do not enable macros in unexpected documents.",
        "pdf_active": "Active elements inside PDF", "pdf_active_desc": "Found: {}.",
        "script_susp": "Suspicious script patterns", "script_susp_desc": "Found: {}.",
        "html_phish": "Password form inside HTML", "html_phish_desc": "The attached HTML page may harvest login details.",
        "packed": "High entropy (packed/encrypted)", "packed_desc": "The content is compressed or encrypted, which malware uses to hide code.",
        "exec_type": "Executable file", "exec_type_desc": "File content is in {} format.",
        "voice_noai": "Transcription unavailable", "voice_noai_desc": "Speech-to-text needs GEMINI_API_KEY on the server, or the request failed. No full verdict possible.",
        "voice_format": "Audio format not supported", "voice_format_desc": "Upload WAV, MP3, OGG or FLAC.",
        "voice_big": "Audio too large", "voice_big_desc": "Upload audio under 14 MB and shorter than 2 minutes.",
        "voice_empty": "No speech found", "voice_empty_desc": "No intelligible speech was detected in the audio.",
        "voice_synth": "Possible synthetic-voice traits (tentative)", "voice_synth_desc": "AI analysis noticed traits of artificial speech. This is not reliable detection, only a signal to be careful.",
        "voice_ok": "No scam indicators in the speech", "voice_ok_desc": "No suspicious phrases were found in the transcript.",
        "voice_info": "Audio details", "voice_info_desc": "Duration {} s.",
    },
}
for _l, _d in TEXTS_EXTRA.items():
    TEXTS[_l].update(_d)

# ------------------------------------------------------------------ URL tahlili
BRANDS = {
    "payme": ("payme.uz",), "click": ("click.uz",), "uzcard": ("uzcard.uz",),
    "humo": ("humo.uz", "humocard.uz"), "paynet": ("paynet.uz",),
    "uzum": ("uzum.uz", "uzumbank.uz", "uzum.market"), "kapitalbank": ("kapitalbank.uz",),
    "telegram": ("telegram.org", "t.me", "telegram.me", "telegram.dog", "telegra.ph"),
    "google": ("google.com", "google.uz", "gmail.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
               "googlemail.com", "googlevideo.com", "googletagmanager.com", "google-analytics.com", "ggpht.com"),
    "youtube": ("youtube.com", "youtu.be"),
    "apple": ("apple.com", "icloud.com", "mzstatic.com"),
    "instagram": ("instagram.com", "cdninstagram.com", "instagr.am"),
    "facebook": ("facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com", "fbcdn.net", "facebook.net"),
    "whatsapp": ("whatsapp.com", "wa.me", "whatsapp.net"),
    "netflix": ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net"),
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "binance": ("binance.com",), "olx": ("olx.uz",),
    "tiktok": ("tiktok.com", "tiktokcdn.com", "tiktokv.com"),
}
ADDONS = {"uz", "secure", "login", "verify", "support", "bank", "pay", "online", "service", "official",
          "app", "web", "help", "id", "my", "wallet", "account", "update", "bonus", "card", "free", "gift"}
EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "ps1", "jar", "msi", "com",
           "pif", "hta", "lnk", "dll", "reg", "cpl", "chm"}
BAD_TLDS = {"xyz", "top", "gq", "ml", "cf", "tk", "pw", "cc", "su", "click", "loan", "zip", "mov", "work", "buzz"}
SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "buff.ly", "clck.ru", "cutt.ly", "rb.gy", "ow.ly"}
PATH_WORDS = ("login", "signin", "verify", "verification", "secure", "account", "update", "confirm",
              "banking", "wallet", "password", "otp", "bonus", "gift", "claim", "unblock", "recover", "suspend")
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})

def _norm(tok):
    return tok.translate(LEET).replace("rn", "m").replace("vv", "w")

def _lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def _dup_letter(tok, brand):
    """paymee -> payme (qo'shilgan takroriy harf)"""
    if len(tok) != len(brand) + 1:
        return False
    for i in range(len(tok)):
        if tok[:i] + tok[i + 1:] == brand and (i > 0 and tok[i] == tok[i - 1] or i + 1 < len(tok) and tok[i] == tok[i + 1]):
            return True
    return False

def _is_official(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)

def url_risk(raw, t):
    """URL xavfini hisoblaydi: (ball, [(sabab, tushuntirish, ball), ...])"""
    raw = (raw or "").strip()
    if re.match(r"^(?:javascript|vbscript|data|file):", raw, re.I):
        return 80, [(t["bad_scheme"], t["bad_scheme_desc"], 80)]
    try:
        u = urlparse(raw if "://" in raw else "https://" + raw)
        host = (u.hostname or "").lower().rstrip(".")
        port = u.port
    except ValueError:
        return 50, [(t["invalid_url"], t["invalid_url_desc"], 50)]
    if not host or ("." not in host and not host.isdigit()):
        return 50, [(t["invalid_url"], t["invalid_url_desc"], 50)]

    s, r = 0, []
    def add(key, pts, *fmt_title, desc_args=()):
        nonlocal s
        s += pts
        r.append((t[key].format(*fmt_title), t[key + "_desc"].format(*desc_args), pts))

    official = next((b for b, ds in BRANDS.items() if _is_official(host, ds)), None)
    if official:
        r.append((t["official"], t["official_desc"].format(host), 0))

    if u.scheme == "http":
        add("no_https", 15)
    try:
        ipaddress.ip_address(host); add("ip_host", 45)
    except ValueError:
        if host.isdigit() or re.fullmatch(r"0x[0-9a-f]+", host):
            add("ip_host", 45)
    if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
        add("punycode", 40)
    if "@" in u.netloc:
        add("at_sign", 35)
    if host.count(".") > 3:
        add("many_sub", 20)
    if port not in (None, 80, 443):
        add("odd_port", 15, desc_args=(port,))
    if any(host == sh or host.endswith("." + sh) for sh in SHORTENERS):
        add("shortener", 25)

    if not official:
        tld = host.rsplit(".", 1)[-1]
        if tld in BAD_TLDS:
            add("bad_tld", 30)
        if host.count("-") >= 3:
            add("hyphens", 15)
        if len(raw) > 120:
            add("long_url", 10)
        text = (u.path + " " + u.query).lower()
        words = [w for w in PATH_WORDS if w in text]
        if words:
            add("kw_path", min(25, 10 * len(words)), desc_args=(", ".join(words[:3]),))

        tokens = [x for x in re.split(r"[.\-_]", host.rsplit(".", 1)[0]) if x]
        flagged = set()
        for b, ds in BRANDS.items():
            for tok in tokens:
                if tok == b or any(tok == b + a or tok == a + b for a in ADDONS):
                    flagged.add(b)
                    add("imitation", 50, b, desc_args=(ds[0],))
                    break
        typos = 0
        for b, ds in BRANDS.items():
            if b in flagged or typos >= 2:
                continue
            for tok in tokens:
                nt = _norm(tok)
                if tok == b:
                    continue
                if (len(b) >= 4 and nt == b) or (len(tok) >= 5 and len(b) >= 6 and _lev(nt, b) <= 1) \
                        or (len(b) >= 5 and _dup_letter(tok, b)):
                    add("typosquat", 45, b, desc_args=(ds[0],))
                    typos += 1
                    break
    return s, r

@app.post("/api/url")
def api_url():
    lang = get_lang(); t = tr(lang)
    raw = txt(500).strip()
    s, r = url_risk(raw, t)
    return out("URL", raw, s, r or [(t["safe"], t["safe_desc"])], lang)

# ------------------------------------------------------------------ Xabar tahlili
def _rx(*alts):
    return re.compile(r"(?<!\w)(?:" + "|".join(alts) + r")(?!\w)", re.I)

RX_URGENT = _rx(r"hoziroq", r"hozirning\s+o'zida", r"zudlik\w*", r"tezda", r"darhol", r"shoshilinch\w*",
                r"oxirgi\s+(?:ogohlantirish|imkoniyat)", r"\d+\s*(?:daqiqa|soat)\s+ichida",
                r"срочно", r"немедленно", r"в\s+течение\s+\d+\s*(?:минут|часов)", r"последн\w+\s+предупреждени\w*",
                r"urgent(?:ly)?", r"immediately", r"right\s+now", r"within\s+\d+\s*(?:minutes?|hours?)",
                r"final\s+notice", r"last\s+warning", r"act\s+now")
RX_SECRET = _rx(r"sms[\s-]?kod\w*", r"tasdiqlash\s+kod\w*", r"bir\s*martalik\s+(?:kod|parol)\w*",
                r"kod(?:ni|ingiz\w*)?", r"parol(?:ni|ingiz\w*)?", r"otp", r"pin[\s-]?kod\w*", r"pin(?:ni)?",
                r"смс[\s-]?код\w*", r"одноразов\w+\s+(?:код|пароль)", r"код(?:а|у|ом)?", r"парол\w+",
                r"пин[\s-]?код\w*", r"пин", r"password", r"passcode", r"verification\s+code",
                r"one[\s-]time\s+(?:code|password)", r"security\s+code")
RX_REQ = _rx(r"ayt(?:ing|ib)", r"yubor(?:ing|ib)", r"kirit(?:ing|ib)", r"jo'?nat(?:ing|ib)", r"ber(?:ing|ib)",
             r"ko'rsat(?:ing|ib)", r"yoz(?:ing|ib)", r"tasdiqlang", r"send", r"share", r"provide", r"tell\s+us",
             r"enter", r"confirm", r"verify", r"reply\s+with", r"сообщите", r"назовите", r"отправьте", r"введите",
             r"пришлите", r"продиктуйте", r"подтвердите", r"передайте")
RX_SAFE = _rx(r"hech\s+kim\w*", r"bermang", r"aytmang", r"do\s+not\s+share", r"don'?t\s+share", r"never\s+share",
              r"никому\s+не", r"не\s+сообщайте", r"не\s+передавайте")
RX_CARD = _rx(r"karta\s+raqam\w*", r"karta\s+ma'?lumot\w*", r"amal\s+qilish\s+muddat\w*", r"cvv2?", r"cvc2?",
              r"номер\s+карты", r"данные\s+карты", r"срок\s+действия", r"card\s+(?:number|details|info)",
              r"expir\w+\s+date")
RX_PRIZE = _rx(r"yutuq\w*", r"yutib\s+ol\w+", r"yutdingiz", r"sovrin\w*", r"g'olib\w*", r"bonus\w*", r"aksiya\w*",
               r"sovg'a\w*", r"million\w*", r"выигр\w+", r"приз\w*", r"подар\w+", r"лотере\w+", r"бонус\w*",
               r"you\s+(?:have\s+)?won", r"winner", r"prize\w*", r"lottery", r"free\s+gift", r"congratulations")
RX_THREAT = _rx(r"blok\w*", r"o'chirilad\w+", r"o'chirib\s+tashlan\w+", r"to'xtatilad\w+", r"cheklan\w+",
                r"muzlat\w+", r"jarima\w*", r"jinoyat\s+ish\w+", r"заблокир\w+", r"блокиров\w+", r"будет\s+удал\w+",
                r"штраф\w*", r"уголовн\w+", r"suspen(?:d|sion)\w*", r"locked", r"blocked", r"deactivat\w+",
                r"will\s+be\s+(?:closed|terminated|deleted)", r"legal\s+action")
RX_IMPERS = _rx(r"bank\s+xodim\w*", r"bank\s+xavfsizlik\w*", r"xavfsizlik\s+xizmat\w*", r"texnik\s+yordam",
                r"call\s*center", r"kol\s*markaz", r"markaziy\s+bank", r"soliq\s+(?:xizmat\w*|qo'mita\w*)",
                r"davlat\s+xizmatlar\w*", r"сотрудник\s+банка", r"служб\w+\s+безопасности", r"центральн\w+\s+банк",
                r"налогов\w+", r"bank\s+(?:employee|representative)", r"security\s+team", r"customer\s+support",
                r"support\s+team")
RX_MONEY = _rx(r"pul\s+o'tkaz\w+", r"o'tkazib\s+ber\w+", r"to'lov\s+qiling", r"to'lab\s+qo'ying",
               r"oldindan\s+to'lov\w*", r"komissiya\s+to'la\w+", r"перевед\w+", r"предоплат\w+",
               r"transfer\s+(?:money|funds)", r"send\s+(?:money|payment)", r"pay\s+(?:a\s+)?fee",
               r"advance\s+payment", r"gift\s*cards?", r"bitcoin", r"usdt", r"crypto\w*")
RX_APK = _rx(r"\S+\.apk", r"apk\s+(?:fayl|ilova)\w*", r"ilovani\s+(?:yuklab|o'rnat)\w+", r"yuklab\s+oling",
             r"скачайте\s+(?:приложение|apk)", r"установите\s+приложени\w+", r"download\s+(?:the\s+)?app",
             r"install\s+(?:the\s+)?(?:app|apk)")
RX_OFFPLAT = _rx(r"(?:telegram|whatsapp|vatsap|watsap|viber)\w*\s*(?:ga|da|orqali)?\s*(?:yozing|o'ting|murojaat|bog'lan)\w*",
                 r"@\w{4,}", r"напишите\s+в\s+(?:telegram|whatsapp|телеграм)",
                 r"write\s+(?:me\s+)?(?:on|to)\s+(?:telegram|whatsapp)",
                 r"contact\s+(?:us\s+)?on\s+(?:telegram|whatsapp)")
RX_JOB = _rx(r"kuniga\s*\d+\w*", r"oyiga\s*\d+\w*", r"ish\s+taklifi", r"uydan\s+turib\s+ishla\w*",
             r"tez\s+daromad\w*", r"passiv\s+daromad\w*", r"investitsiya\s+qiling", r"удаленн\w+\s+работ\w+",
             r"быстрый\s+заработок", r"пассивный\s+доход", r"earn\s+\$?\d+", r"work\s+from\s+home",
             r"passive\s+income", r"guaranteed\s+(?:profit|returns?)")

def _find_hits(rx, text, n=3):
    seen = []
    for m in rx.finditer(text):
        w = m.group(0).strip()[:40]
        if w.lower() not in [x.lower() for x in seen]:
            seen.append(w)
        if len(seen) >= n:
            break
    return seen

def message_risk(raw, t):
    """Matn xavfini hisoblaydi: (ball, [(sabab, tushuntirish, ball), ...])"""
    raw = raw.replace("ʻ", "'").replace("’", "'").replace("ʼ", "'").replace("`", "'")
    s, r = 0, []
    def add(key, pts, hits=None):
        nonlocal s
        s += pts
        desc = t[key + "_desc"] + (" [" + ", ".join(hits) + "]" if hits else "")
        r.append((t[key], desc, pts))

    hu, hs, hth = _find_hits(RX_URGENT, raw), _find_hits(RX_SECRET, raw), _find_hits(RX_THREAT, raw)
    has_req, safe_note = bool(RX_REQ.search(raw)), bool(RX_SAFE.search(raw))
    secret_added = False
    if hu:
        add("urgency", 20, hu)
    if hs:
        if safe_note and not has_req:
            r.append((t["legit_otp"], t["legit_otp_desc"], 0))
        elif has_req:
            add("secret_req", 45, hs); secret_added = True
        else:
            add("secret_req", 20, hs)
    hc = _find_hits(RX_CARD, raw)
    if hc and has_req:
        add("card_req", 40, hc); secret_added = True
    if hth:
        add("acc_threat", 35, hth)
    if secret_added and (hu or hth):
        add("combo", 15)
    for key, rx, pts in (("prize", RX_PRIZE, 25), ("impersonation", RX_IMPERS, 25), ("money_req", RX_MONEY, 30),
                         ("install_app", RX_APK, 35), ("off_platform", RX_OFFPLAT, 20), ("job_scam", RX_JOB, 25)):
        h = _find_hits(rx, raw)
        if h:
            add(key, pts, h)
    for u in URL_RE.findall(raw)[:3]:
        u = u.rstrip(".,;:!?)]}")
        su, _ = url_risk(u, t)
        if su >= 30:
            pts = min(55, 15 + su // 2)
            s += pts
            r.append((t["link_in_msg"], t["link_in_msg_desc"].format(u[:60], t["high" if su >= 60 else "mid"], min(su, 100)), pts))
    return s, r

@app.post("/api/message")
def api_msg():
    lang = get_lang(); t = tr(lang)
    raw = txt(3000)
    s, r = message_risk(raw, t)
    return out("Xabar", raw, s, r or [(t["no_msg_threat"], t["no_msg_threat_desc"], 0)], lang)

# ------------------------------------------------------------------ Karta tahlili
TEST_CARDS = {"4111111111111111", "4242424242424242", "5555555555554444", "5105105105105100",
              "378282246310005", "4000056655665556", "6011111111111117", "4012888888881881", "4222222222222"}

def card_brand(n):
    p4 = int(n[:4])
    if n.startswith("8600"): return "Uzcard", {16}
    if n.startswith("9860"): return "Humo", {16}
    if n[0] == "4": return "Visa", {13, 16, 19}
    if n[:2] in {"51", "52", "53", "54", "55"} or 2221 <= p4 <= 2720: return "Mastercard", {16}
    if n[:2] in {"34", "37"}: return "American Express", {15}
    if n[:2] == "62": return "UnionPay", {16, 17, 18, 19}
    if 2200 <= p4 <= 2204: return "Mir", {16, 17, 18, 19}
    return "Unknown", None

@app.post("/api/card")
def api_card():
    lang = get_lang(); t = tr(lang)
    n = re.sub(r"\D", "", txt(200))[:19]
    if len(n) < 13:
        return jsonify(error=t["card_len"] + ": " + t["card_len_desc"]), 400
    s, r = 0, []
    brand, lens = card_brand(n)
    if lens and len(n) not in lens:
        s += 25
        r.append((t["card_len_mismatch"].format(brand),
                  t["card_len_mismatch_desc"].format("/".join(map(str, sorted(lens))), len(n)), 25))
    if not luhn(n):
        s += 40; r.append((t["luhn_fail"], t["luhn_fail_desc"], 40))
    if n in TEST_CARDS:
        s += 20; r.append((t["test_card"], t["test_card_desc"], 20))
    seq = "01234567890123456789"
    if len(set(n)) <= 3 or n in seq or n[::-1] in seq:
        s += 30; r.append((t["repeat_digits"], t["repeat_digits_desc"], 30))
    if not r:
        r.append((t["card_ok"], t["card_ok_desc"], 0))
    r.append((t["card_note"], t["card_note_desc"], 0))
    return out("Karta", None, s, r, lang, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

# ------------------------------------------------------------------ Fayl tahlili
EXEC_TYPES = {"exe", "elf", "macho", "java", "dex", "apk", "jar"}
EXEC_EXT = {"exe": {"exe", "dll", "scr", "sys", "ocx", "com", "cpl"}, "elf": {"elf", "so", "bin", "out", ""},
            "macho": {"dylib", "macho", "bin", ""}, "java": {"class", "jar", ""}, "dex": {"dex"},
            "apk": {"apk"}, "jar": {"jar"}}
EXPECT = {"jpg": {"jpg"}, "jpeg": {"jpg"}, "png": {"png"}, "gif": {"gif"}, "pdf": {"pdf"},
          "docx": {"docx"}, "docm": {"docx"}, "xlsx": {"xlsx"}, "xlsm": {"xlsx"}, "pptx": {"pptx"},
          "zip": {"zip", "apk", "jar", "docx", "xlsx", "pptx"}, "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"},
          "rar": {"rar"}, "7z": {"7z"}}
TYPE_LABEL = {"exe": "Windows (PE/EXE)", "elf": "Linux (ELF)", "macho": "macOS (Mach-O)", "java": "Java class / Mach-O",
              "dex": "Android DEX", "apk": "Android APK", "jar": "Java JAR", "pdf": "PDF", "ole": "Office (OLE)",
              "docx": "Word (OOXML)", "xlsx": "Excel (OOXML)", "pptx": "PowerPoint (OOXML)", "zip": "ZIP",
              "rar": "RAR", "7z": "7-Zip", "png": "PNG", "jpg": "JPEG", "gif": "GIF", "script": "Script",
              "text": "Text", "unknown": "Unknown"}
SCRIPT_EXT = {"js", "jse", "vbs", "vbe", "ps1", "bat", "cmd", "hta", "wsf", "sh", "py"}
APK_PERMS = {"READ_SMS": 12, "RECEIVE_SMS": 12, "SEND_SMS": 12, "READ_CALL_LOG": 8, "BIND_ACCESSIBILITY_SERVICE": 15,
             "SYSTEM_ALERT_WINDOW": 10, "REQUEST_INSTALL_PACKAGES": 10, "BIND_DEVICE_ADMIN": 15,
             "READ_CONTACTS": 6, "RECORD_AUDIO": 6, "QUERY_ALL_PACKAGES": 5}
SCRIPT_PATTERNS = {
    "PowerShell -enc / FromBase64": r"(?i)powershell[^\n]{0,80}-(?:enc|encodedcommand)|frombase64string",
    "eval / atob / unescape": r"(?i)\beval\s*\(|\batob\s*\(|unescape\s*\(",
    "WScript / CreateObject": r"(?i)wscript\.shell|shell\.application|createobject\s*\(",
    "Invoke-Expression": r"(?i)\biex\b|invoke-expression",
    "download-and-run": r"(?i)downloadstring|downloadfile|invoke-webrequest|bitsadmin|certutil[^\n]{0,40}urlcache|curl[^\n]{0,60}\|\s*(?:sh|bash)",
    "mshta / regsvr32 / rundll32": r"(?i)\bmshta\b|regsvr32|rundll32",
    "long base64 blob": r"[A-Za-z0-9+/]{300,}={0,2}",
}

def sniff(b):
    h = b[:16]
    if h[:2] == b"MZ": return "exe"
    if h[:4] == b"\x7fELF": return "elf"
    if h[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"): return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe": return "java"
    if h[:4] == b"dex\n": return "dex"
    if h[:4] == b"%PDF": return "pdf"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return "ole"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"): return "zip"
    if h[:4] == b"Rar!": return "rar"
    if h[:6] == b"7z\xbc\xaf\x27\x1c": return "7z"
    if h[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if h[:3] == b"\xff\xd8\xff": return "jpg"
    if h[:4] == b"GIF8": return "gif"
    if h[:2] == b"#!": return "script"
    try:
        sample = b[:2000].decode("utf-8")
        if sample and sum(c.isprintable() or c in "\r\n\t" for c in sample) / len(sample) > 0.95:
            return "text"
    except UnicodeDecodeError:
        pass
    return "unknown"

def analyze_file(name, b, t):
    s, r = 0, []
    def add(key, pts, *title_args, desc_args=()):
        nonlocal s
        s += pts
        r.append((t[key].format(*title_args), t[key + "_desc"].format(*desc_args), pts))

    low = name.lower()
    ext = low.rsplit(".", 1)[-1] if "." in low else ""
    typ = sniff(b)
    z, infos = None, []
    if typ == "zip":
        try:
            z = zipfile.ZipFile(io.BytesIO(b)); infos = z.infolist()[:3000]
            names = [i.filename for i in infos]; ln = [n.lower() for n in names]
            if "androidmanifest.xml" in ln and any(n.endswith(".dex") for n in ln): typ = "apk"
            elif any(n.startswith("word/") for n in ln): typ = "docx"
            elif any(n.startswith("xl/") for n in ln): typ = "xlsx"
            elif any(n.startswith("ppt/") for n in ln): typ = "pptx"
            elif "meta-inf/manifest.mf" in ln: typ = "jar"
        except Exception:
            z, infos = None, []

    if any(c in name for c in ("\u202e", "\u202d")):
        add("rtlo", 50)
    if re.search(r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\s*\.(?:exe|scr|bat|cmd|js|vbs|com|pif|apk|jar|msi|hta|lnk|ps1)$", low):
        add("double_ext", 50)

    flagged_ext = False
    if ext in EXT_BAD:
        add("bad_ext", 50, ext); flagged_ext = True

    mismatch = False
    if typ in EXEC_TYPES and ext not in EXEC_EXT.get(typ, set()) and not flagged_ext:
        add("magic_mismatch", 70, desc_args=(ext or "?", TYPE_LABEL[typ])); mismatch = True
    elif typ not in EXEC_TYPES and typ not in ("unknown", "text", "script") and ext in EXPECT and typ not in EXPECT[ext]:
        add("magic_mismatch", 15, desc_args=(ext, TYPE_LABEL.get(typ, typ))); mismatch = True
    if typ in ("exe", "elf", "macho", "java", "dex") and not flagged_ext and not mismatch:
        add("exec_type", 30, desc_args=(TYPE_LABEL[typ],))

    if typ in ("exe", "elf", "macho") and len(b) > 50_000:
        sample = b[:1_000_000]; n = len(sample)
        H = -sum(c / n * math.log2(c / n) for c in Counter(sample).values())
        if H > 7.2:
            add("packed", 15)

    if z is not None:
        names = [i.filename for i in infos]; ln = [n.lower() for n in names]
        if typ == "apk" or ext == "apk":
            add("apk_base", 25)
            try:
                mi = z.getinfo("AndroidManifest.xml")
                man = z.read(mi) if mi.file_size < 8_000_000 else b""
                found = [p for p in APK_PERMS if p.encode() in man or p.encode("utf-16-le") in man]
                if found:
                    add("apk_perms", min(60, sum(APK_PERMS[p] for p in found)), desc_args=(", ".join(found),))
                    sms = {"READ_SMS", "RECEIVE_SMS"} & set(found)
                    power = {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN"} & set(found)
                    if sms and power:
                        add("apk_banker", 20)
            except Exception:
                pass
            inner = [n for n in names if re.match(r"(?:assets|res/raw)/.*\.(?:apk|dex|jar)$", n, re.I)]
            if inner:
                add("apk_dropper", 25, desc_args=(", ".join(inner[:3]),))
        elif typ == "zip":
            bad = [n for n in names if n.lower().rsplit(".", 1)[-1] in (EXT_BAD | {"apk"}) and "." in n]
            if bad:
                add("archive_exec", 45, desc_args=(", ".join(bad[:3]),))
            if any(i.flag_bits & 1 for i in infos):
                add("archive_enc", 20)
        if any(n.startswith("/") or ".." in n.split("/") for n in names):
            add("zip_slip", 30)
        if typ in ("docx", "xlsx", "pptx") and any("vbaproject.bin" in n for n in ln):
            add("macro", 45)

    data = b[:3_000_000]
    if typ == "ole" and ("VBA".encode("utf-16-le") in data or b"_VBA_PROJECT" in data
                         or "Macros".encode("utf-16-le") in data):
        add("macro", 40)
    if typ == "pdf":
        found = sorted({m.decode() for m in re.findall(rb"/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|RichMedia|SubmitForm)(?![A-Za-z])", data)})
        if found:
            pts = 40 if set(found) & {"JavaScript", "JS", "Launch"} else min(30, 15 * len(found))
            add("pdf_active", pts, desc_args=(", ".join(found),))
    if typ in ("script", "text") or ext in SCRIPT_EXT:
        text = b[:1_000_000].decode("utf-8", "ignore")
        found = [k for k, p in SCRIPT_PATTERNS.items() if re.search(p, text)]
        if found:
            add("script_susp", min(50, 12 * len(found)), desc_args=(", ".join(found),))
        if ext in ("html", "htm", "svg") and re.search(r"(?i)<input[^>]+type\s*=\s*[\"']?password", text):
            add("html_phish", 35)
    elif ext in ("html", "htm", "svg"):
        text = b[:1_000_000].decode("utf-8", "ignore")
        if re.search(r"(?i)<input[^>]+type\s*=\s*[\"']?password", text):
            add("html_phish", 35)
    return s, r, typ

@app.post("/api/file")
def api_file():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("file")
    if not f:
        return jsonify(error="Fayl topilmadi"), 400
    b = f.read(); name = f.filename or "file"
    s, r, typ = analyze_file(name, b, t)
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "md5": hashlib.md5(b).hexdigest(),
          "sha1": hashlib.sha1(b).hexdigest(), "size": len(b), "name": name, "type": TYPE_LABEL.get(typ, typ)}
    return out("Fayl", name, s, r or [(t["file_clean"], t["file_clean_desc"], 0)], lang, ex)

# ------------------------------------------------------------------ Ovoz tahlili
def wav_stats(b):
    try:
        with wave.open(io.BytesIO(b)) as w:
            ch, sw, sr, n = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            dur = n / sr if sr else 0.0
            if sw != 2 or not sr or dur > 300:
                return {"duration": round(dur, 1)}
            frames = w.readframes(min(n, sr * 120))
        a = array.array("h"); a.frombytes(frames[: len(frames) // 2 * 2])
        if sys.byteorder == "big":
            a.byteswap()
        if ch > 1:
            a = a[::ch]
        win = max(1, sr // 50)
        active = sum(1 for i in range(0, len(a) - win, win)
                     if (sum(x * x for x in a[i:i + win]) / win) ** 0.5 > 150)
        total = max(1, (len(a) - win) // win)
        return {"duration": round(dur, 1), "speech_ratio": round(active / total, 2)}
    except Exception:
        return {}

def audio_mime(b):
    if b[:4] == b"RIFF" and b[8:12] == b"WAVE": return "audio/wav"
    if b[:3] == b"ID3" or b[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"): return "audio/mp3"
    if b[:4] == b"OggS": return "audio/ogg"
    if b[:4] == b"fLaC": return "audio/flac"
    return None

def gemini_audio(b, mime):
    """Audioni Gemini orqali matnga o'giradi va sintetik ovoz belgilarini baholaydi. Xato bo'lsa None."""
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        return None
    prompt = ("Transcribe this audio exactly in its original language (write Uzbek in Latin script). "
              "Also judge whether the voice shows traits of synthetic/AI-generated speech. "
              "Return JSON only: {\"transcript\": string, \"synthetic_cues\": \"none\" | \"possible\" | \"likely\"}. "
              "If there is no speech, transcript must be an empty string.")
    payload = json.dumps({
        "contents": [{"role": "user", "parts": [
            {"inlineData": {"mimeType": mime, "data": base64.b64encode(b).decode()}}, {"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"}}).encode()
    models = []
    for gm in (GEMINI_MODEL, "gemini-3.6-flash", "gemini-3.5-flash-lite"):
        if gm not in models:
            models.append(gm)
    for gm in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{gm}:generateContent"
        for attempt in range(2):
            try:
                req = urllib.request.Request(url, payload, {"Content-Type": "application/json", "x-goog-api-key": key})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = json.load(resp)["candidates"][0]["content"]["parts"][0]["text"]
                d = json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip()))
                return {"transcript": str(d.get("transcript") or "")[:6000],
                        "synthetic_cues": str(d.get("synthetic_cues") or "none")}
            except urllib.error.HTTPError as e:
                app.logger.error("Audio (Gemini %s) xatosi: HTTP %s", gm, e.code)
                if e.code in (429, 500, 503) and attempt == 0:
                    time.sleep(1.5); continue
                break
            except Exception as e:
                app.logger.error("Audio (Gemini %s) xatosi: %r", gm, e)
                break
    return None

@app.post("/api/voice")
def api_voice():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("audio")
    if not f:
        return jsonify(error="Audio ma'lumot qabul qilinmadi"), 400
    b = f.read(); size = len(b)
    mime = audio_mime(b)
    stats = wav_stats(b) if mime == "audio/wav" else {}
    extra = {"size": size, "demo": True}
    if stats.get("duration"):
        extra["duration"] = stats["duration"]
    name = f.filename or "live_audio_stream"
    if not mime:
        return out("Ovoz", name, 0, [(t["voice_format"], t["voice_format_desc"], 0)], lang, extra)
    if size > 14_000_000 or stats.get("duration", 0) > 125:
        return out("Ovoz", name, 0, [(t["voice_big"], t["voice_big_desc"], 0)], lang, extra)
    ai = gemini_audio(b, mime)
    if ai is None:
        return out("Ovoz", name, 0, [(t["voice_noai"], t["voice_noai_desc"], 0)], lang, extra)
    transcript = ai["transcript"].strip()
    extra["transcript"] = transcript
    if not transcript:
        return out("Ovoz", name, 0, [(t["voice_empty"], t["voice_empty_desc"], 0)], lang, extra)
    s, r = message_risk(transcript, t)
    cues = ai["synthetic_cues"]
    if cues in ("likely", "possible"):
        pts = 15 if cues == "likely" else 5
        s += pts; r.append((t["voice_synth"], t["voice_synth_desc"], pts))
    if not r:
        r.append((t["voice_ok"], t["voice_ok_desc"], 0))
    extra["demo"] = False
    return out("Ovoz", name, s, r, lang, extra)

NEWS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
]
_news_cache = {"day": "", "t": 0.0, "items": [], "retry": 0.0}
_news_lock = threading.Lock()
_tr_cache, _tr_lock = {}, threading.Lock()

NEWS_LANG_NAMES = {
    "uz": "Uzbek (Latin script, O'zbek tili)",
    "kr": "Uzbek (Cyrillic script, Ўзбек тили)",
    "ru": "Russian",
}

# Internet yoki manba bo'lmaganda ko'rsatiladigan zaxira (har til uchun)
NEWS_FALLBACK = {
    "uz": ("Yangiliklar manbasiga ulanib bo'lmadi",
           "Server tashqi yangilik lentalariga hozircha ulana olmayapti. Birozdan keyin sahifani yangilang."),
    "kr": ("Янгиликлар манбасига уланиб бўлмади",
           "Сервер ташқи янгилик лентасига ҳозирча уланолмаяпти. Бироздан кейин саҳифани янгиланг."),
    "ru": ("Не удалось подключиться к источникам новостей",
           "Сервер пока не может получить внешние ленты новостей. Обновите страницу позже."),
    "en": ("Could not reach the news sources",
           "The server cannot reach external news feeds right now. Please refresh the page later."),
}

def today_key():
    """Toshkent vaqti bo'yicha bugungi sana (UTC+5)."""
    return (datetime.now(timezone.utc) + timedelta(hours=5)).strftime("%Y-%m-%d")

def _clean(txt_, n):
    txt_ = html.unescape(re.sub(r"<[^>]+>", " ", txt_ or ""))
    txt_ = re.sub(r"\s+", " ", txt_).strip()
    return txt_[:n] + ("..." if len(txt_) > n else "")

def parse_feed(name, data):
    root = ET.fromstring(data)
    items = []
    for it in root.iter("item"):
        title = _clean(it.findtext("title"), 200)
        link = (it.findtext("link") or "").strip()
        if not title or not link.startswith(("http://", "https://")):
            continue
        try:
            dt = email.utils.parsedate_to_datetime(it.findtext("pubDate") or "")
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
        items.append({"ts": dt.timestamp(), "date": dt.strftime("%Y-%m-%d"),
                      "title": title, "category": name, "source": name,
                      "content": _clean(it.findtext("description"), 220), "link": link})
        if len(items) >= 8:
            break
    return items

def fetch_feed(name, url):
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuardNews/1.0"})
    with urllib.request.urlopen(req, timeout=8) as r:
        data = r.read(2_000_000)
    return parse_feed(name, data)

def load_news():
    """Yangiliklar kuniga bir marta (Toshkent sanasi o'zgarganda) yangilanadi."""
    now = time.time()
    with _news_lock:
        c = _news_cache
        if now < c["retry"] or (c["items"] and c["day"] == today_key()):
            return c["items"]

        def one(f):
            try:
                return fetch_feed(*f)
            except Exception as e:
                app.logger.error("Yangilik lentasi xatosi (%s): %r", f[0], e)
                return []

        with ThreadPoolExecutor(max_workers=len(NEWS_FEEDS)) as ex:
            batches = list(ex.map(one, NEWS_FEEDS))
        items, seen = [], set()
        for it in sorted((i for b in batches for i in b), key=lambda x: x["ts"], reverse=True):
            if it["title"] not in seen:
                seen.add(it["title"]); items.append(it)
        items = items[:12]
        if items:
            c.update(day=today_key(), t=now, items=items, retry=0.0)
        else:
            c["retry"] = now + 300  # 5 daqiqadan keyin qayta uriniladi
        return c["items"]

def ai_generate(prompt, system="", max_tokens=4000):
    """Anthropic -> Gemini tartibida matn generatsiya qiladi. Xato bo'lsa None."""
    akey = os.environ.get("ANTHROPIC_API_KEY")
    if akey:
        try:
            body = json.dumps({"model": MODEL, "max_tokens": max_tokens, "system": system,
                               "messages": [{"role": "user", "content": prompt}]}).encode()
            req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
                "x-api-key": akey, "anthropic-version": "2023-06-01",
                "content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.load(r)
            text = "".join(b.get("text", "") for b in d.get("content", [])).strip()
            if text:
                return text
        except Exception as e:
            app.logger.error("AI (Anthropic) xatosi: %r", e)
    gkey = os.environ.get("GEMINI_API_KEY", "").strip()
    if gkey:
        models = []
        for gm in (GEMINI_MODEL, "gemini-3.6-flash", "gemini-3.5-flash-lite"):
            if gm not in models:
                models.append(gm)
        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"}}).encode()
        for gm in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{gm}:generateContent"
            for attempt in range(2):
                try:
                    req = urllib.request.Request(url, payload, {
                        "Content-Type": "application/json", "x-goog-api-key": gkey})
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        ans = json.load(resp)["candidates"][0]["content"]["parts"][0]["text"]
                    if ans:
                        return ans
                except urllib.error.HTTPError as e:
                    app.logger.error("AI (Gemini %s) xatosi: HTTP %s", gm, e.code)
                    if e.code in (429, 500, 503) and attempt == 0:
                        time.sleep(1.5)
                        continue
                    break
                except Exception as e:
                    app.logger.error("AI (Gemini %s) xatosi: %r", gm, e)
                    break
    return None

def translate_news(items, lang):
    """Yangiliklarni tanlangan tilga tarjima qiladi (kuniga bir marta, tilga bir marta)."""
    if lang not in NEWS_LANG_NAMES or not items:
        return items
    stamp = _news_cache["t"]
    with _tr_lock:
        c = _tr_cache.get(lang)
        if c and c["stamp"] == stamp and (not c["failed"] or time.time() < c["retry"]):
            return c["items"]
        src = [{"title": i["title"], "content": i["content"]} for i in items]
        prompt = (
            f"Translate the 'title' and 'content' fields of every object in this JSON array into "
            f"{NEWS_LANG_NAMES[lang]}. Keep product/company names, CVE ids, file names and technical "
            f"acronyms as they are. Return ONLY a JSON array with exactly {len(src)} objects, same order, "
            f"each with keys \"title\" and \"content\".\n\n" + json.dumps(src, ensure_ascii=False))
        result, ok = items, False
        raw = ai_generate(prompt, "You are a precise news translator. Output valid JSON only.")
        if raw:
            try:
                raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
                arr = json.loads(raw)
                if isinstance(arr, list) and len(arr) == len(items):
                    result = [{**o, "title": str(t.get("title") or o["title"])[:300],
                               "content": str(t.get("content") or o["content"])[:400],
                               "translated": True} for o, t in zip(items, arr)]
                    ok = True
            except Exception as e:
                app.logger.error("Tarjima JSON xatosi: %r", e)
        _tr_cache[lang] = {"stamp": stamp, "items": result, "failed": not ok,
                           "retry": time.time() + 300}
        return result

@app.get("/api/news")
def api_news():
    lang = request.args.get("lang", "uz")
    if lang not in TEXTS:
        lang = "uz"
    items = load_news()
    if not items:
        title, content = NEWS_FALLBACK.get(lang, NEWS_FALLBACK["en"])
        return jsonify([{"date": today_key(), "title": title, "category": "PhishGuard",
                         "source": "Offline", "content": content, "link": ""}])
    items = translate_news(items, lang)
    return jsonify([{k: v for k, v in i.items() if k != "ts"} for i in items])

@app.get("/api/stats")
def api_stats():
    lang = get_lang(); t = tr(lang)
    now = datetime.now(timezone.utc)
    days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        lv = {row["level"]: row["c"] for row in con.execute("SELECT level, COUNT(*) AS c FROM scans GROUP BY level")}
        kinds = [{"kind": row["kind"], "count": row["c"]} for row in con.execute("SELECT kind, COUNT(*) AS c FROM scans GROUP BY kind ORDER BY c DESC")]
        cnt = {row["d"]: row["c"] for row in con.execute("SELECT substr(created_at,1,10) AS d, COUNT(*) AS c FROM scans WHERE created_at >= ? GROUP BY d", (days[0],))}
    return jsonify(
        total=total,
        levels=[{"level": k, "label": t.get(k, k), "count": lv.get(k, 0)} for k in ("low", "mid", "high")],
        kinds=kinds,
        daily=[{"date": d[5:], "count": cnt.get(d, 0)} for d in days])

# ------------------------------------------------------------------ AI Chat
SYSTEM_PROMPT = (
    "You are PhishGuard Pro AI assistant. Answer any question helpfully and "
    "concisely. You are especially strong in cybersecurity. Reply in the "
    "user's language (Uzbek, Russian or English). "
    "Use simple Markdown (bold, bullet lists). If the message contains an "
    "'avto-skan' note with link scan results, explain those results to the user "
    "in plain words. End EVERY answer with one final line that starts with "
    "'🛡 Xavfsizlik maslahati:' followed by a short, practical cyber-safety tip "
    "related to the topic (or a general one if unrelated)."
)

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)

# Xavfsiz kalkulyator (eval o'rniga)
_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.USub: operator.neg, ast.UAdd: operator.pos,
}

def _calc(node):
    if isinstance(node, ast.Expression):
        return _calc(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.operand))
    raise ValueError("unsupported")

def safe_calc(expr):
    return _calc(ast.parse(expr, mode="eval"))

def generate_local_ai_response(user_text, lang):
    q = user_text.strip()
    q_low = q.lower()
    try:
        if re.match(r"^[\d\.\+\-\*\/\(\)\s]+$", q) and "**" not in q and len(q) < 60:
            return f"🔢 Hisob-kitob natijasi: {q} = {safe_calc(q)}"
    except Exception:
        pass
    if "start up" in q_low or "startup" in q_low:
        return "🚀 Start-up (Startap) — bu yangi, innovatsion g'oyaga asoslangan va tez o'sishga mo'ljallangan biznes loyiha."
    elif any(w in q_low for w in ["salom", "hello", "privet", "assalom"]):
        return "Assalomu alaykum! Men PhishGuard Pro AI maslahatchisiman. Sizga kiberxavfsizlik, dasturlash va boshqa barcha savollar bo'yicha yordam berishga tayyorman."
    elif any(w in q_low for w in ["parol", "password", "пароль"]):
        return "🔐 Parol xavfsizligi: kuchli parol kamida 12 ta belgidan iborat bo'lib, katta-kichik harflar, raqamlar va maxsus belgilarni o'z ichiga olishi kerak."
    else:
        return ("⚠️ Hozir tashqi AI xizmati ulanmagan, shuning uchun faqat oddiy savollarga javob bera olaman. "
                "To'liq javob uchun serverda ANTHROPIC_API_KEY yoki GEMINI_API_KEY o'rnatilishi kerak.")

def clean_messages(ms):
    if not isinstance(ms, list):
        return []
    res = []
    for m in ms[-20:]:
        if not isinstance(m, dict):
            continue
        role = "assistant" if m.get("role") == "assistant" else "user"
        content = str(m.get("content", ""))[:4000]
        if content.strip():
            res.append({"role": role, "content": content})
    # Anthropic API birinchi xabar "user" bo'lishini talab qiladi
    while res and res[0]["role"] != "user":
        res.pop(0)
    return res

@app.post("/api/chat")
def api_chat():
    j = request.get_json(silent=True) or {}
    ms = clean_messages(j.get("messages", []))
    lang = j.get("lang", "uz")
    if not ms:
        return jsonify(error="Xabar kiritilmadi"), 400

    # Avto-skan: oxirgi xabardagi havolalarni tekshirish
    t = tr(lang if lang in TEXTS else "uz")
    scans, seen = [], set()
    for u in URL_RE.findall(ms[-1]["content"]):
        u = u.rstrip(".,;:!?)]}")
        if not u or u in seen or len(scans) >= 3:
            continue
        seen.add(u)
        sc, rs = url_risk(u, t)
        sc = max(0, min(100, int(sc)))
        lv = "low" if sc < 30 else "mid" if sc < 60 else "high"
        try:
            save_scan("Chat-URL", u, sc, lv, [{"t": x[0], "why": x[1]} for x in rs])
        except Exception:
            pass
        scans.append({"url": u[:80], "score": sc, "level": lv, "label": t.get(lv, lv),
                      "reasons": [x[0] for x in rs][:4]})

    model_ms = [dict(m) for m in ms]
    if scans:
        note = "; ".join(
            f"{x['url']} -> {x['label']} ({x['score']}/100)"
            + (": " + ", ".join(x["reasons"]) if x["reasons"] else "")
            for x in scans)
        model_ms[-1]["content"] += "\n\n[PhishGuard avto-skan natijasi: " + note + "]"

    # 1. Anthropic
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            body = json.dumps({
                "model": MODEL, "max_tokens": 1000,
                "system": SYSTEM_PROMPT, "messages": model_ms
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages", body,
                {"x-api-key": anthropic_key,
                 "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
            text = "".join(b.get("text", "") for b in d.get("content", [])).strip()
            if text:
                return jsonify(text=text, scans=scans)
        except Exception as e:
            app.logger.error("Anthropic xatosi: %r", e)

    # 2. Gemini (band bo'lsa qayta urinadi va zaxira modellarga o'tadi)
    gemini_error = ""
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key:
        models = []
        for gm in (GEMINI_MODEL, "gemini-3.6-flash", "gemini-3.5-flash-lite"):
            if gm not in models:
                models.append(gm)
        contents = [{"role": "model" if m["role"] == "assistant" else "user",
                     "parts": [{"text": m["content"]}]} for m in model_ms]
        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": contents}).encode()
        for gm in models:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{gm}:generateContent"
            for attempt in range(2):
                try:
                    req = urllib.request.Request(url, payload, {
                        "Content-Type": "application/json",
                        "x-goog-api-key": gemini_key})
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        ans = json.load(resp)["candidates"][0]["content"]["parts"][0]["text"]
                    if ans:
                        return jsonify(text=ans, scans=scans)
                except urllib.error.HTTPError as e:
                    gemini_error = f"{gm} -> HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}"
                    app.logger.error("Gemini xatosi: %s", gemini_error)
                    if e.code in (429, 500, 503) and attempt == 0:
                        time.sleep(1.5)
                        continue
                    break
                except Exception as e:
                    gemini_error = f"{gm} -> {e!r}"
                    app.logger.error("Gemini xatosi: %s", gemini_error)
                    break

    # 3. Lokal zaxira
    reply = generate_local_ai_response(ms[-1]["content"], lang)
    if gemini_error:
        reply += f"\n\n[Gemini xatosi: {gemini_error}]"
    return jsonify(text=reply, scans=scans)

INDEX_HTML = r'''<!doctype html>
<html lang="uz">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishGuard Pro AI — Cyber Ecosystem</title>
  <style>
    :root {
      --bg: #070a12; --card: #0f172a; --bd: #1e293b; --tx: #f8fafc; --mu: #94a3b8;
      --ac: #38bdf8; --ac-glow: rgba(56, 189, 248, 0.25); --low: #10b981; --mid: #f59e0b; --high: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; color: var(--tx); font: 14px/1.6 'Inter', system-ui, sans-serif; min-height: 100vh;
      background-color: var(--bg);
      background-image:
        radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(99, 102, 241, 0.08) 0%, transparent 40%),
        linear-gradient(rgba(30, 41, 59, 0.2) 1px, transparent 1px),
        linear-gradient(90deg, rgba(30, 41, 59, 0.2) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 32px 32px, 32px 32px;
      background-attachment: fixed; padding-bottom: 60px;
    }
    header {
      background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--bd);
      padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 50;
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 17px; }
    .brand-pulse { width: 10px; height: 10px; background: var(--ac); border-radius: 50%; box-shadow: 0 0 10px var(--ac); animation: pulse 2s infinite; }
    @keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(56,189,248,0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(56,189,248,0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(56,189,248,0); } }
    .lang-select { border: 1px solid var(--bd); background: #070a12; color: var(--tx); padding: 8px 14px; border-radius: 10px; font-weight: 600; cursor: pointer; }
    main { max-width: 900px; margin: 32px auto; padding: 0 20px; }
    .nav-tabs { display: flex; gap: 6px; background: var(--card); padding: 6px; border: 1px solid var(--bd); border-radius: 14px; margin-bottom: 24px; overflow-x: auto; }
    .nav-tabs button { flex: 1; background: transparent; border: 0; padding: 10px 16px; font: inherit; font-weight: 600; color: var(--mu); cursor: pointer; border-radius: 10px; white-space: nowrap; transition: 0.2s; }
    .nav-tabs button.on { background: var(--ac); color: #070a12; font-weight: 800; box-shadow: 0 0 16px var(--ac-glow); }
    .card { background: var(--card); border: 1px solid var(--bd); border-radius: 18px; padding: 28px; box-shadow: 0 12px 35px rgba(0,0,0,0.4); margin-bottom: 24px; position: relative; overflow: hidden; }
    .card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, var(--ac), transparent); }
    h2 { margin: 0 0 6px; font-size: 19px; font-weight: 800; } p { margin: 4px 0 18px; color: var(--mu); font-size: 13.5px; }
    textarea, input[type=file], input[type=text] { width: 100%; border: 1px solid var(--bd); border-radius: 12px; padding: 14px; font: inherit; outline: none; background: #070a12; color: var(--tx); margin-bottom: 14px; }
    textarea:focus, input:focus { border-color: var(--ac); box-shadow: 0 0 12px var(--ac-glow); }
    textarea { min-height: 110px; resize: vertical; }
    .btn { background: var(--ac); color: #070a12; border: 0; border-radius: 10px; padding: 12px 26px; font: inherit; font-weight: 800; cursor: pointer; }
    .btn.ghost { background: transparent; border: 1px solid var(--bd); color: var(--tx); }
    .btn.danger { background: var(--high); color: #fff; }
    .btn:hover { filter: brightness(1.1); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .res-box { margin-top: 16px; padding: 18px; border-radius: 14px; border: 1px solid var(--bd); background: rgba(7, 10, 18, 0.7); }
    .res-box.low { border-color: var(--low); } .res-box.mid { border-color: var(--mid); } .res-box.high { border-color: var(--high); }
    .badge { display: inline-block; padding: 5px 14px; border-radius: 30px; font-weight: 800; font-size: 11px; margin-bottom: 10px; text-transform: uppercase; }
    .badge.low { background: var(--low); color: #000; } .badge.mid { background: var(--mid); color: #000; } .badge.high { background: var(--high); color: #fff; }
    .badge.demo { background: var(--mu); color: #fff; }
    ul { margin: 10px 0 0 18px; padding: 0; } li { margin-bottom: 6px; font-size: 13px; color: #d1d5db; }
    .meter { background: var(--bd); height: 6px; border-radius: 3px; margin: 10px 0; overflow: hidden; }
    .meter .fill { background: var(--ac); height: 100%; width: 0; transition: width 0.4s; }
    .bar { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: 13px; }
    .bar .lbl { width: 50px; color: var(--mu); }
    .bar .track { flex: 1; background: var(--bd); height: 8px; border-radius: 4px; overflow: hidden; }
    .bar .track i { display: block; background: var(--ac); height: 100%; width: 0; }
    .news { border-bottom: 1px solid var(--bd); padding-bottom: 12px; margin-bottom: 12px; }
    .news small { color: var(--ac); font-weight: 600; }
    .news b { display: block; font-size: 15px; margin: 4px 0; color: var(--tx); }
    .voice-box { border: 1px dashed var(--bd); padding: 16px; border-radius: 12px; margin-bottom: 14px; text-align: center; background: rgba(15,23,42,0.4); }
    .msg { margin-bottom: 10px; }
    .msg.err { color: var(--high); }
    .msg code { background: #1e293b; padding: 1px 6px; border-radius: 5px; font-size: 12.5px; }
    .msg pre { background: #030712; border: 1px solid var(--bd); padding: 10px; border-radius: 8px; overflow-x: auto; margin: 6px 0; }
    .msg ul { margin: 6px 0 6px 20px; }
    .chip { display: inline-block; margin: 6px 6px 0 0; padding: 3px 10px; border-radius: 20px; font-size: 11.5px; font-weight: 700; word-break: break-all; }
    .chip.low { background: rgba(16,185,129,.15); color: var(--low); border: 1px solid var(--low); }
    .chip.mid { background: rgba(245,158,11,.15); color: var(--mid); border: 1px solid var(--mid); }
    .chip.high { background: rgba(239,68,68,.15); color: var(--high); border: 1px solid var(--high); }
    #cl.scanning { animation: scanglow 1.2s ease-in-out infinite; }
    @keyframes scanglow { 0%,100% { border-color: var(--bd); box-shadow: none; } 50% { border-color: var(--ac); box-shadow: 0 0 18px var(--ac-glow); } }
    .nav-tabs { scrollbar-width: thin; scrollbar-color: #334155 transparent; }
    .nav-tabs::-webkit-scrollbar { height: 6px; }
    .nav-tabs::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
    .nav-tabs::-webkit-scrollbar-track { background: transparent; }
    .res-box.low .fill { background: var(--low); } .res-box.mid .fill { background: var(--mid); } .res-box.high .fill { background: var(--high); }
    .pts { display: inline-block; margin-left: 6px; padding: 0 7px; border-radius: 10px; background: #1e293b; color: var(--mu); font-size: 11px; font-weight: 700; }
    .tr-box { background: #070a12; border: 1px solid var(--bd); border-radius: 10px; padding: 10px 12px; margin: 6px 0 10px; color: #d1d5db; white-space: pre-wrap; max-height: 160px; overflow-y: auto; }
  </style>
</head>
<body>
<header>
  <div class="brand"><div class="brand-pulse"></div><span id="header-title">PhishGuard Pro AI</span></div>
  <div style="display:flex; align-items:center; gap:14px;">
    <span id="clock" style="font-size:12px; color:var(--mu);"></span>
    <select class="lang-select" id="langSelect">
      <option value="uz">🇺🇿 O'zbek</option>
      <option value="kr">🇺🇿 Ўзбек</option>
      <option value="ru">🇷🇺 Русский</option>
      <option value="en">🇬🇧 English</option>
    </select>
  </div>
</header>
<main>
  <div class="nav-tabs" id="tabs"></div>
  <div class="card">
    <h2 id="card-title">🛡️ Cyber Scanner</h2>
    <p id="card-desc"></p>
    <div id="inp-area"></div>
  </div>
  <div id="out"></div>
</main>
<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const ls=(k,d)=>{try{return localStorage.getItem(k)||d}catch{return d}},sv=(k,v)=>{try{localStorage.setItem(k,v)}catch{}};
let lang = ls("pg_lang", "uz");
let last = null, waiting = false, CH = [], CLOG = [];
let mediaRecorder = null, audioChunks = [];

const UI = {
  uz: {
    brand: "PhishGuard Pro AI System", check: "Tekshirish", upload: "Yuklab Tahlil Qilish", send: "Yuborish",
    url_t: "🔗 URL Scanner", url_d: "Havolani xavfsizlik, IP, Punycode va fishing alomatlariga tekshirish",
    msg_t: "💬 MessageGuard", msg_d: "SMS yoki chat matnidagi shoshiltirish, OTP va firibgarlik iboralarini aniqlash",
    card_t: "💳 CardGuard", card_d: "Bank kartasi raqamini Luhn algoritmi va xavfsizlikka tekshirish",
    file_t: "📁 FileGuard & APK Shield", file_d: "Fayl, skript yoki APK ilova zararli kengaytmalarini tekshirish",
    voice_t: "🎙 VoiceGuard", voice_d: "Audio fayl yuklash yoki mikrofondan jonli yozib vishing/deepfake tahlili",
    chat_t: "🤖 AI Maslahatchi", chat_d: "Istagan savol bering. Xabarga havola yozsangiz, PhishGuard uni avtomatik skan qiladi",
    news_t: "📰 Yangiliklar", news_d: "Jahon IT va kiberxavfsizlik bo'yicha so'nggi global yangiliklar",
    stats_t: "📊 Statistika", stats_d: "Platformadagi umumiy tahlillar va faollik",
    analyzing: "Ekspertizadan o'tkazilmoqda...", start_rec: "🔴 Yozishni boshlash", stop_rec: "⏹ To'xtatish va Tahlil Qilish", recording: "Ovoz yozilmoqda... Gapiring...", or_file: "Yoki audio fayl yuklang:", transcript: "📝 Transkripsiya", type_lbl: "Turi", voice_note: "Audio tahlil uchun Google Gemini ga yuboriladi va saqlanmaydi."
  },
  ru: {
    brand: "PhishGuard Pro AI System", check: "Проверить", upload: "Загрузить и Анализировать", send: "Отправить",
    url_t: "🔗 URL Scanner", url_d: "Проверка ссылки на безопасность, IP, Punycode и фишинг",
    msg_t: "💬 MessageGuard", msg_d: "Обнаружение срочности, запросов OTP и мошеннических фраз в чате",
    card_t: "💳 CardGuard", card_d: "Безопасная проверка номера карты по алгоритму Луна",
    file_t: "📁 FileGuard & APK Shield", file_d: "Проверка файлов, скриптов и APK на вредоносные расширения",
    voice_t: "🎙 VoiceGuard", voice_d: "Загрузка аудио или запись с микрофона для анализа вишинга/дипфейков",
    chat_t: "🤖 AI Консультант", chat_d: "Задайте любой вопрос. Ссылки в сообщении PhishGuard проверит автоматически",
    news_t: "📰 Новости", news_d: "Мировые IT новости и свежие сводки кибербезопасности",
    stats_t: "📊 Статистика", stats_d: "Общая статистика анализов и активность",
    analyzing: "Анализируется...", start_rec: "🔴 Начать запись", stop_rec: "⏹ Остановить и Анализировать", recording: "Идет запись... Говорите...", or_file: "Или загрузите аудиофайл:", transcript: "📝 Расшифровка", type_lbl: "Тип", voice_note: "Для анализа аудио отправляется в Google Gemini и не сохраняется."
  },
  en: {
    brand: "PhishGuard Pro AI System", check: "Check", upload: "Upload & Analyze", send: "Send",
    url_t: "🔗 URL Scanner", url_d: "Scan link for safety, IP, Punycode and phishing indicators",
    msg_t: "💬 MessageGuard", msg_d: "Detect urgency, OTP requests and scam phrases in text",
    card_t: "💳 CardGuard", card_d: "Safe card number validation using Luhn algorithm",
    file_t: "📁 FileGuard & APK Shield", file_d: "Analyze files, scripts and APK packages for malicious extensions",
    voice_t: "🎙 VoiceGuard", voice_d: "Upload audio file or record live from microphone for vishing/deepfake analysis",
    chat_t: "🤖 AI Consultant", chat_d: "Ask anything. Links in your message are auto-scanned by PhishGuard",
    news_t: "📰 News", news_d: "Latest global IT and cybersecurity updates",
    stats_t: "📊 Statistics", stats_d: "Overall platform scans and activity metrics",
    analyzing: "Analyzing...", start_rec: "🔴 Start Recording", stop_rec: "⏹ Stop & Analyze", recording: "Recording in progress... Speak now...", or_file: "Or upload audio file:", transcript: "📝 Transcript", type_lbl: "Type", voice_note: "Audio is sent to Google Gemini for analysis and is not stored."
  }
};
UI.kr = UI.uz;
// "message" rejimi uchun kalitlar (msg_* ga alias)
Object.keys(UI).forEach(l => { UI[l].message_t = UI[l].msg_t; UI[l].message_d = UI[l].msg_d; });

function T() { return { ...(UI["en"] || {}), ...(UI[lang] || {}) }; }
const MODES = ["url", "message", "card", "file", "voice", "chat", "news", "stats"];
let cur = "url";

const langSelect = $("#langSelect");
langSelect.value = lang;
langSelect.onchange = () => { lang = langSelect.value; sv("pg_lang", lang); updateUI(); };

function updateUI(){
  const t = T();
  $("#header-title").textContent = t.brand || "PhishGuard Pro AI";
  renderTabs();
  setMode(cur);
}

function renderTabs(){
  const t = T();
  $("#tabs").innerHTML = MODES.map(k=>`<button class="${k===cur?'on':''}" data-m="${k}">${t[k+'_t'] || k}</button>`).join("");
  $$("#tabs button").forEach(b=>b.onclick=()=>setMode(b.dataset.m));
}

function setMode(m){
  cur = m; const t = T();
  renderTabs();
  $("#card-title").textContent = t[m+'_t'] || m;
  $("#card-desc").textContent = t[m+'_d'] || "";
  $("#out").innerHTML = "";
  if(m === "news"){ $("#inp-area").innerHTML = ""; loadNews(); return; }
  if(m === "stats"){ $("#inp-area").innerHTML = ""; loadStats(); return; }
  if(m === "chat"){
    $("#inp-area").innerHTML = `<div id="cl" style="max-height:220px;overflow-y:auto;margin-bottom:12px;background:#070a12;padding:12px;border-radius:10px;border:1px solid var(--bd)"></div><textarea id="ci" placeholder="Savolingizni yozing..."></textarea><button class="btn" id="cb">${t.send}</button>`;
    drawChat();
    $("#cb").onclick = () => sendChat($("#ci").value);
    $("#ci").onkeydown = e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat($("#ci").value); } };
    return;
  }
  if(m === "voice"){
    $("#inp-area").innerHTML = `
      <div class="voice-box">
        <div id="v-status" style="margin-bottom:12px; font-weight:600; color:var(--mu);">${t.voice_d}</div>
        <div style="display:flex; justify-content:center; gap:10px; margin-bottom:14px;">
          <button class="btn" id="rec-start">${t.start_rec}</button>
          <button class="btn danger" id="rec-stop" disabled>${t.stop_rec}</button>
        </div>
      </div>
      <div style="font-size:13px; color:var(--mu); margin-bottom:6px;">${t.or_file}</div>
      <input type="file" accept="audio/*" id="audio-file-input">
      <button class="btn" id="audio-upload-btn">${t.upload}</button>
    `;
    setupVoice();
    return;
  }
  if(m === "file"){
    $("#inp-area").innerHTML = `<input type="file" id="f"><button class="btn" id="go">${t.upload}</button>`;
    $("#go").onclick = () => fileScan($("#f").files[0], m);
  } else {
    let isText = (m === "card" || m === "url");
    const ph = m === "card" ? "8600 0000 0000 0000" : "https://...";
    $("#inp-area").innerHTML = (isText ? `<input type="text" id="t" placeholder="${ph}" autocomplete="off">` : `<textarea id="t"></textarea>`) + `<button class="btn" id="go">${t.check}</button>`;
    $("#go").onclick = () => runScan(m, $("#t").value);
    $("#t").onkeydown = e => { if (e.key === "Enter" && (isText || e.ctrlKey)) { e.preventDefault(); $("#go").click(); } };
    if (m === "card") {
      const el = $("#t"); el.inputMode = "numeric"; el.maxLength = 23;
      el.oninput = () => { el.value = el.value.replace(/\D/g, "").slice(0, 19).replace(/(.{4})/g, "$1 ").trim(); };
    }
  }
}

async function toWav16k(blob) {
  const ab = await blob.arrayBuffer();
  const AC = window.AudioContext || window.webkitAudioContext;
  const ctx = new AC();
  let buf;
  try { buf = await ctx.decodeAudioData(ab); } finally { if (ctx.close) ctx.close(); }
  const sr = 16000, dur = Math.min(buf.duration, 120), len = Math.max(1, Math.ceil(dur * sr));
  const off = new OfflineAudioContext(1, len, sr);
  const src = off.createBufferSource(); src.buffer = buf; src.connect(off.destination); src.start(0);
  const d = (await off.startRendering()).getChannelData(0);
  const dv = new DataView(new ArrayBuffer(44 + d.length * 2));
  const w = (o, s) => { for (let i = 0; i < s.length; i++) dv.setUint8(o + i, s.charCodeAt(i)); };
  w(0, "RIFF"); dv.setUint32(4, 36 + d.length * 2, true); w(8, "WAVE"); w(12, "fmt "); dv.setUint32(16, 16, true);
  dv.setUint16(20, 1, true); dv.setUint16(22, 1, true); dv.setUint32(24, sr, true); dv.setUint32(28, sr * 2, true);
  dv.setUint16(32, 2, true); dv.setUint16(34, 16, true); w(36, "data"); dv.setUint32(40, d.length * 2, true);
  for (let i = 0; i < d.length; i++) { const x = Math.max(-1, Math.min(1, d[i])); dv.setInt16(44 + i * 2, x < 0 ? x * 0x8000 : x * 0x7FFF, true); }
  return new Blob([dv], { type: "audio/wav" });
}

async function sendVoice(blob, name) {
  const t = T();
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  let wav = blob;
  try { wav = await toWav16k(blob); name = "voice.wav"; } catch (e) {}
  const fd = new FormData();
  fd.append("audio", wav, name); fd.append("lang", lang);
  renderResult(await api("/api/voice", { method: "POST", body: fd }));
}

async function setupVoice() {
  const t = T();
  const startBtn = $("#rec-start"), stopBtn = $("#rec-stop"), statusEl = $("#v-status");
  $("#audio-upload-btn").onclick = () => {
    const f = $("#audio-file-input").files[0];
    if (f) sendVoice(f, f.name);
  };
  let timer = null;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    mediaRecorder.ondataavailable = e => { if (e.data.size > 0) audioChunks.push(e.data); };
    mediaRecorder.onstop = async () => {
      const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType || "audio/webm" });
      audioChunks = [];
      stream.getTracks().forEach(tr => tr.stop());
      await sendVoice(blob, "mic_recording.webm");
    };
    startBtn.onclick = () => {
      audioChunks = []; mediaRecorder.start();
      startBtn.disabled = true; stopBtn.disabled = false;
      statusEl.textContent = t.recording; statusEl.style.color = "var(--high)";
      timer = setTimeout(() => { if (mediaRecorder.state === "recording") stopBtn.click(); }, 60000);
    };
    stopBtn.onclick = () => {
      clearTimeout(timer);
      if (mediaRecorder.state === "recording") mediaRecorder.stop();
      startBtn.disabled = true; stopBtn.disabled = true;
      statusEl.textContent = t.voice_note; statusEl.style.color = "var(--mu)";
    };
  } catch (err) {
    statusEl.textContent = "Mikrofondan foydalanishga ruxsat berilmadi yoki qurilma topilmadi. Fayl yuklash orqali foydalanishingiz mumkin.";
    statusEl.style.color = "var(--mid)";
    startBtn.disabled = true;
  }
}

async function api(url, opts) {
  try { return await fetch(url, opts).then(r => r.json()); } catch { return { error: "Network error" }; }
}

async function runScan(m, textVal){
  if(!textVal.trim()) return;
  const t = T();
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  const res = await api("/api/" + m, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({text: textVal, lang: lang}) });
  renderResult(res);
}

async function fileScan(fileObj, modeStr){
  if(!fileObj) return;
  const t = T();
  const fd = new FormData();
  fd.append(modeStr === "voice" ? "audio" : "file", fileObj);
  fd.append("lang", lang);
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  const res = await api("/api/" + modeStr, {method: "POST", body: fd});
  renderResult(res);
}

function esc(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function applyWidths() {
  $$("[data-w]").forEach(el => { el.style.width = el.dataset.w + "%"; });
}

function renderResult(r){
  const t = T();
  if(r.error) { $("#out").innerHTML = `<div class="card" style="color:var(--high)">${esc(r.error)}</div>`; return; }
  last = r;
  const demo = !!r.demo, lv = demo ? "demo" : r.level, score = Number(r.score) || 0;
  let extra = "";
  if (r.masked) extra += `<p><b>Brand:</b> ${esc(r.brand)} | ${esc(r.masked)}</p>`;
  if (r.name) extra += `<p><b>${esc(r.name)}</b>${r.size != null ? ` - ${(r.size / 1024).toFixed(1)} KB` : ""}${r.type ? ` - ${esc(t.type_lbl || "Type")}: ${esc(r.type)}` : ""}</p>`;
  else if (r.duration) extra += `<p>${esc(r.duration)} s${r.size != null ? ` - ${(r.size / 1024).toFixed(1)} KB` : ""}</p>`;
  if (r.sha256) extra += `<p><b>SHA-256:</b> <code>${esc(r.sha256)}</code><br><a href="https://www.virustotal.com/gui/file/${encodeURIComponent(r.sha256)}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a></p>`;
  if (r.transcript) extra += `<p style="margin-bottom:0"><b>${esc(t.transcript || "Transcript")}</b></p><div class="tr-box">${esc(r.transcript)}</div>`;

  const reasons = (r.reasons || []).map(x => `<li><b>${esc(x.t)}:</b> ${esc(x.why)}${x.pts ? `<span class="pts">+${Number(x.pts)}</span>` : ""}</li>`).join("");
  const head = demo
    ? `<span class="badge demo">${esc(t.demo_label || "Natija")}</span>`
    : `<span class="badge ${lv}">${esc(r.label)} (${score}/100)</span>
       <div class="meter"><div class="fill" data-w="${score}"></div></div>
       <p>ℹ️ ${esc(r.advice)}</p>`;

  $("#out").innerHTML = `<div class="card res-box ${lv}">${head}${extra}<ul>${reasons}</ul>
    <button class="btn ghost" id="cp" type="button" style="margin-top:14px;">${esc(t.copy || "Nusxalash")}</button></div>`;
  $("#cp").onclick = copyReport;
  applyWidths();
}

async function copyReport() {
  if (!last) return;
  const t = T();
  const lines = [`${last.label} (${last.score}/100)`, last.advice, ...(last.reasons || []).map(x => `- ${x.t}: ${x.why}`)];
  try { await navigator.clipboard.writeText(lines.join("\n")); alert(t.copied || "Nusxalandi!"); } catch {}
}

function renderMd(src) {
  let s = esc(src);
  const blocks = [];
  s = s.replace(/```(?:\w+)?\n?([\s\S]*?)```/g, (m, c) => { blocks.push(c); return "\u0000B" + (blocks.length - 1) + "\u0000"; });
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
  s = s.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<i>$2</i>");
  const out = []; let inList = false;
  for (const ln of s.split("\n")) {
    const h = ln.match(/^#{1,3}\s+(.*)/);
    const li = ln.match(/^\s*[*\-•]\s+(.*)/);
    if (li) { if (!inList) { out.push("<ul>"); inList = true; } out.push("<li>" + li[1] + "</li>"); continue; }
    if (inList) { out.push("</ul>"); inList = false; }
    out.push(h ? "<b>" + h[1] + "</b><br>" : ln + "<br>");
  }
  if (inList) out.push("</ul>");
  return out.join("").replace(/\u0000B(\d+)\u0000/g, (m, i) => "<pre><code>" + blocks[i] + "</code></pre>");
}

function drawChat() {
  const el = $("#cl"); if (!el) return;
  el.classList.toggle("scanning", waiting);
  el.innerHTML = CLOG.map(x => {
    if (x.role === "user") {
      const chips = (x.scans || []).map(sc =>
        `<div class="chip ${esc(sc.level)}">🛡 ${esc(sc.url)} — ${esc(sc.label)} (${Number(sc.score)}/100)</div>`).join("");
      return `<div class="msg" style="white-space:pre-wrap"><b>👤</b> ${esc(x.content)}${chips}</div>`;
    }
    return `<div class="msg ${x.err ? "err" : ""}"><b>🤖</b> ${x.err ? esc(x.content) : renderMd(x.content)}</div>`;
  }).join("") + (waiting ? `<div style="color:var(--mu)"><b>🤖</b> Yozmoqda...</div>` : "");
  el.scrollTop = el.scrollHeight;
}

async function sendChat(v) {
  if (!v.trim() || waiting) return;
  CH.push({ role: "user", content: v }); CLOG.push({ role: "user", content: v });
  $("#ci").value = ""; waiting = true; drawChat();
  const res = await api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ messages: CH, lang }) });
  waiting = false;
  if (res.scans && res.scans.length) {
    for (let i = CLOG.length - 1; i >= 0; i--) { if (CLOG[i].role === "user") { CLOG[i].scans = res.scans; break; } }
  }
  if (res.text) { CH.push({ role: "assistant", content: res.text }); CLOG.push({ role: "assistant", content: res.text }); }
  else { CH.pop(); CLOG.push({ role: "assistant", content: res.error || "Xatolik yuz berdi", err: true }); }
  drawChat();
}

async function loadNews() {
  $("#inp-area").innerHTML = `<p>${esc(T().analyzing)}</p>`;
  const res = await api("/api/news?lang=" + lang);
  if (!Array.isArray(res)) { $("#inp-area").textContent = res.error || "Error"; return; }
  $("#inp-area").innerHTML = res.map(n => {
    const safe = /^https?:\/\//.test(n.link || "");
    const title = safe
      ? `<a href="${esc(n.link)}" target="_blank" rel="noopener noreferrer" style="color:var(--tx);text-decoration:none">${esc(n.title)} ↗</a>`
      : esc(n.title);
    return `<div class="news"><small>${esc(n.date)} &bull; ${esc(n.source || n.category)}${n.translated ? " &bull; 🌐 AI" : ""}</small><b>${title}</b><p style="margin:0">${esc(n.content)}</p></div>`;
  }).join("");
}

async function loadStats() {
  const t = T(), s = await api("/api/stats?lang=" + lang);
  if (s.error) { $("#inp-area").textContent = s.error; return; }
  const max = Math.max(1, ...(s.daily || []).map(d => d.count));
  $("#inp-area").innerHTML =
    `<p><b>${esc(t.total || "Jami")}:</b> ${Number(s.total || 0)}</p>` +
    (s.levels || []).map(l => `<span class="badge ${esc(l.level)}">${esc(l.label)}: ${Number(s.total || 0) > 0 ? Number(l.count) : 0}</span>`).join(" ") +
    `<p class="muted" style="margin-top:14px;"><b>${esc(t.last7 || "Oxirgi 7 kun")}</b></p>` +
    (s.daily || []).map(d => `<div class="bar"><span class="lbl">${esc(d.date)}</span><div class="track"><i data-w="${Math.round(d.count / max * 100)}"></i></div><span>${Number(d.count)}</span></div>`).join("") +
    `<p class="muted" style="margin-top:10px; font-size:12px;">${(s.kinds || []).map(k => `${esc(k.kind)}: ${Number(k.count)}`).join(" &bull; ")}</p>`;
  applyWidths();
}

function updateClock() {
  let el = $("#clock");
  if (el) el.textContent = new Intl.DateTimeFormat("uz-UZ", {hour:"2-digit",minute:"2-digit",second:"2-digit"}).format(new Date()) + " / LOCAL";
}
setInterval(updateClock, 1000); updateClock();
updateUI();
</script>
</body>
</html>'''

@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.get("/health")
def health():
    try:
        with db() as con:
            con.execute("SELECT 1")
        return jsonify(status="ok")
    except Exception:
        return jsonify(status="db_error"), 503

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
