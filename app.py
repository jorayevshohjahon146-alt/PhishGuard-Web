"""
PhishGuard Pro AI - raqamli xavfsizlik va kiberhujumlar tahlili ekotizimi.
Ko'p tilli (i18n) versiya: Flask + SQLite.  v3 (bitta fayl, qat'iy CSP, dark mode, yaxshilangan UI)

Ishga tushirish:
    pip install flask gunicorn
    ANTHROPIC_API_KEY=... gunicorn -w 2 -b 0.0.0.0:10000 phishguard_app:app
"""
import difflib, hashlib, io, ipaddress, json, os, re, sqlite3, threading, time
import urllib.request, wave, zipfile
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)  # frontend shu fayl ichida, pastda berilgan
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.json.ensure_ascii = False
DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.db"))
MODEL = os.environ.get("PHISHGUARD_MODEL", "claude-sonnet-5-5")
RETENTION_DAYS = int(os.environ.get("PHISHGUARD_RETENTION_DAYS", "90"))  # eski yozuvlar o'chiriladi

# ------------------------------------------------------------------ DB
@contextmanager
def db():
    """Ulanishni to'g'ri yopadigan helper (sqlite3 'with' faqat commit qiladi)."""
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

# ------------------------------------------------------------------ Xavfsizlik: headerlar va rate limit
@app.after_request
def add_security_headers(resp):
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    if request.path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; script-src 'self'; style-src 'self'; "
                 "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    return resp

_hits, _lock = defaultdict(deque), threading.Lock()
LIMITS = {"/api/chat": 8}          # so'rov / daqiqa (IP bo'yicha); qolganlari uchun DEFAULT_LIMIT
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
        if len(_hits) > 5000:      # xotirani tozalash
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
                del _hits[k]
        return True

@app.before_request
def throttle():
    if request.method == "POST" and request.path.startswith("/api/"):
        if not allowed(request.path, LIMITS.get(request.path, DEFAULT_LIMIT)):
            return jsonify(error=tr(get_lang())["rate_limit"]), 429

@app.errorhandler(413)
def too_big(_):
    return jsonify(error=tr(get_lang())["too_big"]), 413

@app.errorhandler(500)
def server_error(_):
    return jsonify(error="Server error"), 500

# ------------------------------------------------------------------ Tarjimalar
TEXTS = {
    "uz": {
        "low": "Past xavf", "mid": "O'rta xavf", "high": "Yuqori xavf",
        "adv_low": "Aniq xavf belgisi topilmadi, lekin ehtiyot bo'ling.",
        "adv_mid": "Shubhali belgilar bor. Ma'lumot kiritmang.",
        "adv_high": "Diqqat! Bu fishing yoki xavfli tahdid bo'lishi mumkin. Ochmang!",
        "invalid_url": "URL tushunarsiz", "invalid_url_desc": "Manzil noto'g'ri yozilgan.",
        "no_https": "HTTPS yo'q", "no_https_desc": "Ma'lumot shifrlanmagan.",
        "imitation": "'{}' brendiga taqlid", "imitation_desc": "Rasmiy domen: {}",
        "safe": "Xavfsiz ko'rinadi", "safe_desc": "Aniq fishing belgisi aniqlanmadi.",
        "urgency": "Shoshiltirish", "urgency_desc": "Firibgarlar vaqt bermasdan harakat qilishga majburlaydi.",
        "secret_req": "Maxfiy ma'lumot so'rovi", "secret_req_desc": "Bank hech qachon SMS kod yoki parolni so'ramaydi.",
        "no_msg_threat": "Belgilar topilmadi", "no_msg_threat_desc": "Shubhali iboralar aniqlanmadi.",
        "card_len": "Raqam to'liq emas", "card_len_desc": "13-19 xonali karta raqamini kiriting.",
        "card_note": "Eslatma", "card_note_desc": "Karta raqami xavfsizlik uchun saqlanmaydi.",
        "bad_ext": "Xavfli kengaytma: .{}", "bad_ext_desc": "Bajariladigan yoki shubhali fayl turi.",
        "perm_warn": "Ruxsat: {}", "perm_warn_desc": "Bu ruxsat xavfli APK ilovalarda suiiste'mol qilinadi.",
        "file_clean": "Fayl tozaga o'xshaydi", "file_clean_desc": "Aniq zararli imzo topilmadi.",
        "ip_host": "IP manzil", "ip_host_desc": "Havola domen o'rniga to'g'ridan-to'g'ri IP manzilga olib boradi.",
        "punycode": "Punycode (xn--)", "punycode_desc": "Harflari o'xshash soxta domen bo'lishi mumkin.",
        "at_sign": "'@' belgisi", "at_sign_desc": "Haqiqiy manzil '@' dan keyin yashiringan bo'lishi mumkin.",
        "many_sub": "Ko'p subdomen", "many_sub_desc": "Uzun subdomen zanjiri firibgarlikda ko'p uchraydi.",
        "bad_tld": "Shubhali domen zonasi", "bad_tld_desc": "Bu zonalar fishing uchun ko'p ishlatiladi.",
        "shortener": "Qisqartirilgan havola", "shortener_desc": "Haqiqiy manzil yashirin; ochishdan oldin tekshiring.",
        "card_luhn": "Luhn tekshiruvi o'tmadi", "card_luhn_desc": "Raqamda xato bor yoki karta soxta.",
        "dbl_ext": "Ikki marta kengaytma", "dbl_ext_desc": "Fayl zararsiz ko'rinishga yashiringan.",
        "disguised": "Yashirin bajariladigan fayl", "disguised_desc": "Ichida .exe/ELF imzosi bor, kengaytma esa boshqa.",
        "voice_demo": "Demo rejim", "voice_demo_desc": "Deepfake aniqlash modeli hali ulanmagan; natija ishonchli emas.",
        "prize": "Yutuq va'dasi", "prize_desc": "Soxta sovrin ko'pincha ma'lumot yig'ish uchun ishlatiladi.",
        "acc_threat": "Hisob bloklanishi tahdidi", "acc_threat_desc": "Qo'rqitib ma'lumot so'rash keng tarqalgan usul.",
        "rate_limit": "So'rovlar juda ko'p. Birozdan so'ng urinib ko'ring.", "too_big": "Fayl juda katta (maks. 20 MB).",
        "no_file": "Fayl tanlanmadi.", "bad_msgs": "Xabar formati noto'g'ri.",
        "ai_off": "AI kaliti sozlanmagan.", "ai_err": "AI xatosi, keyinroq urinib ko'ring."
    },
    "kr": {
        "low": "Паст хавф", "mid": "Ўрта хавф", "high": "Юқори хавф",
        "adv_low": "Аниқ хавф белгиси топилмади, лекин эҳтиёт бўлинг.",
        "adv_mid": "Шубҳали белгилар бор. Маълумот киритманг.",
        "adv_high": "Диққат! Бу фишинг ёки хавфли таҳдид бўлиши мумкин. Очманг!",
        "invalid_url": "URL тушунарсиз", "invalid_url_desc": "Манзил нотўғри ёзилган.",
        "no_https": "HTTPS йўқ", "no_https_desc": "Маълумот шифрланмаган.",
        "imitation": "'{}' брендига тақлид", "imitation_desc": "Расмий домен: {}",
        "safe": "Хавфсиз кўринади", "safe_desc": "Аниқ фишинг белгиси аниқланмади.",
        "urgency": "Шошилтириш", "urgency_desc": "Фирибгарлар вақт бермасдан ҳаракат қилишга мажбурлайди.",
        "secret_req": "Махфий маълумот сўрови", "secret_req_desc": "Банк ҳеч қачон SMS код ёки паролни сўрамайди.",
        "no_msg_threat": "Белгилар топилмади", "no_msg_threat_desc": "Шубҳали иборалар аниқланмади.",
        "card_len": "Рақам тўлиқ эмас", "card_len_desc": "13-19 хонали карта рақамини киритинг.",
        "card_note": "Эслатма", "card_note_desc": "Карта рақами хавфсизлик учун сақланмайди.",
        "bad_ext": "Хавфли кенгайтма: .{}", "bad_ext_desc": "Бажариладиган ёки шубҳали файл тури.",
        "perm_warn": "Рухсат: {}", "perm_warn_desc": "Бу рухсат хавфли APK иловаларда суиистеъмол қилинади.",
        "file_clean": "Файл тозага ўхшайди", "file_clean_desc": "Аниқ зарарли имзо топилмади.",
        "ip_host": "IP манзил", "ip_host_desc": "Ҳавола домен ўрнига тўғридан-тўғри IP манзилга олиб боради.",
        "punycode": "Punycode (xn--)", "punycode_desc": "Ҳарфлари ўхшаш сохта домен бўлиши мумкин.",
        "at_sign": "'@' белгиси", "at_sign_desc": "Ҳақиқий манзил '@' дан кейин яширинган бўлиши мумкин.",
        "many_sub": "Кўп субдомен", "many_sub_desc": "Узун субдомен занжири фирибгарликда кўп учрайди.",
        "bad_tld": "Шубҳали домен зонаси", "bad_tld_desc": "Бу зоналар фишинг учун кўп ишлатилади.",
        "shortener": "Қисқартирилган ҳавола", "shortener_desc": "Ҳақиқий манзил яширин; очишдан олдин текширинг.",
        "card_luhn": "Luhn текшируви ўтмади", "card_luhn_desc": "Рақамда хато бор ёки карта сохта.",
        "dbl_ext": "Икки марта кенгайтма", "dbl_ext_desc": "Файл зарарсиз кўринишга яширинган.",
        "disguised": "Яширин бажариладиган файл", "disguised_desc": "Ичида .exe/ELF имзоси бор, кенгайтма эса бошқа.",
        "voice_demo": "Демо режим", "voice_demo_desc": "Deepfake аниқлаш модели ҳали уланмаган; натижа ишончли эмас.",
        "prize": "Ютуқ ваъдаси", "prize_desc": "Сохта совринлар кўпинча маълумот йиғиш учун ишлатилади.",
        "acc_threat": "Ҳисоб блокланиши таҳдиди", "acc_threat_desc": "Қўрқитиб маълумот сўраш кенг тарқалган усул.",
        "rate_limit": "Сўровлар жуда кўп. Бироздан сўнг уриниб кўринг.", "too_big": "Файл жуда катта (макс. 20 MB).",
        "no_file": "Файл танланмади.", "bad_msgs": "Хабар формати нотўғри.",
        "ai_off": "AI калити созланмаган.", "ai_err": "AI хатоси, кейинроқ уриниб кўринг."
    },
    "ru": {
        "low": "Низкий риск", "mid": "Средний риск", "high": "Высокий риск",
        "adv_low": "Явных угроз не обнаружено, но будьте осторожны.",
        "adv_mid": "Есть подозрительные признаки. Не вводите данные.",
        "adv_high": "Внимание! Это фишинг или вредоносный ресурс. Не открывайте!",
        "invalid_url": "Некорректный URL", "invalid_url_desc": "Адрес указан неверно.",
        "no_https": "Отсутствует HTTPS", "no_https_desc": "Данные передаются в незашифрованном виде.",
        "imitation": "Имитация бренда '{}'", "imitation_desc": "Официальный домен: {}",
        "safe": "Выглядит безопасно", "safe_desc": "Признаков фишинга не обнаружено.",
        "urgency": "Срочность", "urgency_desc": "Злоумышленники заставляют действовать без раздумий.",
        "secret_req": "Запрос секретных данных", "secret_req_desc": "Банк никогда не запрашивает коды из SMS или пароли.",
        "no_msg_threat": "Угроз не найдено", "no_msg_threat_desc": "Подозрительных фраз не обнаружено.",
        "card_len": "Номер неполный", "card_len_desc": "Введите 13-19-значный номер карты.",
        "card_note": "Примечание", "card_note_desc": "Номер карты не сохраняется в целях безопасности.",
        "bad_ext": "Опасное расширение: .{}", "bad_ext_desc": "Исполняемый или подозрительный тип файла.",
        "perm_warn": "Разрешение: {}", "perm_warn_desc": "Это разрешение часто используется во вредоносных APK.",
        "file_clean": "Файл выглядит безопасным", "file_clean_desc": "Вредоносных сигнатур не обнаружено.",
        "ip_host": "IP-адрес вместо домена", "ip_host_desc": "Ссылка ведёт напрямую на IP-адрес.",
        "punycode": "Punycode (xn--)", "punycode_desc": "Возможен поддельный домен с похожими символами.",
        "at_sign": "Символ '@'", "at_sign_desc": "Настоящий адрес может скрываться после '@'.",
        "many_sub": "Много поддоменов", "many_sub_desc": "Длинная цепочка поддоменов типична для мошенников.",
        "bad_tld": "Подозрительная доменная зона", "bad_tld_desc": "Эти зоны часто используют для фишинга.",
        "shortener": "Сокращённая ссылка", "shortener_desc": "Реальный адрес скрыт; проверьте перед открытием.",
        "card_luhn": "Проверка Луна не пройдена", "card_luhn_desc": "В номере ошибка или карта поддельная.",
        "dbl_ext": "Двойное расширение", "dbl_ext_desc": "Файл маскируется под безобидный.",
        "disguised": "Замаскированный исполняемый файл", "disguised_desc": "Внутри сигнатура .exe/ELF, а расширение другое.",
        "voice_demo": "Демо-режим", "voice_demo_desc": "Модель выявления дипфейков не подключена; результат недостоверен.",
        "prize": "Обещание выигрыша", "prize_desc": "Фальшивые призы часто используют для сбора данных.",
        "acc_threat": "Угроза блокировки аккаунта", "acc_threat_desc": "Запугивание — частый приём для выманивания данных.",
        "rate_limit": "Слишком много запросов. Повторите позже.", "too_big": "Файл слишком большой (макс. 20 МБ).",
        "no_file": "Файл не выбран.", "bad_msgs": "Неверный формат сообщения.",
        "ai_off": "Ключ AI не настроен.", "ai_err": "Ошибка AI, повторите позже."
    },
    "en": {
        "low": "Low Risk", "mid": "Medium Risk", "high": "High Risk",
        "adv_low": "No clear signs of threat found, but remain cautious.",
        "adv_mid": "Suspicious indicators found. Do not enter sensitive data.",
        "adv_high": "Warning! This may be phishing or malware. Do not open!",
        "invalid_url": "Invalid URL", "invalid_url_desc": "The URL structure is incorrect.",
        "no_https": "No HTTPS", "no_https_desc": "Connection is not encrypted.",
        "imitation": "Imitating brand '{}'", "imitation_desc": "Official domain: {}",
        "safe": "Appears Safe", "safe_desc": "No phishing indicators detected.",
        "urgency": "Urgency Indicator", "urgency_desc": "Scammers rush victims to act without thinking.",
        "secret_req": "Sensitive Data Request", "secret_req_desc": "Banks never ask for OTP or passwords.",
        "no_msg_threat": "No Threats Found", "no_msg_threat_desc": "No suspicious language detected.",
        "card_len": "Incomplete Number", "card_len_desc": "Enter a valid 13-19 digit card number.",
        "card_note": "Notice", "card_note_desc": "Card numbers are never stored.",
        "bad_ext": "Dangerous extension: .{}", "bad_ext_desc": "Executable or risky file type.",
        "perm_warn": "Permission: {}", "perm_warn_desc": "Abused in malicious APK packages.",
        "file_clean": "File appears clean", "file_clean_desc": "No malicious signatures detected.",
        "ip_host": "IP address host", "ip_host_desc": "The link points straight to an IP address, not a domain.",
        "punycode": "Punycode (xn--)", "punycode_desc": "May be a look-alike (homograph) domain.",
        "at_sign": "'@' in URL", "at_sign_desc": "The real destination may be hidden after the '@'.",
        "many_sub": "Many subdomains", "many_sub_desc": "Long subdomain chains are common in scams.",
        "bad_tld": "Suspicious TLD", "bad_tld_desc": "These zones are frequently abused for phishing.",
        "shortener": "Shortened link", "shortener_desc": "The real destination is hidden; verify before opening.",
        "card_luhn": "Luhn check failed", "card_luhn_desc": "The number has a typo or the card is fake.",
        "dbl_ext": "Double extension", "dbl_ext_desc": "The file is disguised as something harmless.",
        "disguised": "Disguised executable", "disguised_desc": "Contains an .exe/ELF signature but a different extension.",
        "voice_demo": "Demo mode", "voice_demo_desc": "No deepfake-detection model is connected; the result is not reliable.",
        "prize": "Prize promise", "prize_desc": "Fake prizes are often used to harvest data.",
        "acc_threat": "Account-lock threat", "acc_threat_desc": "Intimidation is a common trick to extract data.",
        "rate_limit": "Too many requests. Please try again shortly.", "too_big": "File too large (max 20 MB).",
        "no_file": "No file selected.", "bad_msgs": "Invalid message format.",
        "ai_off": "AI key is not configured.", "ai_err": "AI error, please try again later."
    },
    "tr": {
        "low": "Düşük Risk", "mid": "Orta Risk", "high": "Yüksek Risk",
        "adv_low": "Belirgin bir tehdit bulunamadı, yine de dikkatli olun.",
        "adv_mid": "Şüpheli göstergeler var. Bilgi girmeyin.",
        "adv_high": "Dikkat! Bu bir oltalama veya zararlı içerik olabilir. Açmayın!",
        "invalid_url": "Geçersiz URL", "invalid_url_desc": "Adres biçimi hatalı.",
        "no_https": "HTTPS Yok", "no_https_desc": "Veri iletimi şifrelenmemiş.",
        "imitation": "'{}' markasını taklit etme", "imitation_desc": "Resmi alan adı: {}",
        "safe": "Güvenli Görünüyor", "safe_desc": "Oltalama belirtisi bulunamadı.",
        "urgency": "Acele Ettirme", "urgency_desc": "Dolandırıcılar düşünmeden hareket etmeye zorlar.",
        "secret_req": "Gizli Bilgi Talebi", "secret_req_desc": "Banka asla SMS kodu veya şifre istemez.",
        "no_msg_threat": "Tehdit Bulunamadı", "no_msg_threat_desc": "Şüpheli ifade tespit edilmedi.",
        "card_len": "Eksik Numara", "card_len_desc": "13-19 haneli bir kart numarası girin.",
        "card_note": "Not", "card_note_desc": "Kart numarası güvenlik nedeniyle saklanmaz.",
        "bad_ext": "Tehlikeli uzantı: .{}", "bad_ext_desc": "Çalıştırılabilir veya riskli dosya türü.",
        "perm_warn": "İzin: {}", "perm_warn_desc": "Kötü amaçlı APK dosyalarında suistimal edilir.",
        "file_clean": "Dosya temiz görünüyor", "file_clean_desc": "Zararlı imza tespit edilmedi.",
        "ip_host": "IP adresi", "ip_host_desc": "Bağlantı alan adı yerine doğrudan IP adresine gidiyor.",
        "punycode": "Punycode (xn--)", "punycode_desc": "Benzer karakterli sahte alan adı olabilir.",
        "at_sign": "'@' işareti", "at_sign_desc": "Gerçek adres '@' işaretinden sonra gizlenmiş olabilir.",
        "many_sub": "Çok sayıda alt alan adı", "many_sub_desc": "Uzun alt alan adı zinciri dolandırıcılıkta yaygındır.",
        "bad_tld": "Şüpheli alan uzantısı", "bad_tld_desc": "Bu uzantılar oltalamada sık kullanılır.",
        "shortener": "Kısaltılmış bağlantı", "shortener_desc": "Gerçek adres gizli; açmadan önce kontrol edin.",
        "card_luhn": "Luhn kontrolü başarısız", "card_luhn_desc": "Numarada hata var veya kart sahte.",
        "dbl_ext": "Çift uzantı", "dbl_ext_desc": "Dosya zararsız gibi gösteriliyor.",
        "disguised": "Gizlenmiş çalıştırılabilir dosya", "disguised_desc": "İçinde .exe/ELF imzası var ama uzantı farklı.",
        "voice_demo": "Demo modu", "voice_demo_desc": "Deepfake tespit modeli bağlı değil; sonuç güvenilir değil.",
        "prize": "Ödül vaadi", "prize_desc": "Sahte ödüller genellikle veri toplamak için kullanılır.",
        "acc_threat": "Hesap bloklama tehdidi", "acc_threat_desc": "Korkutarak bilgi istemek yaygın bir yöntemdir.",
        "rate_limit": "Çok fazla istek. Lütfen biraz sonra deneyin.", "too_big": "Dosya çok büyük (en fazla 20 MB).",
        "no_file": "Dosya seçilmedi.", "bad_msgs": "Mesaj biçimi geçersiz.",
        "ai_off": "AI anahtarı ayarlanmamış.", "ai_err": "AI hatası, lütfen sonra deneyin."
    }
}

def tr(lang):
    return {**TEXTS["en"], **TEXTS.get(lang, {})}

# ------------------------------------------------------------------ Yordamchi ma'lumotlar
# brend -> rasmiy domenlar (birinchisi xabarda ko'rsatiladi)
BRANDS = {
    "payme": ("payme.uz",), "click": ("click.uz",), "uzcard": ("uzcard.uz",), "humo": ("humo.uz",),
    "telegram": ("telegram.org", "t.me", "telegram.me"),
    "google": ("google.com", "google.ru", "google.co.uk", "google.uz"),
    "uzum": ("uzum.uz", "uzum.com"),
}
BRAND_SUFFIX = {"uz", "login", "secure", "pay", "verify", "bank", "support", "online", "app", "web", "help", "id"}
HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "$": "s"})
SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "goo.gl", "ow.ly", "rebrand.ly", "shorturl.at"}
BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "rest", "work", "zip", "mov"}
EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk"}
EXEC_EXT = {"exe", "dll", "scr", "sys", "bin", "so", "elf", "com"}
PERM = {"SEND_SMS": 20, "READ_SMS": 20, "RECEIVE_SMS": 15, "BIND_ACCESSIBILITY_SERVICE": 25,
        "REQUEST_INSTALL_PACKAGES": 15, "SYSTEM_ALERT_WINDOW": 15}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|mp3|mp4)\.(exe|scr|bat|cmd|js|vbs|jar|msi|apk)$", re.I)

URG_RE = re.compile(r"\b(hozir|zudlik|tezda|darhol|срочно|немедленно|urgent|immediately|asap)\b|24\s*(soat|час|hours?)", re.I)
SECRET_RE = re.compile(r"\b(kod|parol|otp|cvv|cvc|код|пароль|password)(?:i|ni|ini|ingiz|ingizni|lar|larni|а|ы|у)?\b|\bpin\b|karta\s*raqam\w*|номер\s+карты|card\s+number", re.I)
PRIZE_RE = re.compile(r"\b(yutuq|yutdingiz|sovrin|tabriklaymiz|приз|выиграл\w*|congratulations|you won|winner)\b", re.I)
BLOCK_RE = re.compile(r"(bloklan|блокиров|заблокирован|suspended|deactivat|account.{0,15}blocked)", re.I)
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:uz|com|org|net|ru|xyz|top|click|tk|ly|me|io)\b(?:/[^\s<>\"']*)?",
    re.I)

# ------------------------------------------------------------------ Umumiy funksiyalar
def get_lang():
    j = request.get_json(silent=True)
    l = (j.get("lang") if isinstance(j, dict) else None) or request.form.get("lang") or request.args.get("lang")
    return l if l in TEXTS else "uz"

def out(kind, preview, score, reasons, lang="uz", extra=None):
    score = max(0, min(100, int(score)))
    lv = "low" if score < 30 else "mid" if score < 60 else "high"
    t = tr(lang)
    safe_reasons = [{"t": str(rt)[:160], "why": str(rw)[:500]} for rt, rw in reasons]
    try:
        save_scan(kind, preview, score, lv, safe_reasons)
    except Exception:
        app.logger.exception("save_scan failed")
    return jsonify(score=score, level=lv, label=t[lv], advice=t[f"adv_{lv}"],
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

def within_one_edit(a, b):
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i + 1:] == b[i + 1:] if len(a) == len(b) else a[i:] == b[i + 1:]

def official(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)

def brand_hit(host):
    tokens = [x.translate(HOMO) for x in re.split(r"[.\-_]", host) if x]
    for b, domains in BRANDS.items():
        if official(host, domains):
            continue
        for tok in tokens:
            if tok == b:
                return b, domains[0]
            if len(b) >= 5 and (within_one_edit(tok, b) or (tok.startswith(b) and tok[len(b):] in BRAND_SUFFIX)):
                return b, domains[0]
    return None

def analyze_url(raw, t):
    """URL ni tahlil qiladi -> (ball, [(sarlavha, izoh), ...])."""
    raw = (raw or "").strip()
    bad = (40, [(t["invalid_url"], t["invalid_url_desc"])])
    if not raw or re.search(r"\s", raw):
        return bad
    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    try:
        u = urlparse(raw if has_scheme else "https://" + raw)
        host = (u.hostname or "").lower().rstrip(".")
        u.port  # noto'g'ri port bo'lsa ValueError beradi
    except ValueError:
        return bad
    if u.scheme not in ("http", "https") or not host:
        return bad

    s, r = 0, []
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        s += 35; r.append((t["ip_host"], t["ip_host_desc"]))
    elif "." not in host:
        return bad

    if has_scheme and u.scheme == "http":
        s += 15; r.append((t["no_https"], t["no_https_desc"]))
    if u.username is not None:
        s += 30; r.append((t["at_sign"], t["at_sign_desc"]))

    if not is_ip:
        labels = host.split(".")
        if any(l.startswith("xn--") for l in labels) or not host.isascii():
            s += 30; r.append((t["punycode"], t["punycode_desc"]))
        if len(labels) > 4:
            s += 15; r.append((t["many_sub"], t["many_sub_desc"]))
        if labels[-1] in BAD_TLDS:
            s += 15; r.append((t["bad_tld"], t["bad_tld_desc"]))
        if host in SHORTENERS:
            s += 20; r.append((t["shortener"], t["shortener_desc"]))
        hit = brand_hit(host)
        if hit:
            s += 40; r.append((t["imitation"].format(hit[0]), t["imitation_desc"].format(hit[1])))
    return s, r

# ------------------------------------------------------------------ API
@app.post("/api/url")
def api_url():
    lang = get_lang(); t = tr(lang)
    raw = txt(500).strip()
    s, r = analyze_url(raw, t)
    return out("URL", raw, s, r or [(t["safe"], t["safe_desc"])], lang)

@app.post("/api/message")
def api_msg():
    lang = get_lang(); t = tr(lang)
    raw = txt(3000); s, r = 0, []
    if URG_RE.search(raw):
        s += 25; r.append((t["urgency"], t["urgency_desc"]))
    if SECRET_RE.search(raw):
        s += 40; r.append((t["secret_req"], t["secret_req_desc"]))
    if PRIZE_RE.search(raw):
        s += 20; r.append((t["prize"], t["prize_desc"]))
    if BLOCK_RE.search(raw):
        s += 20; r.append((t["acc_threat"], t["acc_threat_desc"]))
    # xabar ichidagi havolalarni ham tekshiramiz
    urls = []
    for m in URL_RE.findall(raw):
        m = m.rstrip(".,;:!?)")
        if m and m not in urls:
            urls.append(m)
    for url in urls[:3]:
        us, ur = analyze_url(url, t)
        if us:
            s += min(us, 50)
            r.extend(x for x in ur if x not in r)
    return out("Xabar", raw, s, r or [(t["no_msg_threat"], t["no_msg_threat_desc"])], lang)

@app.post("/api/card")
def api_card():
    lang = get_lang(); t = tr(lang)
    n = re.sub(r"\D", "", txt(200))[:19]; s, r = 0, []
    if len(n) < 13:
        return out("Karta", None, 0, [(t["card_len"], t["card_len_desc"])], lang)
    if n.startswith("8600"): brand = "Uzcard"
    elif n.startswith("9860"): brand = "Humo"
    elif n[0] == "4": brand = "Visa"
    elif n[:2] in {"51", "52", "53", "54", "55"} or 2221 <= int(n[:4]) <= 2720: brand = "Mastercard"
    else: brand = "Unknown"
    if not luhn(n):
        s += 30; r.append((t["card_luhn"], t["card_luhn_desc"]))
    r.append((t["card_note"], t["card_note_desc"]))
    return out("Karta", None, s, r, lang, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

@app.post("/api/file")
def api_file():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("file")
    if not f:
        return jsonify(error=t["no_file"]), 400
    b = f.read(); name = os.path.basename(f.filename or "file")[:120]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "name": name}
    if ext in EXT_BAD:
        s += 30; r.append((t["bad_ext"].format(ext), t["bad_ext_desc"]))
    if DOUBLE_EXT.search(name):
        s += 30; r.append((t["dbl_ext"], t["dbl_ext_desc"]))
    if ext not in EXEC_EXT and b.startswith((b"MZ", b"\x7fELF")):
        s += 40; r.append((t["disguised"], t["disguised_desc"]))
    if b[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                if "AndroidManifest.xml" in z.namelist() and z.getinfo("AndroidManifest.xml").file_size <= 5_000_000:
                    m = z.read("AndroidManifest.xml")
                    blob = m.decode("utf-16le", "ignore") + m[1:].decode("utf-16le", "ignore") + m.decode("latin-1")
                    found = sorted(p for p in PERM if p in blob)
                    for p in found:
                        s += PERM[p]; r.append((t["perm_warn"].format(p), t["perm_warn_desc"]))
                    ex["permissions"] = found
        except (zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError):
            pass
    return out("Fayl", name, s, r or [(t["file_clean"], t["file_clean_desc"])], lang, ex)

@app.post("/api/voice")
def api_voice():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("audio")
    if not f:
        return jsonify(error=t["no_file"]), 400
    b = f.read(); name = os.path.basename(f.filename or "audio")[:120]
    ex = {"demo": True, "name": name, "size": len(b)}
    try:
        with wave.open(io.BytesIO(b)) as w:
            ex["duration"] = round(w.getnframes() / w.getframerate(), 1)
    except (wave.Error, EOFError, ZeroDivisionError):
        pass
    # Haqiqiy model ulanmaguncha soxta "xavfsiz" natija bermaymiz
    return out("Ovoz", name, 0, [(t["voice_demo"], t["voice_demo_desc"])], lang, ex)

@app.get("/api/news")
def api_news():
    # Namuna ma'lumot. Haqiqiy manba (RSS / JSON fayl) ulash mumkin.
    return jsonify([
        {"date": "2026-10-24", "title": "OpenSSL Critical Vulnerability", "category": "Cybersecurity",
         "content": "Network administrators must patch systems immediately."},
        {"date": "2026-10-23", "title": "Python 3.15 Released", "category": "Programming",
         "content": "New JIT compiler improvements and memory optimizations added."}
    ])

@app.get("/api/stats")
def api_stats():
    lang = get_lang(); t = tr(lang)
    now = datetime.now(timezone.utc)
    days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        lv = {row["level"]: row["c"] for row in con.execute("SELECT level, COUNT(*) AS c FROM scans GROUP BY level")}
        kinds = [{"kind": row["kind"], "count": row["c"]} for row in
                 con.execute("SELECT kind, COUNT(*) AS c FROM scans GROUP BY kind ORDER BY c DESC")]
        cnt = {row["d"]: row["c"] for row in con.execute(
            "SELECT substr(created_at,1,10) AS d, COUNT(*) AS c FROM scans WHERE created_at >= ? GROUP BY d", (days[0],))}
    return jsonify(
        total=total,
        levels=[{"level": k, "label": t[k], "count": lv.get(k, 0)} for k in ("low", "mid", "high")],
        kinds=kinds,
        daily=[{"date": d[5:], "count": cnt.get(d, 0)} for d in days])

SYSTEM_PROMPT = ("You are the PhishGuard AI Advisor. Answer only questions about cybersecurity, phishing, scams, "
                 "online safety and programming; politely decline other topics. Be concise (under 150 words). "
                 "Reply in the language the user writes in; if unclear, use Uzbek (Latin script). "
                 "Never ask users to share passwords, OTP codes or card numbers.")

def clean_messages(ms):
    if not isinstance(ms, list):
        return None
    res = []
    for m in ms[-10:]:
        if not isinstance(m, dict) or m.get("role") not in ("user", "assistant"):
            return None
        c = m.get("content")
        if not isinstance(c, str) or not c.strip():
            return None
        res.append({"role": m["role"], "content": c[:2000]})
    while res and res[0]["role"] == "assistant":
        res.pop(0)
    return res if res and res[-1]["role"] == "user" else None

@app.post("/api/chat")
def api_chat():
    lang = get_lang(); t = tr(lang)
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return jsonify(error=t["ai_off"]), 503
    j = request.get_json(silent=True)
    ms = clean_messages(j.get("messages") if isinstance(j, dict) else None)
    if not ms:
        return jsonify(error=t["bad_msgs"]), 400
    body = json.dumps({"model": MODEL, "max_tokens": 500,
                       "system": SYSTEM_PROMPT + f" UI language code: {lang}.", "messages": ms}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body,
                                 {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.load(resp)
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text").strip()
        return jsonify(text=text)
    except Exception:
        app.logger.exception("chat failed")
        return jsonify(error=t["ai_err"]), 502


# ------------------------------------------------------------------ Frontend (bitta fayl ichida)
# CSS va JS alohida URL'lardan beriladi, shuning uchun CSP'da 'unsafe-inline' kerak emas.
INDEX_HTML = r'''<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="description" content="PhishGuard Pro AI: fishing, zararli fayl va firibgarlikni aniqlash">
<title>PhishGuard Pro AI</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ctext y='13' font-size='13'%3E%F0%9F%9B%A1%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<header>
  <div class="brand"><i class="dot"></i><span id="header-title">PhishGuard Pro AI</span></div>
  <div class="ctl">
    <button class="icon-btn" id="themeBtn" type="button" aria-label="Theme">🌓</button>
    <select class="lang-select" id="langSelect" aria-label="Language">
      <option value="uz">🇺🇿 O'zbek</option>
      <option value="kr">🇺🇿 Ўзбек</option>
      <option value="ru">🇷🇺 Русский</option>
      <option value="en">🇬🇧 English</option>
      <option value="tr">🇹🇷 Türkçe</option>
    </select>
  </div>
</header>
<main>
  <div class="nav-tabs" id="tabs" role="tablist"></div>
  <div class="card" id="panel" role="tabpanel">
    <h2 id="card-title"></h2>
    <p id="card-desc" class="muted"></p>
    <div id="inp-area"></div>
  </div>
  <div id="out" aria-live="polite"></div>
</main>
<div id="toast" class="toast" role="status"></div>
<noscript><p class="noscript">JavaScript is required.</p></noscript>
<script src="/static/i18n.js"></script>
<script src="/static/app.js"></script>
</body>
</html>
'''

APP_CSS = r''':root{--bg:#f8fafc;--card:#fff;--soft:#f1f5f9;--bd:#e2e8f0;--tx:#1e293b;--mu:#64748b;--ac:#2563eb;--ac2:#1d4ed8;--low:#10b981;--mid:#f59e0b;--high:#ef4444;--shadow:0 4px 6px -1px rgba(0,0,0,.05)}
[data-theme=dark]{--bg:#0b1220;--card:#131c2e;--soft:#1a2540;--bd:#25314a;--tx:#e5e9f2;--mu:#94a3b8;--ac:#3b82f6;--ac2:#2563eb;--shadow:none}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding-bottom:70px}
:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
header{background:var(--card);border-bottom:1px solid var(--bd);padding:12px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;min-width:0}
.brand span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dot{width:10px;height:10px;background:var(--ac);border-radius:50%;box-shadow:0 0 8px var(--ac);flex:none}
.ctl{display:flex;gap:8px;align-items:center}
.lang-select,.icon-btn{border:1px solid var(--bd);background:var(--card);color:var(--tx);padding:6px 12px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
main{max-width:850px;margin:24px auto;padding:0 16px}
.nav-tabs{display:flex;gap:6px;background:var(--card);padding:8px;border:1px solid var(--bd);border-radius:12px;margin-bottom:20px;overflow-x:auto}
.nav-tabs button{flex:1;background:transparent;border:0;padding:10px 14px;font:inherit;font-weight:600;color:var(--mu);cursor:pointer;border-radius:8px;white-space:nowrap;transition:.2s}
.nav-tabs button:hover{background:var(--soft)}
.nav-tabs button.on{background:var(--ac);color:#fff;box-shadow:0 4px 12px rgba(37,99,235,.25)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:24px;box-shadow:var(--shadow);margin-bottom:20px}
h2{margin:0 0 6px;font-size:18px}
p{margin:4px 0 14px}.muted{color:var(--mu);font-size:13px}
textarea,input[type=text]{width:100%;border:1px solid var(--bd);border-radius:10px;padding:12px;font:inherit;color:var(--tx);background:var(--soft);margin-bottom:12px}
textarea:focus,input:focus{border-color:var(--ac);outline:none}
textarea{min-height:100px;resize:vertical}
.row{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--ac);color:#fff;border:0;border-radius:10px;padding:12px 24px;font:inherit;font-weight:600;cursor:pointer;transition:.2s}
.btn:hover{background:var(--ac2)}.btn:disabled{opacity:.6;cursor:wait}
.btn.ghost{background:transparent;color:var(--ac);border:1px solid var(--bd)}
.btn.ghost:hover{background:var(--soft)}
.drop{display:flex;flex-direction:column;align-items:center;gap:6px;border:2px dashed var(--bd);border-radius:12px;padding:28px 16px;text-align:center;color:var(--mu);cursor:pointer;margin-bottom:12px;transition:.2s}
.drop.over,.drop:focus-within,.drop:hover{border-color:var(--ac);background:var(--soft)}
.drop b{color:var(--tx);word-break:break-all}
.res{border-width:1px}
.res.low{border-color:var(--low);background:rgba(16,185,129,.06)}
.res.mid{border-color:var(--mid);background:rgba(245,158,11,.06)}
.res.high{border-color:var(--high);background:rgba(239,68,68,.06)}
.res.demo{border-color:#94a3b8;background:var(--soft)}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:700;font-size:12px;margin:0 6px 8px 0;color:#fff}
.badge.low{background:var(--low)}.badge.mid{background:var(--mid)}.badge.high{background:var(--high)}.badge.demo{background:#64748b}
.meter{height:10px;background:var(--bd);border-radius:6px;overflow:hidden;margin:4px 0 12px}
.fill{height:100%;width:0;border-radius:6px;transition:width .6s ease}
.low .fill{background:var(--low)}.mid .fill{background:var(--mid)}.high .fill{background:var(--high)}
ul{margin:8px 0 14px 20px;padding:0}li{margin-bottom:6px;font-size:13px}
code{font-size:12px}a{color:var(--ac)}
.chatlog{max-height:300px;overflow-y:auto;margin-bottom:12px;background:var(--soft);padding:12px;border-radius:10px}
.msg{margin-bottom:8px;white-space:pre-wrap;word-break:break-word}
.msg.err{color:var(--high)}
.news{border-bottom:1px solid var(--bd);padding-bottom:8px;margin-bottom:8px}
.news small{font-size:11px;color:var(--ac);font-weight:600}.news b{display:block;font-size:15px}
.bar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:12px}
.bar .lbl{width:44px;color:var(--mu)}.bar .track{flex:1;height:12px;background:var(--soft);border-radius:6px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--ac);border-radius:6px;transition:width .6s}
.spin{width:16px;height:16px;border:2px solid var(--bd);border-top-color:var(--ac);border-radius:50%;display:inline-block;animation:sp .8s linear infinite;vertical-align:-3px;margin-right:8px}
@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,20px);background:var(--tx);color:var(--bg);padding:8px 16px;border-radius:20px;opacity:0;pointer-events:none;transition:.25s;font-weight:600}
.toast.show{opacity:1;transform:translate(-50%,0)}
.noscript{text-align:center;color:var(--high)}
@media(max-width:560px){header{padding:10px 12px}.card{padding:16px}.btn{width:100%}.nav-tabs button{flex:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
'''

I18N_JS = r'''"use strict";
const UI={
  uz:{brand:"PhishGuard Pro AI Ekotizimi",check:"Tekshirish",upload:"Yuklab Tahlil Qilish",send:"Yuborish",analyzing:"Tahlil qilinmoqda...",
    url_t:"🔗 URL Scanner",url_d:"Havolani xavfsizlik va fishing alomatlariga tekshirish",
    message_t:"💬 MessageGuard",message_d:"SMS yoki chat matnidagi shubhali iboralar va havolalarni aniqlash",
    card_t:"💳 CardGuard",card_d:"Bank kartasi raqamini xavfsiz tekshirish (saqlanmaydi)",
    file_t:"📁 FileGuard & APK Shield",file_d:"Fayl yoki APK ilova xavfsizligini tekshirish",
    voice_t:"🎙 VoiceGuard",voice_d:"Ovozli xabar yoki audio fayl tahlili (demo)",
    chat_t:"🤖 AI Maslahatchi",chat_d:"Kiberxavfsizlik va dasturlash bo'yicha savol bering",
    news_t:"📰 Yangiliklar",news_d:"Kiberxavfsizlik va IT sohasidagi so'nggi yangiliklar",
    stats_t:"📊 Statistika",stats_d:"Barcha tekshiruvlar statistikasi (shaxsiy ma'lumotsiz)",
    ph_url:"https://example.com",ph_message:"SMS yoki xabar matnini shu yerga qo'ying...",ph_card:"Karta raqami (13-19 xona)",ph_chat:"Savolingizni yozing...",
    demo_label:"DEMO - natija ishonchli emas",total:"Jami tekshiruvlar",last7:"So'nggi 7 kun"},
  kr:{brand:"PhishGuard Pro AI Экотизими",check:"Текшириш",upload:"Юклаб Таҳлил Қилиш",send:"Юбориш",analyzing:"Таҳлил қилинмоқда...",
    url_t:"🔗 URL Scanner",url_d:"Ҳаволани хавфсизлик ва фишинг аломатларига текшириш",
    message_t:"💬 MessageGuard",message_d:"SMS ёки чат матнидаги шубҳали ибора ва ҳаволаларни аниқлаш",
    card_t:"💳 CardGuard",card_d:"Банк картаси рақамини хавфсиз текшириш (сақланмайди)",
    file_t:"📁 FileGuard & APK Shield",file_d:"Файл ёки APK илова хавфсизлигини текшириш",
    voice_t:"🎙 VoiceGuard",voice_d:"Овозли хабар ёки аудио файл таҳлили (демо)",
    chat_t:"🤖 AI Маслаҳатчи",chat_d:"Киберхавфсизлик ва дастурлаш бўйича савол беринг",
    news_t:"📰 Янгиликлар",news_d:"Киберхавфсизлик ва ИТ соҳасидаги сўнгги янгиликлар",
    stats_t:"📊 Статистика",stats_d:"Барча текширувлар статистикаси (шахсий маълумотсиз)",
    ph_url:"https://example.com",ph_message:"SMS ёки хабар матнини шу ерга қўйинг...",ph_card:"Карта рақами (13-19 хона)",ph_chat:"Саволингизни ёзинг...",
    demo_label:"ДЕМО - натижа ишончли эмас",total:"Жами текширувлар",last7:"Сўнгги 7 кун"},
  ru:{brand:"Экосистема PhishGuard Pro AI",check:"Проверить",upload:"Загрузить и Анализировать",send:"Отправить",analyzing:"Анализируется...",
    url_t:"🔗 URL Scanner",url_d:"Проверка ссылки на безопасность и признаки фишинга",
    message_t:"💬 MessageGuard",message_d:"Поиск подозрительных фраз и ссылок в SMS или чате",
    card_t:"💳 CardGuard",card_d:"Безопасная проверка номера карты (не сохраняется)",
    file_t:"📁 FileGuard & APK Shield",file_d:"Проверка безопасности файлов и APK приложений",
    voice_t:"🎙 VoiceGuard",voice_d:"Анализ голосовых сообщений и аудиофайлов (демо)",
    chat_t:"🤖 AI Консультант",chat_d:"Задайте вопрос по кибербезопасности и программированию",
    news_t:"📰 Новости",news_d:"Последние новости в сфере ИТ и кибербезопасности",
    stats_t:"📊 Статистика",stats_d:"Статистика всех проверок (без личных данных)",
    ph_url:"https://example.com",ph_message:"Вставьте текст SMS или сообщения...",ph_card:"Номер карты (13-19 цифр)",ph_chat:"Напишите ваш вопрос...",
    demo_label:"ДЕМО - результат недостоверен",total:"Всего проверок",last7:"Последние 7 дней"},
  en:{brand:"PhishGuard Pro AI Ecosystem",check:"Check",upload:"Upload & Analyze",send:"Send",analyzing:"Analyzing...",
    url_t:"🔗 URL Scanner",url_d:"Scan link for safety and phishing indicators",
    message_t:"💬 MessageGuard",message_d:"Detect suspicious phrases and links in SMS or chats",
    card_t:"💳 CardGuard",card_d:"Safe card number validation (never stored)",
    file_t:"📁 FileGuard & APK Shield",file_d:"Analyze file and APK application security",
    voice_t:"🎙 VoiceGuard",voice_d:"Voice message and audio analysis (demo)",
    chat_t:"🤖 AI Consultant",chat_d:"Ask questions regarding cybersecurity and dev",
    news_t:"📰 News",news_d:"Latest news in IT and cybersecurity domain",
    stats_t:"📊 Statistics",stats_d:"Statistics of all scans (no personal data)",
    ph_url:"https://example.com",ph_message:"Paste the SMS or message text here...",ph_card:"Card number (13-19 digits)",ph_chat:"Type your question...",
    demo_label:"DEMO - result is not reliable",total:"Total scans",last7:"Last 7 days"},
  tr:{brand:"PhishGuard Pro AI Ekosistemi",check:"Kontrol Et",upload:"Yükle ve Analiz Et",send:"Gönder",analyzing:"Analiz ediliyor...",
    url_t:"🔗 URL Scanner",url_d:"Bağlantıyı güvenlik ve oltalama belirtilerine karşı tara",
    message_t:"💬 MessageGuard",message_d:"SMS veya sohbetteki şüpheli ifade ve bağlantıları tespit et",
    card_t:"💳 CardGuard",card_d:"Güvenli kart numarası doğrulaması (saklanmaz)",
    file_t:"📁 FileGuard & APK Shield",file_d:"Dosya ve APK uygulama güvenliğini analiz et",
    voice_t:"🎙 VoiceGuard",voice_d:"Sesli mesaj ve ses dosyası analizi (demo)",
    chat_t:"🤖 AI Danışman",chat_d:"Siber güvenlik ve yazılım hakkında soru sorun",
    news_t:"📰 Haberler",news_d:"BT ve siber güvenlik alanındaki son haberler",
    stats_t:"📊 İstatistik",stats_d:"Tüm taramaların istatistiği (kişisel veri yok)",
    ph_url:"https://example.com",ph_message:"SMS veya mesaj metnini buraya yapıştırın...",ph_card:"Kart numarası (13-19 hane)",ph_chat:"Sorunuzu yazın...",
    demo_label:"DEMO - sonuç güvenilir değil",total:"Toplam tarama",last7:"Son 7 gün"}
};

Object.assign(UI.uz,{err_net:"Tarmoq xatosi. Ulanishni tekshiring.",err_big:"Fayl juda katta (maks. 20 MB).",copy:"📋 Hisobotni nusxalash",copied:"Nusxalandi!",clear:"Tozalash",example:"Namuna",ex_url:"http://payme-uz-login.xyz/verify",ex_message:"Hurmatli mijoz! Kartangiz bloklandi. Hozir SMS kodni yuboring: https://payme-login.top",drop:"Faylni shu yerga tashlang yoki tanlang"});
Object.assign(UI.kr,{err_net:"Тармоқ хатоси. Уланишни текширинг.",err_big:"Файл жуда катта (макс. 20 MB).",copy:"📋 Ҳисоботни нусхалаш",copied:"Нусхаланди!",clear:"Тозалаш",example:"Намуна",ex_url:"http://payme-uz-login.xyz/verify",ex_message:"Ҳурматли мижоз! Картангиз блокланди. Ҳозир SMS кодни юборинг: https://payme-login.top",drop:"Файлни шу ерга ташланг ёки танланг"});
Object.assign(UI.ru,{err_net:"Ошибка сети. Проверьте соединение.",err_big:"Файл слишком большой (макс. 20 МБ).",copy:"📋 Копировать отчёт",copied:"Скопировано!",clear:"Очистить",example:"Пример",ex_url:"http://payme-uz-login.xyz/verify",ex_message:"Уважаемый клиент! Ваша карта заблокирована. Срочно отправьте код из SMS: https://payme-login.top",drop:"Перетащите файл сюда или выберите"});
Object.assign(UI.en,{err_net:"Network error. Check your connection.",err_big:"File too large (max 20 MB).",copy:"📋 Copy report",copied:"Copied!",clear:"Clear",example:"Example",ex_url:"http://payme-uz-login.xyz/verify",ex_message:"Dear customer! Your card is blocked. Send the SMS code immediately: https://payme-login.top",drop:"Drop a file here or choose one"});
Object.assign(UI.tr,{err_net:"Ağ hatası. Bağlantınızı kontrol edin.",err_big:"Dosya çok büyük (en fazla 20 MB).",copy:"📋 Raporu kopyala",copied:"Kopyalandı!",clear:"Temizle",example:"Örnek",ex_url:"http://payme-uz-login.xyz/verify",ex_message:"Sayın müşteri! Kartınız bloke edildi. SMS kodunu hemen gönderin: https://payme-login.top",drop:"Dosyayı buraya bırakın veya seçin"});
'''

APP_JS = r'''"use strict";
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const store = {
  get(k, d) { try { return localStorage.getItem(k) || d } catch { return d } },
  set(k, v) { try { localStorage.setItem(k, v) } catch {} }
};
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const MAX_FILE = 20 * 1024 * 1024;
const MODES = ["url", "message", "card", "file", "voice", "chat", "news", "stats"];

let lang = store.get("pg_lang", "uz"); if (!UI[lang]) lang = "uz";
let cur = "url", CH = [], CLOG = [], waiting = false, last = null, toastTimer;
const T = () => ({ ...UI.en, ...UI[lang] });

/* ---------- theme ---------- */
function applyTheme(th) { document.documentElement.dataset.theme = th; store.set("pg_theme", th) }
applyTheme(store.get("pg_theme", matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
$("#themeBtn").onclick = () => applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");

/* ---------- helpers ---------- */
async function api(path, opts = {}) {
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 40000);
  try {
    const r = await fetch(path, { ...opts, signal: ctl.signal });
    try { return await r.json() } catch { return { error: "HTTP " + r.status } }
  } catch { return { error: T().err_net } }
  finally { clearTimeout(to) }
}
function toast(m) {
  const el = $("#toast"); el.textContent = m; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 1600);
}
// CSP inline style'ga ruxsat bermaydi, shuning uchun kenglik CSSOM orqali beriladi
function applyWidths() { $$("[data-w]").forEach(el => { el.style.width = el.dataset.w + "%" }) }
function busy(on) { const b = $("#go"); if (b) b.disabled = on }
const loading = () => { $("#out").innerHTML = `<div class="card"><span class="spin"></span>${esc(T().analyzing)}</div>` };

/* ---------- UI ---------- */
$("#langSelect").value = lang;
$("#langSelect").onchange = e => { lang = e.target.value; store.set("pg_lang", lang); updateUI() };

function updateUI() {
  document.documentElement.lang = lang === "kr" ? "uz-Cyrl" : lang;
  $("#header-title").textContent = T().brand;
  $("#themeBtn").setAttribute("aria-label", T().theme || "Theme");
  setMode(cur);
}
function renderTabs() {
  const t = T();
  $("#tabs").innerHTML = MODES.map(k =>
    `<button role="tab" aria-selected="${k === cur}" tabindex="${k === cur ? 0 : -1}" class="${k === cur ? "on" : ""}" data-m="${k}">${esc(t[k + "_t"])}</button>`).join("");
  $$("#tabs button").forEach(b => b.onclick = () => setMode(b.dataset.m));
}
$("#tabs").addEventListener("keydown", e => {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
  const i = MODES.indexOf(cur) + (e.key === "ArrowRight" ? 1 : -1);
  setMode(MODES[(i + MODES.length) % MODES.length]);
  $("#tabs .on").focus();
});

function setMode(m) {
  cur = m; last = null;
  const t = T(), A = $("#inp-area");
  renderTabs();
  $("#card-title").textContent = t[m + "_t"];
  $("#card-desc").textContent = t[m + "_d"];
  $("#out").innerHTML = "";

  if (m === "news") { A.innerHTML = ""; return loadNews() }
  if (m === "stats") { A.innerHTML = ""; return loadStats() }

  if (m === "chat") {
    A.innerHTML = `<div id="cl" class="chatlog" aria-live="polite"></div>
      <label class="sr" for="ci">${esc(t.chat_t)}</label>
      <textarea id="ci" placeholder="${esc(t.ph_chat)}"></textarea>
      <div class="row"><button class="btn" id="cb" type="button">${esc(t.send)}</button>
      <button class="btn ghost" id="cc" type="button">${esc(t.clear)}</button></div>`;
    drawChat();
    $("#cb").onclick = () => sendChat($("#ci").value);
    $("#cc").onclick = () => { CH = []; CLOG = []; drawChat() };
    $("#ci").onkeydown = e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) sendChat($("#ci").value) };
    return;
  }

  if (m === "file" || m === "voice") {
    A.innerHTML = `<label class="drop" id="drop"><span>${esc(t.drop)}</span><b id="fname"></b>
      <input type="file" id="f" class="sr" accept="${m === "file" ? "*/*" : "audio/*"}"></label>
      <div class="row"><button class="btn" id="go" type="button">${esc(t.upload)}</button></div>`;
    const dz = $("#drop"), showName = () => { $("#fname").textContent = $("#f").files[0]?.name || "" };
    ["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("over") }));
    ["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("over") }));
    dz.addEventListener("drop", e => { if (e.dataTransfer.files.length) { $("#f").files = e.dataTransfer.files; showName() } });
    $("#f").onchange = showName;
    $("#go").onclick = () => fileScan($("#f").files[0], m);
    return;
  }

  const line = m === "url" || m === "card";
  const field = line
    ? `<input type="text" id="t" placeholder="${esc(t["ph_" + m])}" autocomplete="off" spellcheck="false" ${m === "card" ? 'inputmode="numeric"' : ""}>`
    : `<textarea id="t" placeholder="${esc(t.ph_message)}"></textarea>`;
  const ex = (m === "url" || m === "message") ? `<button class="btn ghost" id="ex" type="button">${esc(t.example)}</button>` : "";
  A.innerHTML = `<label class="sr" for="t">${esc(t[m + "_t"])}</label>${field}
    <div class="row"><button class="btn" id="go" type="button">${esc(t.check)}</button>${ex}</div>`;
  $("#go").onclick = () => runScan(m, $("#t").value);
  $("#t").onkeydown = e => { if (e.key === "Enter" && (line || e.ctrlKey)) runScan(m, $("#t").value) };
  if (ex) $("#ex").onclick = () => { $("#t").value = t["ex_" + m]; runScan(m, $("#t").value) };
}

/* ---------- scans ---------- */
async function runScan(m, v) {
  if (!v.trim()) return;
  loading(); busy(true);
  const res = await api("/api/" + m, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: v, lang }) });
  busy(false); renderResult(res);
}
async function fileScan(file, m) {
  if (!file) return;
  if (file.size > MAX_FILE) return renderResult({ error: T().err_big });
  const fd = new FormData();
  fd.append(m === "file" ? "file" : "audio", file); fd.append("lang", lang);
  loading(); busy(true);
  const res = await api("/api/" + m, { method: "POST", body: fd });
  busy(false); renderResult(res);
}

function renderResult(r) {
  const t = T();
  if (r.error) { $("#out").innerHTML = `<div class="card msg err">${esc(r.error)}</div>`; return }
  last = r;
  const demo = !!r.demo, lv = demo ? "demo" : r.level, score = Number(r.score) || 0;
  let extra = "";
  if (r.masked) extra += `<p><b>Brand:</b> ${esc(r.brand)} | ${esc(r.masked)}</p>`;
  if (r.name) extra += `<p><b>${esc(r.name)}</b>${r.size != null ? ` - ${(r.size / 1024).toFixed(1)} KB` : ""}${r.duration ? ` - ${esc(r.duration)} s` : ""}</p>`;
  if (r.sha256) extra += `<p><b>SHA-256:</b> <code>${esc(r.sha256)}</code><br><a href="https://www.virustotal.com/gui/file/${encodeURIComponent(r.sha256)}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a></p>`;
  const reasons = (r.reasons || []).map(x => `<li><b>${esc(x.t)}:</b> ${esc(x.why)}</li>`).join("");
  const head = demo
    ? `<span class="badge demo">${esc(t.demo_label)}</span>`
    : `<span class="badge ${lv}">${esc(r.label)} (${score}/100)</span>
       <div class="meter" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${score}"><div class="fill" data-w="${score}"></div></div>
       <p>ℹ️ ${esc(r.advice)}</p>`;
  $("#out").innerHTML = `<section class="card res ${lv}">${head}${extra}<ul>${reasons}</ul>
    <button class="btn ghost" id="cp" type="button">${esc(t.copy)}</button></section>`;
  $("#cp").onclick = copyReport;
  applyWidths();
}
async function copyReport() {
  if (!last) return;
  const lines = [`${last.label} (${last.score}/100)`, last.advice, ...(last.reasons || []).map(x => `- ${x.t}: ${x.why}`)];
  try { await navigator.clipboard.writeText(lines.join("\n")); toast(T().copied) } catch { /* clipboard bloklangan */ }
}

/* ---------- chat ---------- */
function drawChat() {
  const el = $("#cl"); if (!el) return;
  el.innerHTML = CLOG.map(x => `<div class="msg ${x.err ? "err" : ""}"><b>${x.role === "user" ? "👤" : "🤖"}</b> ${esc(x.content)}</div>`).join("")
    + (waiting ? `<div class="msg"><b>🤖</b> <span class="spin"></span></div>` : "");
  el.scrollTop = el.scrollHeight;
}
async function sendChat(v) {
  if (!v.trim() || waiting) return;
  CH.push({ role: "user", content: v }); CLOG.push({ role: "user", content: v });
  $("#ci").value = ""; waiting = true; drawChat();
  const res = await api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ messages: CH, lang }) });
  waiting = false;
  if (res.text) { CH.push({ role: "assistant", content: res.text }); CLOG.push({ role: "assistant", content: res.text }) }
  else { CH.pop(); CLOG.push({ role: "assistant", content: res.error || "Error", err: true }) } // xato API tarixiga tushmaydi
  drawChat();
}

/* ---------- news & stats ---------- */
async function loadNews() {
  const res = await api("/api/news");
  if (!Array.isArray(res)) { $("#inp-area").textContent = res.error || "Error"; return }
  $("#inp-area").innerHTML = res.map(n => `<div class="news"><small>${esc(n.date)} &bull; ${esc(n.category)}</small><b>${esc(n.title)}</b><p>${esc(n.content)}</p></div>`).join("");
}
async function loadStats() {
  const t = T(), s = await api("/api/stats?lang=" + lang);
  if (s.error) { $("#inp-area").textContent = s.error; return }
  const max = Math.max(1, ...s.daily.map(d => d.count));
  $("#inp-area").innerHTML =
    `<p><b>${esc(t.total)}:</b> ${Number(s.total)}</p>` +
    s.levels.map(l => `<span class="badge ${esc(l.level)}">${esc(l.label)}: ${Number(l.count)}</span>`).join("") +
    `<p class="muted"><b>${esc(t.last7)}</b></p>` +
    s.daily.map(d => `<div class="bar"><span class="lbl">${esc(d.date)}</span><div class="track"><i data-w="${Math.round(d.count / max * 100)}"></i></div><span>${Number(d.count)}</span></div>`).join("") +
    `<p class="muted">${s.kinds.map(k => `${esc(k.kind)}: ${Number(k.count)}`).join(" &bull; ")}</p>`;
  applyWidths();
}

updateUI();
'''

ASSETS = {
    "app.css": (APP_CSS, "text/css"),
    "i18n.js": (I18N_JS, "text/javascript"),
    "app.js": (APP_JS, "text/javascript"),
}

@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.get("/static/<name>")
def static_asset(name):
    asset = ASSETS.get(name)
    if not asset:
        return jsonify(error="Not found"), 404
    resp = Response(asset[0], mimetype=asset[1])
    resp.headers["Cache-Control"] = "no-cache"
    return resp

@app.get("/health")
def health():
    try:
        with db() as con:
            con.execute("SELECT 1")
        return jsonify(status="ok")
    except Exception:
        app.logger.exception("health failed")
        return jsonify(status="db_error"), 503

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
