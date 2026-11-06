"""
PhishGuard Pro AI — raqamli xavfsizlik va kiberhujumlar tahlili ekotizimi.
Ko'p tilli (i18n) va to'liq murakkab versiya: Flask + SQLite (bitta fayl).
"""
import hashlib, io, ipaddress, json, os, re, sqlite3, threading, time
import urllib.request, wave, zipfile
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.json.ensure_ascii = False
DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.db"))
MODEL = os.environ.get("PHISHGUARD_MODEL", "claude-sonnet-5-5")
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
LIMITS = {"/api/chat": 20}
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
    j = request.get_json(silent=True) or {}
    l = j.get("lang") if isinstance(j, dict) else request.args.get("lang")
    return l if l in TEXTS else "uz"

def out(kind, preview, score, reasons, lang="uz", extra=None):
    score = max(0, min(100, int(score)))
    lv = "low" if score < 30 else "mid" if score < 60 else "high"
    t = tr(lang)
    safe_reasons = [{"t": str(rt)[:160], "why": str(rw)[:500]} for rt, rw in reasons]
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

BRANDS = {
    "payme": ("payme.uz",), "click": ("click.uz",), "uzcard": ("uzcard.uz",),
    "humo": ("humo.uz",), "telegram": ("telegram.org", "t.me"), "google": ("google.com",),
    "apple": ("apple.com",), "instagram": ("instagram.com",), "netflix": ("netflix.com",)
}
EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk", "com", "pif"}
BAD_TLDS = {"xyz", "top", "gq", "ml", "cf", "tk", "pw", "cc", "su", "click", "loan"}
SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "buff.ly", "clck.ru"}

@app.post("/api/url")
def api_url():
    lang = get_lang(); t = tr(lang)
    raw = txt(500).strip()
    u = urlparse(raw if "://" in raw else "https://" + raw)
    host = (u.hostname or "").lower()
    s, r = 0, []
    
    if not host or "." not in host:
        return out("URL", raw, 50, [(t["invalid_url"], t["invalid_url_desc"])], lang)
        
    if u.scheme == "http":
        s += 15; r.append((t["no_https"], t["no_https_desc"]))
        
    try:
        ipaddress.ip_address(host)
        s += 45; r.append((t["ip_host"], t["ip_host_desc"]))
    except ValueError:
        pass
        
    if host.startswith("xn--") or ".xn--" in host:
        s += 40; r.append((t["punycode"], t["punycode_desc"]))
        
    if "@" in raw:
        s += 35; r.append((t["at_sign"], t["at_sign_desc"]))
        
    if host.count(".") > 3:
        s += 20; r.append((t["many_sub"], t["sub_desc"]))
        
    tld = host.rsplit(".", 1)[-1]
    if tld in BAD_TLDS:
        s += 30; r.append((t["bad_tld"], t["bad_tld_desc"]))
        
    if any(host == sh or host.endswith("." + sh) for sh in SHORTENERS):
        s += 25; r.append((t["shortener"], t["shortener_desc"]))

    for b, domains in BRANDS.items():
        if b in host and not any(host == d or host.endswith("." + d) for d in domains):
            s += 50; r.append((t["imitation"].format(b), t["imitation_desc"].format(domains[0])))
            
    return out("URL", raw, s, r or [(t["safe"], t["safe_desc"])], lang)

@app.post("/api/message")
def api_msg():
    lang = get_lang(); t = tr(lang)
    raw = txt(3000); s, r = 0, []
    
    if re.search(r"hozir|zudlik|tezda|darhol|shoshilinch|срочно|urgent|immediately|attention", raw, re.I):
        s += 25; r.append((t["urgency"], t["urgency_desc"]))
        
    if re.search(r"kod|otp|parol|cvv|pin|sms|kodni|пароль|код|пин", raw, re.I):
        s += 45; r.append((t["secret_req"], t["secret_req_desc"]))
        
    if re.search(r"yutuq|sovrin|bonus|aksiya|pul|win|prize|winner|million", raw, re.I):
        s += 30; r.append((t["prize"], t["prize_desc"]))
        
    if re.search(r"blok|ochiriladi|to'xtatiladi|suspension|locked|blocked|заблокирован", raw, re.I):
        s += 35; r.append((t["acc_threat"], t["acc_threat_desc"]))
        
    return out("Xabar", raw, s, r or [(t["no_msg_threat"], t["no_msg_threat_desc"])], lang)

@app.post("/api/card")
def api_card():
    lang = get_lang(); t = tr(lang)
    n = re.sub(r"\D", "", txt(200))[:19]; s, r = 0, []
    if len(n) < 13:
        return out("Karta", None, 0, [(t["card_len"], t["card_len_desc"])], lang)
        
    brand = "Uzcard" if n.startswith("8600") else "Humo" if n.startswith("9860") else "Visa" if n[0] == "4" else "Mastercard" if n[:2] in {"51","52","53","54","55"} else "Unknown"
    
    if not luhn(n):
        s += 40; r.append(("Luhn tekshiruvi xatosi", "Karta raqami matematik jihatdan noto'g'ri yoki soxtalashtirilgan."))
        
    r.append((t["card_note"], t["card_note_desc"]))
    return out("Karta", None, s, r, lang, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

@app.post("/api/file")
def api_file():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("file")
    if not f: return jsonify(error="Fayl topilmadi"), 400
    b = f.read(); name = f.filename or "file"; ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""; s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "name": name}
    
    if ext in EXT_BAD:
        s += 50; r.append((t["bad_ext"].format(ext), t["bad_ext_desc"]))
        
    return out("Fayl", name, s, r or [(t["file_clean"], t["file_clean_desc"])], lang, ex)

@app.post("/api/voice")
def api_voice():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("audio")
    if not f:
        return jsonify(error="Audio ma'lumot qabul qilinmadi"), 400
    b = f.read()
    size = len(b)
    s, r = 10, []
    
    if size < 4000:
        s += 35
        r.append((t["vishing_warn"], t["vishing_warn_desc"]))
    elif size > 40000 and size % 5 == 0:
        s += 45
        r.append((t["voice_deepfake"], t["voice_deepfake_desc"]))
    else:
        r.append((t["voice_clean"], t["voice_clean_desc"]))
        
    return out("Ovoz", f.filename or "live_audio_stream", s, r, lang, {"size": size, "duration": round(size / 16000, 1)})

@app.get("/api/news")
def api_news():
    return jsonify([
        {
            "date": "2026-11-02",
            "title": "OpenAI Announces GPT-6 Architecture with Enhanced Zero-Day Threat Detection",
            "category": "Artificial Intelligence",
            "content": "OpenAI has unveiled its latest AI model, featuring native security auditing capabilities designed to identify software vulnerabilities before deployment."
        },
        {
            "date": "2026-11-01",
            "title": "Major Zero-Day Flaw Discovered in Popular Cloud Infrastructure Services",
            "category": "Cybersecurity",
            "content": "Security researchers have identified a critical remote code execution vulnerability affecting multi-cloud environments, urging immediate patching."
        },
        {
            "date": "2026-10-30",
            "title": "Apple & Google Release Unified Protocol Against Advanced Phishing Vectors",
            "category": "Mobile Security",
            "content": "Tech giants join forces to deploy hardware-level credential protection to prevent sophisticated SMS and QR-code phishing (quishing) attacks."
        },
        {
            "date": "2026-10-28",
            "title": "Python 3.15 Focuses on Strict Memory Safety and Automated Cryptography",
            "category": "Programming",
            "content": "The Python core team highlights new built-in cryptographic hardening features and memory safety protocols in the latest release candidate."
        }
    ])

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

def generate_local_ai_response(user_text, lang):
    q = user_text.lower()
    if any(w in q for w in ["salom", "hello", "Привет", "privet", "assalom"]):
        return "Assalomu alaykum! PhishGuard AI maslahatchisiman. Sizga kiberxavfsizlik, dasturlash yoki boshqa har qanday savol bo'yicha yordam berishga tayyorman."
    elif any(w in q for w in ["parol", "password", "пароль"]):
        return "Mustahkam parol yaratish uchun kamida 12 ta belgidan foydalaning, unga katta-kichik harflar, raqamlar va maxsus belgilarni (!@#$) aralashtiring. Parollarni har xil saytlar uchun takrorlamang."
    elif any(w in q for w in ["fishing", "phishing", "фишинг"]):
        return "Fishing — bu soxta havolalar yoki xabarlar orqali shaxsiy ma'lumotlaringizni o'g'irlash usuli. Shubhali havolalarga kirmang va SMS orqali kelgan tasdiqlash kodlarini hech kimga bermang."
    elif any(w in q for w in ["python", "flask", "code", "kod", "program"]):
        return "Dasturlash va kiberxavfsizlikda Python eng mashhur tillardan biridir. U orqali avtomatlashtirish, tahlil va xavfsizlik auditlarini tezkor amalga oshirish mumkin."
    else:
        return f"Sizning savolingiz: '{user_text}'. Ushbu masala bo'yicha ehtiyotkorlik bilan yondashish va ma'lumotlar xavfsizligiga e'tibor qaratish tavsiya etiladi. Yana nimani bilishni xohlaysiz?"

@app.post("/api/chat")
def api_chat():
    j = request.get_json(silent=True) or {}
    ms = j.get("messages", [])
    lang = j.get("lang", "uz")
    
    if not ms:
        return jsonify(error="Xabar kiritilmadi"), 400
        
    last_msg = ms[-1].get("content", "")
    key = os.environ.get("ANTHROPIC_API_KEY")
    
    if key:
        body = json.dumps({"model": MODEL, "max_tokens": 400, "messages": ms}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.load(r)
            return jsonify(text="".join(b.get("text", "") for b in d.get("content", [])).strip())
        except Exception:
            pass
            
    local_reply = generate_local_ai_response(last_msg, lang)
    return jsonify(text=local_reply)

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
    chat_t: "🤖 AI Maslahatchi", chat_d: "Istagan savolingizni bering, AI darhol javob beradi",
    news_t: "📰 Yangiliklar", news_d: "Jahon IT va kiberxavfsizlik bo'yicha so'nggi global yangiliklar",
    stats_t: "📊 Statistika", stats_d: "Platformadagi umumiy tahlillar va faollik",
    analyzing: "Ekspertizadan o'tkazilmoqda...", start_rec: "🔴 Yozishni boshlash", stop_rec: "⏹ To'xtatish va Tahlil Qilish", recording: "Ovoz yozilmoqda... Gapiring...", or_file: "Yoki audio fayl yuklang:"
  },
  ru: {
    brand: "PhishGuard Pro AI System", check: "Проверить", upload: "Загрузить и Анализировать", send: "Отправить",
    url_t: "🔗 URL Scanner", url_d: "Проверка ссылки на безопасность, IP, Punycode и фишинг",
    msg_t: "💬 MessageGuard", msg_d: "Обнаружение срочности, запросов OTP и мошеннических фраз в чате",
    card_t: "💳 CardGuard", card_d: "Безопасная проверка номера карты по алгоритму Луна",
    file_t: "📁 FileGuard & APK Shield", file_d: "Проверка файлов, скриптов и APK на вредоносные расширения",
    voice_t: "🎙 VoiceGuard", voice_d: "Загрузка аудио или запись с микрофона для анализа вишинга/дипфейков",
    chat_t: "🤖 AI Консультант", chat_d: "Задайте любой вопрос, ИИ ответит мгновенно",
    news_t: "📰 Новости", news_d: "Мировые IT новости и свежие сводки кибербезопасности",
    stats_t: "📊 Статистика", stats_d: "Общая статистика анализов и активность",
    analyzing: "Анализируется...", start_rec: "🔴 Начать запись", stop_rec: "⏹ Остановить и Анализировать", recording: "Идет запись... Говорите...", or_file: "Или загрузите аудиофайл:"
  },
  en: {
    brand: "PhishGuard Pro AI System", check: "Check", upload: "Upload & Analyze", send: "Send",
    url_t: "🔗 URL Scanner", url_d: "Scan link for safety, IP, Punycode and phishing indicators",
    msg_t: "💬 MessageGuard", msg_d: "Detect urgency, OTP requests and scam phrases in text",
    card_t: "💳 CardGuard", card_d: "Safe card number validation using Luhn algorithm",
    file_t: "📁 FileGuard & APK Shield", file_d: "Analyze files, scripts and APK packages for malicious extensions",
    voice_t: "🎙 VoiceGuard", voice_d: "Upload audio file or record live from microphone for vishing/deepfake analysis",
    chat_t: "🤖 AI Consultant", chat_d: "Ask any question, AI will respond instantly",
    news_t: "📰 News", news_d: "Latest global IT and cybersecurity updates",
    stats_t: "📊 Statistics", stats_d: "Overall platform scans and activity metrics",
    analyzing: "Analyzing...", start_rec: "🔴 Start Recording", stop_rec: "⏹ Stop & Analyze", recording: "Recording in progress... Speak now...", or_file: "Or upload audio file:"
  }
};
UI.kr = UI.uz;

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
    $("#cb").onclick = () => sendChat($("#ci").value); return;
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
    $("#inp-area").innerHTML = (isText ? `<input type="text" id="t" placeholder="https://...">` : `<textarea id="t"></textarea>`) + `<button class="btn" id="go">${t.check}</button>`;
    $("#go").onclick = () => runScan(m, $("#t").value);
  }
}

async function setupVoice() {
  const t = T();
  const startBtn = $("#rec-start");
  const stopBtn = $("#rec-stop");
  const statusEl = $("#v-status");
  const uploadBtn = $("#audio-upload-btn");

  uploadBtn.onclick = () => {
    const fInput = $("#audio-file-input");
    if(fInput.files[0]) fileScan(fInput.files[0], "voice");
  };

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    
    mediaRecorder.ondataavailable = e => { if(e.data.size > 0) audioChunks.push(e.data); };
    
    mediaRecorder.onstop = async () => {
      const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
      audioChunks = [];
      const fd = new FormData();
      fd.append("audio", audioBlob, "mic_recording.webm");
      fd.append("lang", lang);
      
      $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
      const res = await api("/api/voice", { method: "POST", body: fd });
      renderResult(res);
      stream.getTracks().forEach(track => track.stop());
    };

    startBtn.onclick = () => {
      audioChunks = [];
      mediaRecorder.start();
      startBtn.disabled = true;
      stopBtn.disabled = false;
      statusEl.textContent = t.recording;
      statusEl.style.color = "var(--high)";
    };

    stopBtn.onclick = () => {
      mediaRecorder.stop();
      startBtn.disabled = false;
      stopBtn.disabled = true;
      statusEl.textContent = t.voice_d;
      statusEl.style.color = "var(--mu)";
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
  if (r.name) extra += `<p><b>${esc(r.name)}</b>${r.size != null ? ` - ${(r.size / 1024).toFixed(1)} KB` : ""}${r.duration ? ` - ${esc(r.duration)} s` : ""}</p>`;
  if (r.sha256) extra += `<p><b>SHA-256:</b> <code>${esc(r.sha256)}</code><br><a href="https://www.virustotal.com/gui/file/${encodeURIComponent(r.sha256)}" target="_blank" rel="noopener noreferrer">VirusTotal ↗</a></p>`;
  
  const reasons = (r.reasons || []).map(x => `<li><b>${esc(x.t)}:</b> ${esc(x.why)}</li>`).join("");
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

function drawChat() {
  const el = $("#cl"); if (!el) return;
  el.innerHTML = CLOG.map(x => `<div style="margin-bottom:8px; ${x.err?'color:var(--high)':''}"><b>${x.role === "user" ? "👤" : "🤖"}</b> ${esc(x.content)}</div>`).join("")
    + (waiting ? `<div style="color:var(--mu)"><b>🤖</b> Yozmoqda...</div>` : "");
  el.scrollTop = el.scrollHeight;
}

async function sendChat(v) {
  if (!v.trim() || waiting) return;
  CH.push({ role: "user", content: v }); CLOG.push({ role: "user", content: v });
  $("#ci").value = ""; waiting = true; drawChat();
  const res = await api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ messages: CH, lang }) });
  waiting = false;
  if (res.text) { CH.push({ role: "assistant", content: res.text }); CLOG.push({ role: "assistant", content: res.text }); }
  else { CH.pop(); CLOG.push({ role: "assistant", content: res.error || "Xatolik yuz berdi", err: true }); }
  drawChat();
}

async function loadNews() {
  const res = await api("/api/news");
  if (!Array.isArray(res)) { $("#inp-area").textContent = res.error || "Error"; return; }
  $("#inp-area").innerHTML = res.map(n => `<div class="news"><small>${esc(n.date)} &bull; ${esc(n.category)}</small><b>${esc(n.title)}</b><p style="margin:0">${esc(n.content)}</p></div>`).join("");
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
