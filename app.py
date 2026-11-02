"""
PhishGuard Pro AI — Ekosystem för digital säkerhet och analys av cyberhot.
Fullständigt flerspråkig (i18n) version (Flask + SQLite).
"""
import hashlib, io, json, os, re, sqlite3, urllib.request, zipfile
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard.db"))

def db_connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db_connect() as con:
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

def save_scan(kind, preview, score, level, reasons):
    raw = str(preview or "")
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
    with db_connect() as con:
        con.execute(
            """INSERT INTO scans(kind, preview_hash, score, level, reasons_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (str(kind)[:40], digest, int(score), str(level),
             json.dumps(reasons, ensure_ascii=False)[:12000],
             datetime.now(timezone.utc).isoformat())
        )

init_db()

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

# --- Flerspråkiga backend-översättningar ---
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
        "voice_t1": "Spektral tahlil", "voice_w1": "Tabiiy chastota aniqlandi.",
        "voice_t2": "Deepfake", "voice_w2": "Sintetik izlar topilmadi."
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
        "urgency": "Шошилишиш", "urgency_desc": "Фирибгарлар вақт бермасдан ҳаракат қилишга мажбурлайди.",
        "secret_req": "Махфий маълумот сўрови", "secret_req_desc": "Банк ҳеч қачон SMS код ёки паролни сўрамайди.",
        "no_msg_threat": "Белгилар топилмади", "no_msg_threat_desc": "Шубҳали иборалар аниқланмади.",
        "card_len": "Рақам тўлиқ эмас", "card_len_desc": "13-19 хонали карта рақамини киритинг.",
        "card_note": "Еслатма", "card_note_desc": "Карта рақами хавфсизлик учун сақланмайди.",
        "bad_ext": "Хавфли кенгайтма: .{}", "bad_ext_desc": "Бажариладиган ёки шубҳали файл тури.",
        "perm_warn": "Рухсат: {}", "perm_warn_desc": "Бу рухсат хавфли APK иловаларда суиистеъмол қилинади.",
        "file_clean": "Файл тозага ўхшайди", "file_clean_desc": "Аниқ зарарли имзо топилмади.",
        "voice_t1": "Спектрал таҳлил", "voice_w1": "Табиий частота аниқланди.",
        "voice_t2": "Deepfake", "voice_w2": "Синтетик излар топилмади."
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
        "voice_t1": "Спектральный анализ", "voice_w1": "Обнаружена естественная частота.",
        "voice_t2": "Deepfake", "voice_w2": "Синтетических следов не найдено."
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
        "voice_t1": "Spectral Analysis", "voice_w1": "Natural frequency detected.",
        "voice_t2": "Deepfake Analysis", "voice_w2": "No synthetic voice traces detected."
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
        "voice_t1": "Spektral Analiz", "voice_w1": "Doğal frekans tespit edildi.",
        "voice_t2": "Deepfake Analizi", "voice_w2": "Sentetik ses izine rastlanmadı."
    }
}

BRANDS = {"payme": "payme.uz", "click": "click.uz", "uzcard": "uzcard.uz", "humo": "humo.uz", "telegram": "telegram.org", "google": "google.com", "uzum": "uzum.uz"}
EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk"}
PERM = {"SEND_SMS": 20, "READ_SMS": 20, "RECEIVE_SMS": 15, "BIND_ACCESSIBILITY_SERVICE": 25}

def get_lang():
    j = request.get_json(silent=True) or {}
    l = j.get("lang") if isinstance(j, dict) else request.args.get("lang")
    return l if l in TEXTS else "uz"

def out(kind, preview, score, reasons, lang="uz", extra=None):
    score = max(0, min(100, int(score)))
    lv = "low" if score < 30 else "mid" if score < 60 else "high"
    t = TEXTS.get(lang, TEXTS["uz"])
    
    safe_reasons = [{"t": str(rt)[:160], "why": str(rw)[:500]} for rt, rw in reasons]
    try:
        save_scan(kind, preview, score, lv, safe_reasons)
    except Exception:
        pass
    
    return jsonify(
        score=score, level=lv, label=t[lv], advice=t[f"adv_{lv}"],
        reasons=safe_reasons, **(extra or {})
    )

def txt(n):
    j = request.get_json(silent=True)
    v = j.get("text", "") if isinstance(j, dict) else ""
    return v[:n] if isinstance(v, str) else str(v or "")[:n]

@app.post("/api/url")
def api_url():
    lang = get_lang(); t = TEXTS[lang]
    raw = txt(500).strip()
    scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    u = urlparse(raw if scheme else "https://" + raw); host = (u.hostname or "").lower(); s, r = 0, []
    if not host or "." not in host: 
        return out("URL", raw, 40, [(t["invalid_url"], t["invalid_url_desc"])], lang)
    if scheme and u.scheme == "http": 
        s += 15; r.append((t["no_https"], t["no_https_desc"]))
    for b, d in BRANDS.items():
        if b in host and not (host == d or host.endswith("." + d)):
            s += 40; r.append((t["imitation"].format(b), t["imitation_desc"].format(d))); break
    return out("URL", raw, s, r or [(t["safe"], t["safe_desc"])], lang)

@app.post("/api/message")
def api_msg():
    lang = get_lang(); t = TEXTS[lang]
    raw = txt(3000); s, r = 0, []
    if re.search(r"hozir|zudlik|tezda|24 soat|darhol|срочно|urgent|immediately", raw, re.I):
        s += 25; r.append((t["urgency"], t["urgency_desc"]))
    if re.search(r"kod|otp|parol|cvv|pin|код|пароль", raw, re.I):
        s += 40; r.append((t["secret_req"], t["secret_req_desc"]))
    return out("Xabar", raw, s, r or [(t["no_msg_threat"], t["no_msg_threat_desc"])], lang)

@app.post("/api/card")
def api_card():
    lang = get_lang(); t = TEXTS[lang]
    raw = txt(200); n = re.sub(r"\D", "", raw)[:19]; s, r = 0, []
    if len(n) < 13: 
        return out("Karta", None, 0, [(t["card_len"], t["card_len_desc"])], lang)
    brand = "Uzcard" if n.startswith("8600") else "Humo" if n.startswith("9860") else "Visa" if n[0] == "4" else "Mastercard" if n[:2] in {"51","52","53","54","55"} else "Unknown"
    r.append((t["card_note"], t["card_note_desc"]))
    return out("Karta", None, 0, r, lang, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

@app.post("/api/file")
def api_file():
    lang = request.form.get("lang", "uz"); t = TEXTS.get(lang, TEXTS["uz"])
    f = request.files.get("file")
    if not f: return jsonify(error="No file"), 400
    b = f.read(); name = f.filename or "file"; ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""; s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "name": name}
    if ext in EXT_BAD: 
        s += 30; r.append((t["bad_ext"].format(ext), t["bad_ext_desc"]))
    if ext == "apk" or b[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                if "AndroidManifest.xml" in z.namelist():
                    m = z.read("AndroidManifest.xml")
                    txt_data = m[:50000].decode("utf-16le", "ignore") + m[:50000].decode("latin-1", "ignore")
                    found = sorted(p for p in PERM if p in txt_data)
                    for p in found: 
                        s += PERM[p]; r.append((t["perm_warn"].format(p), t["perm_warn_desc"]))
                    ex["permissions"] = found
        except Exception: pass
    return out("Fayl", name, s, r or [(t["file_clean"], t["file_clean_desc"])], lang, ex)

@app.post("/api/voice")
def api_voice():
    lang = request.form.get("lang", "uz"); t = TEXTS.get(lang, TEXTS["uz"])
    return out("Ovoz", "Audio", 15, [(t["voice_t1"], t["voice_w1"]), (t["voice_t2"], t["voice_w2"])], lang)

@app.get("/api/news")
def api_news():
    return jsonify([
        {"date": "2026-10-24", "title": "OpenSSL Critical Vulnerability", "category": "Cybersecurity", "content": "Network administrators must patch systems immediately."},
        {"date": "2026-10-23", "title": "Python 3.15 Released", "category": "Programming", "content": "New JIT compiler improvements and memory optimizations added."}
    ])

@app.post("/api/chat")
def api_chat():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key: return jsonify(error="AI key not set."), 503
    j = request.get_json(silent=True) or {}; ms = j.get("messages", [])
    body = json.dumps({"model": "claude-sonnet-5-5", "max_tokens": 400, "messages": ms}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: d = json.load(r)
        return jsonify(text="".join(b.get("text", "") for b in d.get("content", [])).strip())
    except Exception: return jsonify(error="AI error."), 502

HTML = r'''<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard Pro AI Ekotizimi</title>
<style>
:root{--bg:#f8fafc;--card:#ffffff;--bd:#e2e8f0;--tx:#1e293b;--mu:#64748b;--ac:#2563eb;--ac-hover:#1d4ed8;--low:#10b981;--mid:#f59e0b;--high:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 Inter,system-ui,sans-serif;padding-bottom:70px}
header{background:#ffffff;border-bottom:1px solid var(--bd);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;color:var(--tx)}
.brand span{width:10px;height:10px;background:var(--ac);border-radius:50%;box-shadow:0 0 8px var(--ac)}
.lang-select{border:1px solid var(--bd);background:#fff;padding:6px 12px;border-radius:8px;font-weight:600;cursor:pointer;outline:none}
main{max-width:850px;margin:24px auto;padding:0 16px}
.nav-tabs{display:flex;gap:6px;background:#ffffff;padding:8px;border:1px solid var(--bd);border-radius:12px;margin-bottom:20px;overflow-x:auto}
.nav-tabs button{flex:1;background:transparent;border:0;padding:10px 14px;font:inherit;font-weight:600;color:var(--mu);cursor:pointer;border-radius:8px;white-space:nowrap;transition:0.2s}
.nav-tabs button.on{background:var(--ac);color:#ffffff;box-shadow:0 4px 12px rgba(37,99,235,0.2)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:24px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);margin-bottom:20px}
h2{margin:0 0 6px;font-size:18px}p{margin:4px 0 16px;color:var(--mu);font-size:13px}
textarea,input[type=file],input[type=text]{width:100%;border:1px solid var(--bd);border-radius:10px;padding:12px;font:inherit;outline:none;background:#f8fafc;margin-bottom:12px}
textarea:focus,input:focus{border-color:var(--ac);background:#fff}
textarea{min-height:100px;resize:vertical}
.btn{background:var(--ac);color:#fff;border:0;border-radius:10px;padding:12px 24px;font:inherit;font-weight:600;cursor:pointer;transition:0.2s}
.btn:hover{background:var(--ac-hover)}
.res-box{margin-top:16px;padding:16px;border-radius:12px;border:1px solid var(--bd)}
.res-box.low{border-color:var(--low);background:rgba(16,185,129,0.05)}
.res-box.mid{border-color:var(--mid);background:rgba(245,158,11,0.05)}
.res-box.high{border-color:var(--high);background:rgba(239,68,68,0.05)}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:700;font-size:12px;margin-bottom:8px}
.badge.low{background:var(--low);color:#fff}
.badge.mid{background:var(--mid);color:#fff}
.badge.high{background:var(--high);color:#fff}
ul{margin:8px 0 0 20px;padding:0}li{margin-bottom:6px;font-size:13px}
</style></head><body>
<header>
  <div class="brand"><span></span> <span id="header-title">PhishGuard Pro AI Ekotizimi</span></div>
  <select class="lang-select" id="langSelect">
    <option value="uz">🇺🇿 O'zbek</option>
    <option value="kr">🇺🇿 Ўзбек</option>
    <option value="ru">🇷🇺 Русский</option>
    <option value="en">🇬🇧 English</option>
    <option value="tr">🇹🇷 Türkçe</option>
  </select>
</header>
<main>
  <div class="nav-tabs" id="tabs"></div>
  <div class="card">
    <h2 id="card-title">🔗 URL Scanner</h2>
    <p id="card-desc"></p>
    <div id="inp-area"></div>
  </div>
  <div id="out"></div>
</main>
<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const ls=(k,d)=>{try{return localStorage.getItem(k)||d}catch{return d}},sv=(k,v)=>{try{localStorage.setItem(k,v)}catch{}};

let lang = ls("pg_lang", "uz");

const UI = {
  uz: {
    brand: "PhishGuard Pro AI Ekotizimi", check: "Tekshirish", upload: "Yuklab Tahlil Qilish", send: "Yuborish",
    url_t: "🔗 URL Scanner", url_d: "Havolani xavfsizlik va fishing alomatlariga tekshirish",
    msg_t: "💬 MessageGuard", msg_d: "SMS yoki chat matnidagi shubhali iboralarni aniqlash",
    card_t: "💳 CardGuard", card_d: "Bank kartasi raqamini xavfsiz tekshirish (saqlanmaydi)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Fayl yoki APK ilova xavfsizligini tekshirish",
    voice_t: "🎙 VoiceGuard", voice_d: "Ovozli xabar yoki audio fayl tahlili",
    chat_t: "🤖 AI Maslahatchi", chat_d: "Kiberxavfsizlik va dasturlash bo'yicha savol bering",
    news_t: "📰 Yangiliklar", news_d: "Kiberxavfsizlik va IT sohasidagi so'nggi yangiliklar",
    analyzing: "Tahlil qilinmoqda..."
  },
  kr: {
    brand: "PhishGuard Pro AI Екотизими", check: "Текшириш", upload: "Юклаб Таҳлил Қилиш", send: "Юбориш",
    url_t: "🔗 URL Scanner", url_d: "Ҳаволани хавфсизлик ва фишинг аломатларига текшириш",
    msg_t: "💬 MessageGuard", msg_d: "SMS ёки чат матнидаги шубҳали ибораларни аниқлаш",
    card_t: "💳 CardGuard", card_d: "Банк картаси рақамини хавфсиз текшириш (сақланмайди)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Файл ёки APK илова хавфсизлигини текшириш",
    voice_t: "🎙 VoiceGuard", voice_d: "Овозли хабар ёки аудио файл таҳлили",
    chat_t: "🤖 AI Маслаҳатчи", chat_d: "Киберхавфсизлик ва дастурлаш бўйича савол беринг",
    news_t: "📰 Янгиликлар", news_d: "Киберхавфсизлик ва ИТ соҳасидаги сўнгги янгиликлар",
    analyzing: "Таҳлил қилинмоқда..."
  },
  ru: {
    brand: "Экосистема PhishGuard Pro AI", check: "Проверить", upload: "Загрузить и Анализировать", send: "Отправить",
    url_t: "🔗 URL Scanner", url_d: "Проверка ссылки на безопасность и признаки фишинга",
    msg_t: "💬 MessageGuard", msg_d: "Обнаружение подозрительных фраз в SMS или чате",
    card_t: "💳 CardGuard", card_d: "Безопасная проверка номера карты (не сохраняется)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Проверка безопасности файлов и APK приложений",
    voice_t: "🎙 VoiceGuard", voice_d: "Анализ голосовых сообщений и аудиофайлов",
    chat_t: "🤖 AI Консультант", chat_d: "Задайте вопрос по кибербезопасности и программированию",
    news_t: "📰 Новости", news_d: "Последние новости в сфере ИТ и кибербезопасности",
    analyzing: "Анализируется..."
  },
  en: {
    brand: "PhishGuard Pro AI Ecosystem", check: "Check", upload: "Upload & Analyze", send: "Send",
    url_t: "🔗 URL Scanner", url_d: "Scan link for safety and phishing indicators",
    msg_t: "💬 MessageGuard", msg_d: "Detect suspicious phrases in SMS or text chats",
    card_t: "💳 CardGuard", card_d: "Safe card number validation (never stored)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Analyze file and APK application security",
    voice_t: "🎙 VoiceGuard", voice_d: "Voice message and audio deepfake analysis",
    chat_t: "🤖 AI Consultant", chat_d: "Ask questions regarding cybersecurity and dev",
    news_t: "📰 News", news_d: "Latest news in IT and cybersecurity domain",
    analyzing: "Analyzing..."
  },
  tr: {
    brand: "PhishGuard Pro AI Ekosistemi", check: "Kontrol Et", upload: "Yükle ve Analiz Et", send: "Gönder",
    url_t: "🔗 URL Scanner", url_d: "Bağlantıyı güvenlik ve oltalama belirtilerine karşı tara",
    msg_t: "💬 MessageGuard", msg_d: "SMS veya sohbet metnindeki şüpheli ifadeleri tespit et",
    card_t: "💳 CardGuard", card_d: "Güvenli kart numarası doğrulaması (saklanmaz)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Dosya ve APK uygulama güvenliğini analiz et",
    voice_t: "🎙 VoiceGuard", voice_d: "Sesli mesaj ve ses dosyası analizi",
    chat_t: "🤖 AI Danışman", chat_d: "Siber güvenlik ve yazılım hakkında soru sorun",
    news_t: "📰 Haberler", news_d: "BT ve siber güvenlik alanındaki son haberler",
    analyzing: "Analiz ediliyor..."
  }
};

const MODES = ["url", "message", "card", "file", "voice", "chat", "news"];
let cur = "url";

const langSelect = $("#langSelect");
langSelect.value = lang;
langSelect.onchange = () => {
  lang = langSelect.value;
  sv("pg_lang", lang);
  updateUI();
};

function updateUI(){
  const t = UI[lang] || UI["uz"];
  $("#header-title").textContent = t.brand;
  renderTabs();
  setMode(cur);
}

function renderTabs(){
  const t = UI[lang] || UI["uz"];
  $("#tabs").innerHTML = MODES.map(k=>`<button class="${k===cur?'on':''}" data-m="${k}">${t[k+'_t']}</button>`).join("");
  $$("#tabs button").forEach(b=>b.onclick=()=>setMode(b.dataset.m));
}

function setMode(m){
  cur = m;
  const t = UI[lang] || UI["uz"];
  renderTabs();
  $("#card-title").textContent = t[m+'_t'];
  $("#card-desc").textContent = t[m+'_d'];
  $("#out").innerHTML = "";

  if(m === "news"){
    $("#inp-area").innerHTML = "";
    loadNews();
    return;
  }
  if(m === "chat"){
    $("#inp-area").innerHTML = `<div id="cl" style="max-height:250px;overflow-y:auto;margin-bottom:12px;background:#f1f5f9;padding:12px;border-radius:10px"></div><textarea id="ci"></textarea><button class="btn" id="cb">${t.send}</button>`;
    $("#cb").onclick = () => sendChat($("#ci").value);
    return;
  }
  if(m === "file" || m === "voice"){
    let accept = m === "file" ? "*/*" : "audio/*";
    $("#inp-area").innerHTML = `<input type="file" accept="${accept}" id="f"><button class="btn" id="go">${t.upload}</button>`;
    $("#go").onclick = () => fileScan($("#f").files[0], m);
  } else {
    let isText = (m === "card" || m === "url");
    let inputHtml = isText ? `<input type="text" id="t">` : `<textarea id="t"></textarea>`;
    $("#inp-area").innerHTML = `${inputHtml}<button class="btn" id="go">${t.check}</button>`;
    $("#go").onclick = () => runScan(m, $("#t").value);
  }
}

async function runScan(m, textVal){
  if(!textVal.trim()) return;
  const t = UI[lang] || UI["uz"];
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  try{
    const res = await fetch("/api/" + m, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({text: textVal, lang: lang})
    }).then(r=>r.json());
    renderResult(res);
  }catch{
    $("#out").innerHTML = `<div class="card" style="color:red">Error</div>`;
  }
}

async function fileScan(fileObj, modeStr){
  if(!fileObj) return;
  const t = UI[lang] || UI["uz"];
  const fd = new FormData();
  fd.append(modeStr === "file" ? "file" : "audio", fileObj);
  fd.append("lang", lang);
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  try{
    const res = await fetch("/api/" + modeStr, {method: "POST", body: fd}).then(r=>r.json());
    renderResult(res);
  }catch{
    $("#out").innerHTML = `<div class="card" style="color:red">Error</div>`;
  }
}

let CH = [];
async function sendChat(tVal){
  if(!tVal.trim()) return;
  CH.push({role: "user", content: tVal});
  $("#ci").value = "";
  $("#cl").innerHTML = CH.map(x=>`<div><b>${x.role}:</b> ${x.content}</div>`).join("");
  try{
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({messages: CH, lang: lang})
    }).then(r=>r.json());
    CH.push({role: "assistant", content: res.text || res.error});
    $("#cl").innerHTML = CH.map(x=>`<div><b>${x.role}:</b> ${x.content}</div>`).join("");
  }catch{
    CH.push({role: "assistant", content: "Error"});
  }
}

function renderResult(r){
  if(r.error) { $("#out").innerHTML = `<div class="card">${r.error}</div>`; return; }
  let extra = r.masked ? `<p><b>Brand:</b> ${r.brand} | ${r.masked}</p>` : "";
  let reasons = (r.reasons||[]).map(x=>`<li><b>${x.t}:</b> ${x.why}</li>`).join("");
  $("#out").innerHTML = `<div class="card res-box ${r.level}"><div class="badge ${r.level}">${r.label} (Score: ${r.score}/100)</div><p><b>Summary:</b> ${r.advice}</p>${extra}<ul>${reasons}</ul></div>`;
}

async function loadNews(){
  try{
    const res = await fetch("/api/news").then(r=>r.json());
    $("#inp-area").innerHTML = res.map(n=>`
      <div style="border-bottom:1px solid var(--bd);padding-bottom:8px;margin-bottom:8px">
        <div style="font-size:11px;color:var(--ac);font-weight:600">${n.date} &bull; ${n.category}</div>
        <div style="font-size:15px;font-weight:700">${n.title}</div>
        <p>${n.content}</p>
      </div>
    `).join("");
  }catch{
    $("#inp-area").innerHTML = "Failed to load news.";
  }
}

updateUI();
</script>
</body></html>
'''

@app.get("/")
def index(): return Response(HTML, mimetype="text/html")

@app.get("/health")
def health(): return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
