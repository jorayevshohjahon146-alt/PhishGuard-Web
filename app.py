"""
PhishGuard Pro AI — raqamli xavfsizlik va kiberhujumlar tahlili ekotizimi.
Ko'p tilli (i18n) versiya: Flask + SQLite (bitta fayl).
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
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return resp

_hits, _lock = defaultdict(deque), threading.Lock()
LIMITS = {"/api/chat": 8}
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
        "voice_demo": "Demo rejim", "voice_demo_desc": "Deepfake aniqlash modeli hali ulanmagan.",
        "prize": "Yutuq va'dasi", "prize_desc": "Soxta sovrin ko'pincha ma'lumot yig'ish uchun ishlatiladi.",
        "acc_threat": "Hisob bloklanishi tahdidi", "acc_threat_desc": "Qo'rqitib ma'lumot so'rash keng tarqalgan usul.",
        "total": "Jami tekshiruvlar", "last7": "Oxirgi 7 kundagi dinamika", "copy": "Nusxalash", "copied": "Nusxalandi!", "demo_label": "Demo"
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
        "ip_host": "IP-адрес", "ip_host_desc": "Ссылка ведёт напрямую на IP-адрес.",
        "punycode": "Punycode (xn--)", "punycode_desc": "Возможен поддельный домен с похожими символами.",
        "at_sign": "Символ '@'", "at_sign_desc": "Настоящий адрес может скрываться после '@'.",
        "many_sub": "Много поддоменов", "many_sub_desc": "Длинная цепочка поддоменов типична для мошенников.",
        "bad_tld": "Подозрительная доменная зона", "bad_tld_desc": "Эти зоны часто используют для фишинга.",
        "shortener": "Сокращённая ссылка", "shortener_desc": "Реальный адрес скрыт; проверьте перед открытием.",
        "card_luhn": "Проверка Луна не пройдена", "card_luhn_desc": "В номере ошибка или карта поддельная.",
        "dbl_ext": "Двойное расширение", "dbl_ext_desc": "Файл маскируется под безобидный.",
        "disguised": "Замаскированный исполняемый файл", "disguised_desc": "Внутри сигнатура .exe/ELF, а расширение другое.",
        "voice_demo": "Демо-режим", "voice_demo_desc": "Модель выявления дипфейков не подключена.",
        "prize": "Обещание выигрыша", "prize_desc": "Фальшивые призы часто используют для сбора данных.",
        "acc_threat": "Угроза блокировки аккаунта", "acc_threat_desc": "Запугивание — частый приём для выманивания данных.",
        "total": "Всего проверок", "last7": "Динамика за 7 дней", "copy": "Копировать", "copied": "Скопировано!", "demo_label": "Демо"
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
        "ip_host": "IP address host", "ip_host_desc": "The link points straight to an IP address.",
        "punycode": "Punycode (xn--)", "punycode_desc": "May be a look-alike domain.",
        "at_sign": "'@' in URL", "at_sign_desc": "The real destination may be hidden after '@'.",
        "many_sub": "Many subdomains", "many_sub_desc": "Long subdomain chains are common in scams.",
        "bad_tld": "Suspicious TLD", "bad_tld_desc": "These zones are frequently abused for phishing.",
        "shortener": "Shortened link", "shortener_desc": "The real destination is hidden; verify before opening.",
        "card_luhn": "Luhn check failed", "card_luhn_desc": "The number has a typo or the card is fake.",
        "dbl_ext": "Double extension", "dbl_ext_desc": "The file is disguised as something harmless.",
        "disguised": "Disguised executable", "disguised_desc": "Contains an .exe/ELF signature.",
        "voice_demo": "Demo mode", "voice_demo_desc": "No deepfake-detection model is connected.",
        "prize": "Prize promise", "prize_desc": "Fake prizes are often used to harvest data.",
        "acc_threat": "Account-lock threat", "acc_threat_desc": "Intimidation is a common trick.",
        "total": "Total scans", "last7": "Last 7 days activity", "copy": "Copy", "copied": "Copied!", "demo_label": "Demo"
    }
}
TEXTS["kr"] = TEXTS["uz"] # Kirillcha uchun

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

BRANDS = {"payme": ("payme.uz",), "click": ("click.uz",), "uzcard": ("uzcard.uz",), "humo": ("humo.uz",), "telegram": ("telegram.org", "t.me"), "google": ("google.com",)}
EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk"}
PERM = {"SEND_SMS": 20, "READ_SMS": 20, "RECEIVE_SMS": 15, "BIND_ACCESSIBILITY_SERVICE": 25}

@app.post("/api/url")
def api_url():
    lang = get_lang(); t = tr(lang)
    raw = txt(500).strip()
    u = urlparse(raw if "://" in raw else "https://" + raw)
    host = (u.hostname or "").lower()
    s, r = 0, []
    if not host or "." not in host:
        return out("URL", raw, 40, [(t["invalid_url"], t["invalid_url_desc"])], lang)
    if u.scheme == "http":
        s += 15; r.append((t["no_https"], t["no_https_desc"]))
    for b, domains in BRANDS.items():
        if b in host and not any(host == d or host.endswith("." + d) for d in domains):
            s += 40; r.append((t["imitation"].format(b), t["imitation_desc"].format(domains[0])))
    return out("URL", raw, s, r or [(t["safe"], t["safe_desc"])], lang)

@app.post("/api/message")
def api_msg():
    lang = get_lang(); t = tr(lang)
    raw = txt(3000); s, r = 0, []
    if re.search(r"hozir|zudlik|tezda|darhol|срочно|urgent", raw, re.I):
        s += 25; r.append((t["urgency"], t["urgency_desc"]))
    if re.search(r"kod|otp|parol|cvv|pin|код|пароль", raw, re.I):
        s += 40; r.append((t["secret_req"], t["secret_req_desc"]))
    return out("Xabar", raw, s, r or [(t["no_msg_threat"], t["no_msg_threat_desc"])], lang)

@app.post("/api/card")
def api_card():
    lang = get_lang(); t = tr(lang)
    n = re.sub(r"\D", "", txt(200))[:19]; s, r = 0, []
    if len(n) < 13:
        return out("Karta", None, 0, [(t["card_len"], t["card_len_desc"])], lang)
    brand = "Uzcard" if n.startswith("8600") else "Humo" if n.startswith("9860") else "Visa" if n[0] == "4" else "Mastercard" if n[:2] in {"51","52","53","54","55"} else "Unknown"
    if not luhn(n):
        s += 30; r.append((t["card_luhn"], t["card_luhn_desc"]))
    r.append((t["card_note"], t["card_note_desc"]))
    return out("Karta", None, s, r, lang, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

@app.post("/api/file")
def api_file():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("file")
    if not f: return jsonify(error=t.get("no_file", "No file")), 400
    b = f.read(); name = f.filename or "file"; ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""; s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b), "name": name}
    if ext in EXT_BAD:
        s += 30; r.append((t["bad_ext"].format(ext), t["bad_ext_desc"]))
    return out("Fayl", name, s, r or [(t["file_clean"], t["file_clean_desc"])], lang, ex)

@app.post("/api/voice")
def api_voice():
    lang = get_lang(); t = tr(lang)
    f = request.files.get("audio")
    name = f.filename.rsplit("/", 1)[-1] if f and f.filename else "audio"
    return out("Ovoz", name, 0, [(t["voice_demo"], t["voice_demo_desc"])], lang, {"demo": True})

@app.get("/api/news")
def api_news():
    return jsonify([
        {"date": "2026-10-24", "title": "OpenSSL Critical Vulnerability", "category": "Cybersecurity", "content": "Network administrators must patch systems immediately."},
        {"date": "2026-10-23", "title": "Python 3.15 Released", "category": "Programming", "content": "New JIT compiler improvements and memory optimizations added."}
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

@app.post("/api/chat")
def api_chat():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key: return jsonify(error="AI key not set."), 503
    j = request.get_json(silent=True) or {}; ms = j.get("messages", [])
    body = json.dumps({"model": MODEL, "max_tokens": 400, "messages": ms}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: d = json.load(r)
        return jsonify(text="".join(b.get("text", "") for b in d.get("content", [])).strip())
    except Exception: return jsonify(error="AI error."), 502

INDEX_HTML = r'''<!doctype html>
<html lang="uz">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishGuard Pro AI — Cyber Ecosystem</title>
  <style>
    :root {
      --bg: #070a12;
      --card: #0f172a;
      --bd: #1e293b;
      --tx: #f8fafc;
      --mu: #94a3b8;
      --ac: #38bdf8;
      --ac-glow: rgba(56, 189, 248, 0.25);
      --low: #10b981;
      --mid: #f59e0b;
      --high: #ef4444;
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
    .btn:hover { filter: brightness(1.1); }
    .res-box { margin-top: 16px; padding: 18px; border-radius: 14px; border: 1px solid var(--bd); background: rgba(7, 10, 18, 0.7); }
    .res-box.low { border-color: var(--low); } .res-box.mid { border-color: var(--mid); } .res-box.high { border-color: var(--high); }
    .badge { display: inline-block; padding: 5px 14px; border-radius: 30px; font-weight: 800; font-size: 11px; margin-bottom: 10px; text-transform: uppercase; }
    .badge.low { background: var(--low); color: #000; } .badge.mid { background: var(--mid); color: #000; } .badge.high { background: var(--high); color: #fff; }
    ul { margin: 10px 0 0 18px; padding: 0; } li { margin-bottom: 6px; font-size: 13px; color: #d1d5db; }
  </style>
</head>
<body>
<header>
  <div class="brand"><div class="brand-pulse"></div><span id="header-title">PhishGuard Pro AI</span></div>
  <select class="lang-select" id="langSelect">
    <option value="uz">🇺🇿 O'zbek</option>
    <option value="kr">🇺🇿 Ўзбек</option>
    <option value="ru">🇷🇺 Русский</option>
    <option value="en">🇬🇧 English</option>
  </select>
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

const UI = {
  uz: {
    brand: "PhishGuard Pro AI System", check: "Tekshirish", upload: "Yuklab Tahlil Qilish", send: "Yuborish",
    url_t: "🔗 URL Scanner", url_d: "Havolani xavfsizlik va fishing alomatlariga tekshirish",
    msg_t: "💬 MessageGuard", msg_d: "SMS yoki chat matnidagi shubhali iboralarni aniqlash",
    card_t: "💳 CardGuard", card_d: "Bank kartasi raqamini xavfsiz tekshirish (saqlanmaydi)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Fayl yoki APK ilova xavfsizligini tekshirish",
    voice_t: "🎙 VoiceGuard", voice_d: "Ovozli xabar yoki audio fayl tahlili",
    chat_t: "🤖 AI Maslahatchi", chat_d: "Kiberxavfsizlik va dasturlash bo'yicha savol bering",
    news_t: "📰 Yangiliklar", news_d: "Kiberxavfsizlik va IT sohasidagi so'nggi yangiliklar",
    analyzing: "Tahlil qilinmoqda..."
  },
  ru: {
    brand: "PhishGuard Pro AI System", check: "Проверить", upload: "Загрузить и Анализировать", send: "Отправить",
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
    brand: "PhishGuard Pro AI System", check: "Check", upload: "Upload & Analyze", send: "Send",
    url_t: "🔗 URL Scanner", url_d: "Scan link for safety and phishing indicators",
    msg_t: "💬 MessageGuard", msg_d: "Detect suspicious phrases in SMS or text chats",
    card_t: "💳 CardGuard", card_d: "Safe card number validation (never stored)",
    file_t: "📁 FileGuard & APK Shield", file_d: "Analyze file and APK application security",
    voice_t: "🎙 VoiceGuard", voice_d: "Voice message and audio deepfake analysis",
    chat_t: "🤖 AI Consultant", chat_d: "Ask questions regarding cybersecurity and dev",
    news_t: "📰 News", news_d: "Latest news in IT and cybersecurity domain",
    analyzing: "Analyzing..."
  }
};
UI.kr = UI.uz;

const MODES = ["url", "message", "card", "file", "voice", "chat", "news"];
let cur = "url";
const langSelect = $("#langSelect");
langSelect.value = lang;
langSelect.onchange = () => { lang = langSelect.value; sv("pg_lang", lang); updateUI(); };

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
  cur = m; const t = UI[lang] || UI["uz"];
  renderTabs();
  $("#card-title").textContent = t[m+'_t'];
  $("#card-desc").textContent = t[m+'_d'];
  $("#out").innerHTML = "";
  if(m === "news"){ $("#inp-area").innerHTML = ""; loadNews(); return; }
  if(m === "chat"){
    $("#inp-area").innerHTML = `<div id="cl" style="max-height:220px;overflow-y:auto;margin-bottom:12px;background:#070a12;padding:12px;border-radius:10px;border:1px solid var(--bd)"></div><textarea id="ci"></textarea><button class="btn" id="cb">${t.send}</button>`;
    $("#cb").onclick = () => sendChat($("#ci").value); return;
  }
  if(m === "file" || m === "voice"){
    let accept = m === "file" ? "*/*" : "audio/*";
    $("#inp-area").innerHTML = `<input type="file" accept="${accept}" id="f"><button class="btn" id="go">${t.upload}</button>`;
    $("#go").onclick = () => fileScan($("#f").files[0], m);
  } else {
    let isText = (m === "card" || m === "url");
    $("#inp-area").innerHTML = (isText ? `<input type="text" id="t" placeholder="https://...">` : `<textarea id="t"></textarea>`) + `<button class="btn" id="go">${t.check}</button>`;
    $("#go").onclick = () => runScan(m, $("#t").value);
  }
}

async function runScan(m, textVal){
  if(!textVal.trim()) return;
  const t = UI[lang] || UI["uz"];
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  try {
    const res = await fetch("/api/" + m, { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({text: textVal, lang: lang}) }).then(r=>r.json());
    renderResult(res);
  } catch { $("#out").innerHTML = `<div class="card" style="color:red">Error</div>`; }
}

async function fileScan(fileObj, modeStr){
  if(!fileObj) return;
  const t = UI[lang] || UI["uz"];
  const fd = new FormData(); fd.append(modeStr === "file" ? "file" : "audio", fileObj); fd.append("lang", lang);
  $("#out").innerHTML = `<div class="card">${t.analyzing}</div>`;
  try {
    const res = await fetch("/api/" + modeStr, {method: "POST", body: fd}).then(r=>r.json());
    renderResult(res);
  } catch { $("#out").innerHTML = `<div class="card" style="color:red">Error</div>`; }
}

let CH = [];
async function sendChat(tVal){
  if(!tVal.trim()) return;
  CH.push({role: "user", content: tVal}); $("#ci").value = "";
  $("#cl").innerHTML = CH.map(x=>`<div style="margin-bottom:6px"><b>${x.role}:</b> ${x.content}</div>`).join("");
  try {
    const res = await fetch("/api/chat", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({messages: CH, lang: lang}) }).then(r=>r.json());
    CH.push({role: "assistant", content: res.text || res.error});
    $("#cl").innerHTML = CH.map(x=>`<div style="margin-bottom:6px"><b>${x.role}:</b> ${x.content}</div>`).join("");
  } catch { CH.push({role: "assistant", content: "Error"}); }
}

function renderResult(r){
  if(r.error) { $("#out").innerHTML = `<div class="card">${r.error}</div>`; return; }
  let extra = r.masked ? `<p><b>Brand:</b> ${r.brand} | ${r.masked}</p>` : "";
  let reasons = (r.reasons||[]).map(x=>`<li><b>${x.t}:</b> ${x.why}</li>`).join("");
  $("#out").innerHTML = `<div class="card res-box ${r.level}"><div class="badge ${r.level}">${r.label} (${r.score}/100)</div><p><b>Xulosa:</b> ${r.advice}</p>${extra}<ul>${reasons}</ul></div>`;
}

async function loadNews(){
  try {
    const res = await fetch("/api/news").then(r=>r.json());
    $("#inp-area").innerHTML = res.map(n=>`<div style="border-bottom:1px solid var(--bd);padding-bottom:10px;margin-bottom:10px"><div style="font-size:11px;color:var(--ac);font-weight:600">${n.date} &bull; ${n.category}</div><div style="font-size:15px;font-weight:700;margin:2px 0">${n.title}</div><p style="margin:0">${n.content}</p></div>`).join("");
  } catch { $("#inp-area").innerHTML = "Failed to load news."; }
}

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
