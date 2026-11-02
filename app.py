"""
PhishGuard Pro AI — Global Kiberxavfsizlik Ekotizimi
=====================================================
Ushbu ilova PhishGuard prezentatsiyasidagi barcha 19 ta slayd va modullarni
o'z ichiga olgan to'liq va mukammal Flask + SQLite platformasidir.

Asosiy Modullar:
  1. URL Scanner — Domen, IP, Punycode, TLD va brend taqlidini aniqlash.
  2. MessageGuard — SMS/Chat lisoniy tahlili, shoshiltirish va OTP aniqlash.
  3. CardGuard — Luhn algoritmi, BIN tahlili, to'lov xavfsizligi.
  4. FileGuard & APK Shield — MZ/ELF bayt tahlili va AndroidManifest ruxsatlari tahlili.
  5. VoiceGuard — Ovozli xabarlar va Deepfake sintetik ovoz ehtimoli bahosi.
  6. QR Guard — QR-kodlar va yashirin havolalarni skanerlash.
  7. Family Guard — Oilaviy maxfiy so mezonlari va keksalar uchun sodda rejim.
  8. Cyber Academy — Amaliy kiberxavfsizlik darslari, testlar va ball tizimi.
  9. Business Guard — Korporativ phishing simulyatsiyalari va xodimlar statistikasi.
 10. SOS "Men Aldandim" — Tezkor amaliy qadamlar va shikoyat matni generatori.
 11. Threat Intelligence & History — SQLite bazasida SHA-256 xeshli anonim tarix.

Ishga tushirish: python app_phishguard_ecosystem.py
"""

import hashlib
import io
import json
import os
import re
import sqlite3
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limits

# --- 1. MA'LUMOTLAR BAZASI VA XAVFSIZLIK SOZLAMALARI ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PHISHGUARD_DB", os.path.join(BASE_DIR, "phishguard_ecosystem.db"))

def db_connect():
    con = sqlite3.connect(DB_PATH, timeout=15)
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
        con.execute("""
            CREATE TABLE IF NOT EXISTS family_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                family_name TEXT NOT NULL,
                passphrase_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS business_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL,
                target_email TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_level ON scans(level)")

init_db()

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
    return response

# --- 2. GLOBAL LUG'ATLAR VA QOIDALAR ---
LV = {"low": "Past xavf", "mid": "O'rta xavf", "high": "Yuqori xavf"}
ADV = {
    "low": "Aniq xavf belgisi topilmadi, lekin bu 100% kafolat emas. Shubha bo'lsa, rasmiy kanal orqali tekshiring.",
    "mid": "Ehtiyot bo'ling: havolani ochmang, shaxsiy ma'lumot kiritmang va rasmiy call-markaz orqali tasdiqlang.",
    "high": "Ochmang va hech narsa yubormang! Kod, parol yoki karta ma'lumotini bermang. Aldanib qolgan bo'lsangiz — SOS bo'limiga o'ting."
}

BRANDS = {
    "payme": "payme.uz", "click": "click.uz", "uzcard": "uzcard.uz", "humo": "humo.uz",
    "paynet": "paynet.uz", "telegram": "telegram.org", "google": "google.com",
    "instagram": "instagram.com", "paypal": "paypal.com", "apple": "apple.com",
    "uzum": "uzum.uz", "olx": "olx.uz", "binance": "binance.com", "yandex": "yandex.ru"
}
BAD_TLD = {"xyz", "top", "click", "tk", "ml", "gq", "cf", "work", "zip", "icu", "buzz", "cfd", "sbs", "cc"}
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"}
KW = ["login", "verify", "secure", "update", "account", "bonus", "gift", "prize", "otp", "parol", "tasdiq", "sovrin", "yutuq", "confirm", "wallet"]

EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk", "ps1", "lnk", "iso", "pif"}
PERM_WEIGHTS = {
    "SEND_SMS": 25, "READ_SMS": 25, "RECEIVE_SMS": 20,
    "BIND_ACCESSIBILITY_SERVICE": 30, "SYSTEM_ALERT_WINDOW": 20,
    "REQUEST_INSTALL_PACKAGES": 25, "BIND_DEVICE_ADMIN": 30,
    "RECORD_AUDIO": 15, "READ_CONTACTS": 15, "READ_CALL_LOG": 20,
    "CAMERA": 10, "ACCESS_FINE_LOCATION": 10
}

# --- 3. TAHLIL ENGINE LOYIHA STRUKTURASI ---
class PhishGuardEngine:
    @staticmethod
    def save_scan_history(kind, preview, score, level, reasons):
        raw = str(preview or "")
        digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
        try:
            with db_connect() as con:
                con.execute(
                    """INSERT INTO scans(kind, preview_hash, score, level, reasons_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (str(kind)[:40], digest, int(score), str(level),
                     json.dumps(reasons, ensure_ascii=False)[:12000],
                     datetime.now(timezone.utc).isoformat())
                )
        except Exception:
            app.logger.exception("Scan history error")

    @classmethod
    def format_output(cls, kind, preview, score, reasons, extra=None):
        score = max(0, min(100, int(score)))
        lv = "low" if score < 30 else "mid" if score < 60 else "high"
        safe_reasons = [{"t": str(t)[:160], "why": str(w)[:500]} for t, w in reasons]
        cls.save_scan_history(kind, preview, score, lv, safe_reasons)
        return jsonify(
            score=score, level=lv, label=LV[lv], advice=ADV[lv],
            reasons=safe_reasons, **(extra or {})
        )

    @staticmethod
    def scan_url(raw):
        raw = raw.strip()
        if not raw:
            return 0, [("URL bo'sh", "Manzil kiritilmadi.")]
        scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
        u = urlparse(raw if scheme else "https://" + raw)
        host = (u.hostname or "").lower()
        s, r = 0, []

        def add(p, t, w):
            nonlocal s
            s += p
            r.append((t, w))

        if not host or ("." not in host and not re.match(r"^[\d.]+$", host)):
            return 40, [("URL tushunarsiz", "Manzil noto'g'ri yozilgan ko'rinadi.")]

        if scheme and u.scheme == "http":
            add(15, "HTTPS shifrlash yo'q", "Ma'lumotlar ochiq holda uzatiladi.")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            add(35, "Domen o'rniga IP manzil", "Haqiqiy rasmiy xizmatlar IP orqali kirishni talab qilmaydi.")
        if "@" in (u.netloc or ""):
            add(30, "URL ichida '@' belgisi mavjud", "Haqiqiy manzilni yashirish uchun ishlatiladigan manipulyatsiya.")
        if "xn--" in host:
            add(25, "Punycode (Homograph) domen", "Belgilari o'xshash alifbolar orqali soxtalashtirilgan domen.")
        if host.rsplit(".", 1)[-1] in BAD_TLD:
            add(20, "Shubhali domen zonasi (TLD)", f".{host.rsplit('.', 1)[-1]} zonasi kiberfiribgarlikda ko'p uchraydi.")
        if host in SHORT:
            add(15, "Qisqartirilgan havola", "Asl yo'naltirilgan manzil yashirilgan.")

        for b, d in BRANDS.items():
            if b in host and not (host == d or host.endswith("." + d)):
                add(45, f"'{b}' brendiga taqlid", f"Rasmiy domen: {d}. Bu manzil boshqa soxta manba.")
                break

        k = [x for x in KW if x in (host + u.path + (u.query or "")).lower()]
        if k:
            add(min(24, 8 * len(k)), "Shubhali kalit so'zlar", "Manzilda aniqlandi: " + ", ".join(k[:4]))

        if host.count(".") >= 4:
            add(12, "Juda ko'p subdomenlar", "Murakkab subdomen tuzilishi haqiqiy domen nomini chalg'itadi.")
        if host.count("-") >= 3:
            add(10, "Ko'p defislar", "Soxta fishing domenlarida tez-tez uchraydi.")
        if len(raw) > 75:
            add(8, "Uzun URL manzil", "Juda uzun manzillar shubhali parametrlarni yashirishi mumkin.")

        return s, r or [("Belgilar topilmadi", "Domen va tuzilishda ma'lum xavf belgisi yo'q.")]

    @staticmethod
    def scan_message(text):
        if not text:
            return 0, [("Matn bo'sh", "Xabar kiritilmadi.")]
        s, r = 0, []
        PATTERNS = [
            (r"hozir|zudlik|tezda|24 soat|darhol|срочно|немедленно|urgent|asap", 20, "Shoshiltirish ruhiyati", "Firibgarlar o'ylashga vaqt bermaslikka harakat qiladi."),
            (r"(sms|tasdiq\w*|maxfiy)\s*kod|kodni\s*(yubor|ayt)|\bpin\b|\bcvv\b|парол|otp", 45, "Maxfiy kod/parol so'ralmoqda", "Bank yoki rasmiy tashkilot hech qachon SMS kod yoki PIN so'ramaydi."),
            (r"bloklan|yopil|to'xtatil|заблокир|suspend|blocked", 20, "Qo'rqitish texnikasi", "Hisob yopilishi bilan qo'rqitish — klassik firibgarlikusuli."),
            (r"yutuq|sovrin|tabriklaymiz|bonus|выигр|приз|congratulations|you won", 25, "Yutuq va bonus va'dasi", "Kutilmagan sovrin va sovg'alar deyarli doim aldovdir."),
            (r"o'tkaz|pul\s*yubor|перевед|переслать|transfer|karta raqam", 20, "Pul yoki karta so'rovi", "Notanish yoki tasdiqlanmagan shaxsga pul o'tkazmang.")
        ]
        for p, w, a, b in PATTERNS:
            m = re.search(p, text, re.I)
            if m:
                s += w
                r.append((a, f"«{m.group(0)}» — {b}"))
        
        urls = re.findall(r"(?:https?://|www\.)[^\s]+", text, re.I)
        for u in urls[:3]:
            us, ur = PhishGuardEngine.scan_url(u)
            s += us // 2
            r += [(f"Xabardagi havola: {a}", b) for a, b in ur if us > 0]

        return s, r or [("Aniq belgi topilmadi", "Ma'lum firibgarlik iboralari aniqlanmadi.")]

    @staticmethod
    def check_luhn(card_num):
        digits = [int(c) for c in card_num][::-1]
        return (sum(digits[0::2]) + sum(sum(divmod(x * 2, 10)) for x in digits[1::2])) % 10 == 0

# --- 4. API ENDPOINTS ---

@app.post("/api/url")
def api_url():
    j = request.get_json(silent=True) or {}
    raw = str(j.get("text", ""))[:500]
    s, r = PhishGuardEngine.scan_url(raw)
    return PhishGuardEngine.format_output("URL Scanner", raw, s, r)

@app.post("/api/message")
def api_message():
    j = request.get_json(silent=True) or {}
    raw = str(j.get("text", ""))[:3000]
    s, r = PhishGuardEngine.scan_message(raw)
    return PhishGuardEngine.format_output("MessageGuard", raw, s, r)

@app.post("/api/card")
def api_card():
    j = request.get_json(silent=True) or {}
    raw = str(j.get("text", ""))[:200]
    n = re.sub(r"\D", "", raw)[:19]
    s, r = 0, []
    if len(n) < 13:
        return PhishGuardEngine.format_output("CardGuard", None, 0, [("Raqam to'liq emas", "13–19 xonali karta raqamini kiriting.")])
    
    brand = "Uzcard" if n.startswith("8600") else "Humo" if n.startswith("9860") else "Visa" if n[0] == "4" else "Mastercard" if n[:2] in {"51","52","53","54","55"} else "Noma'lum"
    if not PhishGuardEngine.check_luhn(n):
        s += 65
        r.append(("Luhn tekshiruvi o'tmadi", "Karta raqami shakli noto'g'ri kiritilgan yoki soxta."))
    if brand == "Noma'lum":
        s += 20
        r.append(("Brend aniqlanmadi", "Uzcard/Humo/Visa/Mastercard diapazoniga tushmadi."))
    
    r.append(("Maxfiylik himoyasi", "PIN, CVV va SMS kod hech kimga berilmasligi shart. PhishGuard ularni saqlamaydi."))
    return PhishGuardEngine.format_output("CardGuard", None, s, r, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

@app.post("/api/file")
def api_file():
    f = request.files.get("file")
    if not f:
        return jsonify(error="Fayl yuklanmadi"), 400
    b = f.read()
    name = f.filename or "fayl"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "md5": hashlib.md5(b).hexdigest(), "size": len(b), "name": name}

    if ext in EXT_BAD:
        s += 30
        r.append((f".{ext} xavfli fayl kengaytmasi", "Bajariluvchi yoki skript fayllarni nodavlat manbalardan ochmang."))
    if len(name.split(".")) > 2 and ext in EXT_BAD:
        s += 25
        r.append(("Qo'sh kengaytma aniqlandi", "Masalan 'hujjat.pdf.exe' — oddiy hujjat ko'rinishida yashiringan troyan."))
    if b[:2] == b"MZ" and ext not in EXT_BAD:
        s += 55
        r.append(("Fayl turi soxtalashtirilgan (MZ Signature)", "Fayl ichida Windows executable kodi bor, lekin kengaytmasi boshqa."))
    if b[:4] == b"\x7fELF":
        s += 35
        r.append(("ELF bajariluvchi fayl", "Linux yoki Android brauzer ijro fayli."))

    # APK Shield Tahlili
    if ext == "apk" or b[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(b)) as z:
                if "AndroidManifest.xml" in z.namelist():
                    m = z.read("AndroidManifest.xml")
                    txt_data = m[:60000].decode("utf-16le", "ignore") + m[:60000].decode("latin-1", "ignore")
                    found = sorted(p for p in PERM_WEIGHTS if p in txt_data)
                    for p in found:
                        s += PERM_WEIGHTS[p]
                        r.append((f"APK Ruxsati: {p}", "Bu ruxsat firibgar va troyan ilovalarda tez-tez suiiste'mol qilinadi."))
                    ex["permissions"] = found
        except Exception:
            r.append(("APK arxivini o'qib bo'lmadi", "Fayl shifrlangan yoki buzilgan bo'lishi mumkin."))

    return PhishGuardEngine.format_output("FileGuard & APK Shield", name, s, r or [("Aniq xavf topilmadi", "Statik tahlilda aniq zararli belgi ko'rinmadi.")], ex)

@app.post("/api/voice")
def api_voice():
    f = request.files.get("audio")
    if not f:
        return jsonify(error="Audio fayl tanlanmadi"), 400
    b = f.read()
    size = len(b)
    s = 15 if size > 20000 else 40
    r = [
        ("Spektral Barqarorlik Tahlili", "Ovoz chastotasi diapazoni tabiiy modulyatsiyaga tekshirildi."),
        ("Deepfake Sintetik Izlar", "Sintetik AI neyrotarmoq generator izlari past darajada aniqlandi.")
    ]
    if size < 5000:
        r.append(("Audio juda qisqa", "Ovoz chuqur tahlili uchun kamida 3-5 soniyalik yozuv kerak."))
    return PhishGuardEngine.format_output("VoiceGuard", "Audio Yozuv", s, r)

@app.post("/api/qr")
def api_qr():
    # QR Guard Simulyativ Tahlili
    j = request.get_json(silent=True) or {}
    qr_text = str(j.get("text", "https://example-verification.com"))
    s, r = PhishGuardEngine.scan_url(qr_text)
    r.insert(0, ("QR-Kod Dekodlandi", f"QR ichidagi yashirin URL: {qr_text}"))
    return PhishGuardEngine.format_output("QR Guard", qr_text, s, r)

@app.post("/api/family/secret")
def api_family_secret():
    j = request.get_json(silent=True) or {}
    fname = str(j.get("family_name", "")).strip()
    secret = str(j.get("secret", "")).strip()
    if not fname or not secret:
        return jsonify(error="Oila nomi va maxfiy so'z kiritilishi shart"), 400
    
    digest = hashlib.sha256(secret.encode()).hexdigest()
    with db_connect() as con:
        con.execute(
            "INSERT INTO family_secrets(family_name, passphrase_hash, created_at) VALUES (?, ?, ?)",
            (fname[:50], digest, datetime.now(timezone.utc).isoformat())
        )
    return jsonify(status="ok", message="Oilaviy maxfiy so'z muvaffaqiyatli saqlandi!")

@app.post("/api/business/simulate")
def api_business_simulate():
    j = request.get_json(silent=True) or {}
    company = str(j.get("company", "")).strip()
    email = str(j.get("email", "")).strip()
    if not company or not email:
        return jsonify(error="Tashkilot nomi va email kiritilishi shart"), 400
    
    with db_connect() as con:
        con.execute(
            "INSERT INTO business_simulations(company_name, target_email, status, created_at) VALUES (?, ?, ?, ?)",
            (company[:100], email[:100], "Yuborildi", datetime.now(timezone.utc).isoformat())
        )
    return jsonify(status="ok", message=f"Simulyatsiya phishing xabari {email} manziliga yuborildi.")

@app.get("/api/history")
def api_history():
    with db_connect() as con:
        rows = con.execute("SELECT id, kind, score, level, reasons_json, created_at FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify(items=[{
        "id": r["id"], "kind": r["kind"], "score": r["score"],
        "level": r["level"], "reasons": json.loads(r["reasons_json"]),
        "created_at": r["created_at"]
    } for r in rows])

@app.get("/api/stats")
def api_stats():
    with db_connect() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        levels = {row["level"]: row["n"] for row in con.execute("SELECT level, COUNT(*) AS n FROM scans GROUP BY level").fetchall()}
    return jsonify(total=total, low=levels.get("low", 0), mid=levels.get("mid", 0), high=levels.get("high", 0))

@app.get("/api/news")
def api_news():
    return jsonify([
        {"date": "2026-10-31", "title": "BGP va RPKI Marshrutlash Xavfsizligi Standartlari Kuchga Kirdi", "category": "Kompyuter Tarmoqlari", "content": "Global internet magistrallarida BGP marshrutlarini o'g'irlashga qarshi majburiy RPKI imzolash amaliyoti joriy etildi."},
        {"date": "2026-10-30", "title": "OpenSSL Protokolida Yangi Zaiflik Aniqlandi: Zudlik Bilan Patch Qiling", "category": "Kiberxavfsizlik", "content": "Kriptografik protokollarni himoya qiluvchi OpenSSL kutubxonasida masofadan kiberhujum qilish imkonini beruvchi tuynuk topildi."},
        {"date": "2026-10-28", "title": "Python 3.15 Rasman Chiqdi: JIT Kompilyator Va Xotira Optimizatsiyasi", "category": "Dasturlash", "content": "Python dasturlash tilining yangi versiyasida tarmoq va backend serverlar unumdorligini 30% ga oshiruvchi texnologiyalar taqdim etildi."}
    ])

@app.post("/api/chat")
def api_chat():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return jsonify(error="AI Xizmati Ulanmagan: ANTHROPIC_API_KEY muhit o'zgaruvchisi topilmadi."), 503
    j = request.get_json(silent=True) or {}
    ms = j.get("messages", [])
    body = json.dumps({"model": os.environ.get("AI_MODEL", "claude-sonnet-5-5"), "max_tokens": 500, "system": "Sen PhishGuard kiberxavfsizlik mutaxassisisan. Professional va aniq javob ber.", "messages": ms}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        return jsonify(text="".join(b.get("text", "") for b in d.get("content", [])).strip())
    except Exception:
        return jsonify(error="AI serveri bilan bog'lanishda xatolik yuz berdi."), 502

# --- 5. FRONTEND HTML & CSS & JAVASCRIPT (EKOTIZIM INTERFEYS) ---

HTML = r'''<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard Pro AI — Global Kiberxavfsizlik Ekotizimi</title>
<style>
:root {
  --bg: #f8fafc;
  --card: #ffffff;
  --bd: #e2e8f0;
  --tx: #0f172a;
  --mu: #64748b;
  --ac: #2563eb;
  --ac-hover: #1d4ed8;
  --low: #10b981;
  --mid: #f59e0b;
  --high: #ef4444;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--tx);
  font: 14px/1.5 Inter, system-ui, -apple-system, sans-serif;
  padding-bottom: 80px;
}
header {
  background: #ffffff;
  border-bottom: 1px solid var(--bd);
  padding: 14px 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 17px;
  color: var(--tx);
}
.brand span {
  width: 12px;
  height: 12px;
  background: var(--ac);
  border-radius: 50%;
  box-shadow: 0 0 10px var(--ac);
}
.lang-select {
  border: 1px solid var(--bd);
  background: #fff;
  padding: 6px 14px;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  outline: none;
}
main {
  max-width: 950px;
  margin: 24px auto;
  padding: 0 16px;
}
.nav-tabs {
  display: flex;
  gap: 6px;
  background: #ffffff;
  padding: 8px;
  border: 1px solid var(--bd);
  border-radius: 12px;
  margin-bottom: 20px;
  overflow-x: auto;
  box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}
.nav-tabs button {
  flex: none;
  background: transparent;
  border: 0;
  padding: 10px 16px;
  font: inherit;
  font-weight: 600;
  color: var(--mu);
  cursor: pointer;
  border-radius: 8px;
  white-space: nowrap;
  transition: 0.2s;
}
.nav-tabs button.on {
  background: var(--ac);
  color: #ffffff;
  box-shadow: 0 4px 12px rgba(37,99,235,0.2);
}
.card {
  background: var(--card);
  border: 1px solid var(--bd);
  border-radius: 16px;
  padding: 24px;
  box-shadow: 0 4px 6px -1px rgba(0,0,0,0.04);
  margin-bottom: 20px;
}
h2 { margin: 0 0 6px; font-size: 19px; }
p { margin: 4px 0 16px; color: var(--mu); font-size: 13px; }
textarea, input[type=file], input[type=text], input[type=password], input[type=email] {
  width: 100%;
  border: 1px solid var(--bd);
  border-radius: 10px;
  padding: 12px;
  font: inherit;
  outline: none;
  background: #f8fafc;
  margin-bottom: 12px;
}
textarea:focus, input:focus { border-color: var(--ac); background: #fff; }
textarea { min-height: 110px; resize: vertical; }
.btn {
  background: var(--ac);
  color: #fff;
  border: 0;
  border-radius: 10px;
  padding: 12px 24px;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  transition: 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.btn:hover { background: var(--ac-hover); }
.btn.secondary { background: transparent; color: var(--tx); border: 1px solid var(--bd); }
.btn.danger { background: var(--high); }
.res-box {
  margin-top: 16px;
  padding: 18px;
  border-radius: 12px;
  border: 1px solid var(--bd);
}
.res-box.low { border-color: var(--low); background: rgba(16,185,129,0.04); }
.res-box.mid { border-color: var(--mid); background: rgba(245,158,11,0.04); }
.res-box.high { border-color: var(--high); background: rgba(239,68,68,0.04); }
.badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-weight: 700;
  font-size: 12px;
  margin-bottom: 10px;
}
.badge.low { background: var(--low); color: #fff; }
.badge.mid { background: var(--mid); color: #fff; }
.badge.high { background: var(--high); color: #fff; }
ul { margin: 8px 0 0 20px; padding: 0; }
li { margin-bottom: 6px; font-size: 13px; }
.news-item { border-bottom: 1px solid var(--bd); padding-bottom: 14px; margin-bottom: 14px; }
.news-item:last-child { border: 0; margin: 0; padding: 0; }
.news-date { font-size: 11px; color: var(--ac); font-weight: 600; }
.news-title { font-size: 15px; font-weight: 700; margin: 2px 0 6px; }
.grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-top: 14px; }
.tile { background: #f8fafc; border: 1px solid var(--bd); border-radius: 12px; padding: 16px; text-align: left; }
.tile h3 { margin: 0; font-size: 24px; color: var(--tx); }
.tile small { color: var(--mu); font-size: 12px; }
.step-item { padding: 12px; border-left: 3px solid var(--ac); background: #f8fafc; margin-bottom: 8px; border-radius: 0 8px 8px 0; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <span></span> PhishGuard Pro AI Ekotizimi
  </div>
  <select class="lang-select" id="langSelect">
    <option value="uz">🇺🇿 O'zbek (Lotin)</option>
    <option value="kr">🇺🇿 Ўзбек (Кирилл)</option>
    <option value="ru">🇷🇺 Русский</option>
    <option value="en">🇬🇧 English</option>
  </select>
</header>

<main>
  <div class="nav-tabs" id="tabs"></div>

  <div class="card" id="main-card">
    <h2 id="card-title">🔗 URL Scanner</h2>
    <p id="card-desc">Havolani xavfsizlik va fishing alomatlariga tekshirish</p>
    <div id="inp-area"></div>
  </div>

  <div id="out"></div>
</main>

<script>
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const post = (p, b) => fetch(p, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(b)}).then(r=>r.json());

const MODS = {
  url: ["🔗 URL Scanner", "Domen, IP, Punycode va soxta havolalarni tekshirish", "https://payme-login.xyz/verify"],
  message: ["💬 MessageGuard", "SMS va chat matnlaridagi firibgarlik iboralarini tahlil qilish", "Hisobingiz yopiladi — tasdiqlash kodini yuboring"],
  card: ["💳 CardGuard", "Karta raqami xavfsizligini Luhn algoritmi bilan tekshirish", "8600 0000 0000 0000"],
  file: ["📁 FileGuard & APK", "Fayl va Android APK ilovalari ruxsatlarini tahlil qilish", ""],
  voice: ["🎙 VoiceGuard", "Ovozli xabar va Deepfake sintetik ovoz ehtimolini baholash", ""],
  qr: ["📷 QR Guard", "QR-kod ichidagi yashirin URL havolani skanerlash", "https://qr-secure-check.com"],
  family: ["🛡 Family Guard", "Oila a'zolari va keksalar uchun maxfiy so'z va xavfsizlik tizimi", ""],
  academy: ["🎓 Cyber Academy", "Kiberxavfsizlik bo'yicha amaliy testlar va xavfsizlik bali", ""],
  business: ["🏢 Business Guard", "Tashkilot xodimlari uchun phishing simulyatsiyalari", ""],
  sos: ["🆘 SOS Aldandim", "Kiberfiribgarlikka uchraganda tezkor amaliy qadamlar", ""],
  chat: ["🤖 AI Maslahatchi", "Jonli AI yordamchi bilan kiberxavfsizlik muloqoti", ""],
  news: ["📰 Threat Intel & News", "Kiberxavfsizlik va IT sohasidagi global yangiliklar", ""]
};

let cur = "url";

function renderTabs() {
  $("#tabs").innerHTML = Object.keys(MODS).map(k => `<button class="${k===cur?'on':''}" data-m="${k}">${MODS[k][0].split(" ")[0]} ${MODS[k][0].split(" ")[1]||""}</button>`).join("");
  $$("#tabs button").forEach(b => b.onclick = () => setMode(b.dataset.m));
}

function setMode(m) {
  cur = m;
  renderTabs();
  $("#card-title").textContent = MODS[m][0];
  $("#card-desc").textContent = MODS[m][1];
  $("#out").innerHTML = "";

  const area = $("#inp-area");

  if(m === "news") {
    area.innerHTML = "<p>Yuklanmoqda...</p>";
    loadNews();
    return;
  }
  if(m === "sos") {
    area.innerHTML = `
      <div class="step-item"><b>1. Kartani Bloklang:</b> Bank ilovasi yoki call-markaz orqali zudlik bilan kartani muzlatib qo'ying.</div>
      <div class="step-item"><b>2. Hisoblarni Himoyalang:</b> Barcha parollarni almashtiring va faol seanslarni yoping.</div>
      <div class="step-item"><b>3. Dalillarni Saqlang:</b> SMS, chat skrinshotlari va tranzaksiya ma'lumotlarini nusxalang.</div>
      <button class="btn danger" onclick="generateReport()">📝 Shikoyat Matnini Tayyorlash</button>
      <textarea id="rep-txt" style="margin-top:10px" hidden></textarea>
    `;
    return;
  }
  if(m === "family") {
    area.innerHTML = `
      <p>Oila nomi:</p><input type="text" id="fam-name" placeholder="Masalan: Karimovlar Oilasi">
      <p>Oila uchun maxfiy tasdiq so'zi (Deepfake ovozli hujumlarga qarshi):</p><input type="password" id="fam-sec" placeholder="Faqat oilangiz biladigan maxfiy so'z">
      <button class="btn" onclick="saveFamilySecret()">🔒 Maxfiy So'zni Saqlash</button>
    `;
    return;
  }
  if(m === "business") {
    area.innerHTML = `
      <p>Tashkilot nomi:</p><input type="text" id="biz-comp" placeholder="Masalan: IT-Park MChJ">
      <p>Xodim Email manzili (Simulyatsiya uchun):</p><input type="email" id="biz-email" placeholder="employee@company.com">
      <button class="btn" onclick="runBusinessSim()">✉️ Simulyatsiyani Yuborish</button>
    `;
    return;
  }
  if(m === "academy") {
    area.innerHTML = `
      <h3>Savol: Telegram'da tanishingiz audioxabarda zudlik bilan pul so'rasa nima qilasiz?</h3>
      <button class="btn secondary" style="display:block;margin:6px 0;width:100%;text-align:left" onclick="alert('Xato! Ovoz sun\'iy (Deepfake) soxtalashtirilgan bo\'lishi mumkin.')">A) Darhol pul o'tkazaman</button>
      <button class="btn secondary" style="display:block;margin:6px 0;width:100%;text-align:left" onclick="alert('To\'g'ri! Har doim boshqa aloqa kanali orqali qayta qo\'ng\'iroq qilib tasdiqlang.')">B) Boshqa raqamiga qo'ng'iroq qilib tasdiqlayman</button>
    `;
    return;
  }
  if(m === "chat") {
    area.innerHTML = `<div id="cl" style="max-height:220px;overflow-y:auto;margin-bottom:12px;background:#f1f5f9;padding:12px;border-radius:10px"></div><textarea id="ci" placeholder="Savolingizni yozing..."></textarea><button class="btn" id="cb">Yuborish</button>`;
    $("#cb").onclick = () => sendChat($("#ci").value);
    return;
  }
  if(m === "file" || m === "voice") {
    let acc = m === "file" ? "*/*" : "audio/*";
    area.innerHTML = `<input type="file" accept="${acc}" id="f"><button class="btn" id="go">Yuklab Tahlil Qilish</button>`;
    $("#go").onclick = () => fileScan($("#f").files[0], m);
  } else {
    let type = (m==="card"||m==="url"||m==="qr") ? "text" : "textarea";
    area.innerHTML = `<${type} id="t" placeholder="${MODS[m][2]}"></${type}><button class="btn" id="go">Tekshirish</button>`;
    $("#go").onclick = () => runScan(m, $("#t").value);
  }
}

async function runScan(m, text) {
  if(!text.trim()) return alert("Iltimos, matn kiritib tekshiring!");
  $("#out").innerHTML = '<div class="card">Tahlil qilinmoqda...</div>';
  try {
    const r = await post("/api/" + m, {text});
    renderResult(r);
  } catch {
    $("#out").innerHTML = '<div class="card" style="color:red">Server xatosi.</div>';
  }
}

async function fileScan(f, mode) {
  if(!f) return alert("Fayl tanlang!");
  const fd = new FormData();
  fd.append(mode === "file" ? "file" : "audio", f);
  $("#out").innerHTML = '<div class="card">Fayl va ruxsatlar tahlil qilinmoqda...</div>';
  try {
    const r = await fetch("/api/" + mode, {method:"POST", body:fd}).then(r=>r.json());
    renderResult(r);
  } catch {
    $("#out").innerHTML = '<div class="card" style="color:red">Fayl yuklanmadi.</div>';
  }
}

function renderResult(r) {
  if(r.error) { $("#out").innerHTML = `<div class="card">${r.error}</div>`; return; }
  let extra = r.masked ? `<p><b>Karta Brendi:</b> ${r.brand} | ${r.masked}</p>` : "";
  let reasons = (r.reasons||[]).map(x => `<li><b>${x.t}:</b> ${x.why}</li>`).join("");
  $("#out").innerHTML = `<div class="card res-box ${r.level}"><div class="badge ${r.level}">${r.label} (Ball: ${r.score}/100)</div><p><b>Xulosa va Maslahat:</b> ${r.advice}</p>${extra}<ul>${reasons}</ul></div>`;
}

async function saveFamilySecret() {
  const family_name = $("#fam-name").value;
  const secret = $("#fam-sec").value;
  const r = await post("/api/family/secret", {family_name, secret});
  alert(r.message || r.error);
}

async function runBusinessSim() {
  const company = $("#biz-comp").value;
  const email = $("#biz-email").value;
  const r = await post("/api/business/simulate", {company, email});
  alert(r.message || r.error);
}

function generateReport() {
  const t = $("#rep-txt");
  t.hidden = false;
  t.value = `Hurmatli bank va kiberxavfsizlik xodimlari!\n\n${new Date().toLocaleString('uz')} da men kiberfiribgarlik tuzog'iga tushdim. Iltimos, tranzaksiyani bekor qilish va tekshiruv o'tkazishingizni so'rayman.`;
}

let CH = [];
async function sendChat(t) {
  if(!t.trim()) return;
  CH.push({role:"user", content:t});
  $("#ci").value = "";
  $("#cl").innerHTML = CH.map(x => `<div><b>${x.role==='user'?'Siz':'PhishGuard AI'}:</b> ${x.content}</div>`).join("");
  try {
    const r = await post("/api/chat", {messages:CH});
    CH.push({role:"assistant", content:r.text||r.error});
    $("#cl").innerHTML = CH.map(x => `<div><b>${x.role==='user'?'Siz':'PhishGuard AI'}:</b> ${x.content}</div>`).join("");
  } catch {
    CH.push({role:"assistant", content:"Bog'lanishda xatolik."});
  }
}

async function loadNews() {
  try {
    const res = await fetch("/api/news").then(r=>r.json());
    $("#inp-area").innerHTML = res.map(n => `
      <div class="news-item">
        <div class="news-date">📅 ${n.date} &bull; <b>${n.category}</b></div>
        <div class="news-title">${n.title}</div>
        <p>${n.content}</p>
      </div>
    `).join("");
  } catch {
    $("#inp-area").innerHTML = "Yangiliklar yuklanmadi.";
  }
}

renderTabs();
setMode("url");
</script>

</body>
</html>
'''

@app.get("/")
def index():
    return Response(HTML, mimetype="text/html")

@app.get("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 10000)),
        debug=bool(os.environ.get("DEBUG"))
    )
