"""PhishGuard — Kiberxavfsizlik, IT yangiliklar va AI yordamchi ilovasi (Flask + Google Gemini). Ishga tushirish: python app.py"""
import hashlib, io, json, os, re, zipfile
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request
from google import genai

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

LV = {"low": "Past xavf", "mid": "O'rta xavf", "high": "Yuqori xavf"}
ADV = {
    "low": "Aniq xavf belgisi topilmadi, lekin bu kafolat emas. Shubha bo'lsa, rasmiy kanal orqali tekshiring.",
    "mid": "Ehtiyot bo'ling: havolani ochmang, ma'lumot kiritmang, rasmiy ilova yoki call-markaz orqali tekshiring.",
    "high": "Ochmang va hech narsa yubormang. Kod, parol yoki karta ma'lumotini bermang. Aldanib qolgan bo'lsangiz — SOS bo'limiga o'ting."
}

def out(kind, preview, score, reasons, extra=None):
    score = max(0, min(100, score))
    lv = "low" if score < 30 else "mid" if score < 60 else "high"
    return jsonify(score=score, level=lv, label=LV[lv], advice=ADV[lv], reasons=[{"t": t, "why": w} for t, w in reasons], **(extra or {}))

BRANDS = {"payme": "payme.uz", "click": "click.uz", "uzcard": "uzcard.uz", "humo": "humo.uz", "paynet": "paynet.uz", "telegram": "telegram.org",
          "google": "google.com", "instagram": "instagram.com", "paypal": "paypal.com", "apple": "apple.com", "uzum": "uzum.uz", "olx": "olx.uz"}
BAD_TLD = {"xyz", "top", "click", "tk", "ml", "gq", "cf", "work", "zip", "icu", "buzz", "cfd", "sbs"}
SHORT = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"}
KW = ["login", "verify", "secure", "update", "account", "bonus", "gift", "prize", "otp", "parol", "tasdiq", "sovrin", "yutuq", "confirm", "wallet"]

def txt(n):
    j = request.get_json(silent=True)
    v = j.get("text", "") if isinstance(j, dict) else ""
    return v[:n] if isinstance(v, str) else str(v or "")[:n]

def scan_url(raw):
    try: return _scan_url(raw)
    except Exception: return 0, [("URL tushunarsiz", "Manzil noto'g'ri yozilgan.")]

def _scan_url(raw):
    raw = raw.strip(); scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    u = urlparse(raw if scheme else "https://" + raw); host = (u.hostname or "").lower(); s, r = 0, []
    def add(p, t, w): nonlocal s; s += p; r.append((t, w))
    if not host or "." not in host and not re.match(r"^[\d.]+$", host): return 0, [("URL tushunarsiz", "Manzil noto'g'ri yozilgan ko'rinadi.")]
    if scheme and u.scheme == "http": add(15, "HTTPS yo'q", "Ma'lumot shifrlanmagan holda uzatiladi.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host): add(30, "Domen o'rniga IP manzil", "Rasmiy xizmatlar odatda IP orqali ishlamaydi.")
    if "@" in (u.netloc or ""): add(25, "URL ichida '@' belgisi", "Haqiqiy manzilni yashirish uchun ishlatiladi.")
    if "xn--" in host: add(25, "Punycode domen", "Shakli o'xshash harflar bilan soxta domen bo'lishi mumkin.")
    if host.rsplit(".", 1)[-1] in BAD_TLD: add(15, "Shubhali domen zonasi", "Bu zonalar firibgarlikda ko'p uchraydi.")
    if host in SHORT: add(15, "Qisqartirilgan havola", "Haqiqiy manzil yashirilgan, ochishdan oldin kengaytirib tekshiring.")
    for b, d in BRANDS.items():
        if b in host and not (host == d or host.endswith("." + d)):
            add(40, f"'{b}' brendiga taqlid", f"Rasmiy domen: {d}. Bu manzil boshqa sayt."); break
    k = [x for x in KW if x in (host + u.path + (u.query or "")).lower()]
    if k: add(min(24, 8 * len(k)), "Shubhali so'zlar", "Manzilda: " + ", ".join(k[:4]))
    if host.count(".") >= 4: add(10, "Juda ko'p subdomen", "Murakkab manzil — haqiqiy domen oxirgi ikki qismda.")
    if host.count("-") >= 3: add(8, "Ko'p defis", "Soxta domenlarda tez-tez uchraydi.")
    if len(raw) > 75: add(8, "Juda uzun URL", "Uzun manzillar shubhali qismlarni yashirishi mumkin.")
    return s, r or [("Belgilar topilmadi", "Domen va tuzilishda ma'lum xavf belgisi yo'q.")]

PAT = [(r"hozir|zudlik|tezda|24 soat|darhol|срочно|немедленно|сейчас|urgent|immediately|asap", 20, "Shoshiltirish", "Firibgarlar o'ylashga vaqt bermaydi."),
       (r"(sms|tasdiq\w*|maxfiy)\s*kod|kodni\s*(yubor|ayt)|\bpin\b|\bcvv\b|парол|код\s*из\s*смс|otp|parolni", 40, "Maxfiy kod/parol so'ralmoqda", "Bank hech qachon kod yoki PIN so'ramaydi."),
       (r"bloklan|yopil|to'xtatil|заблокир|suspend|blocked", 20, "Qo'rqitish", "Hisob yopilishi bilan qo'rqitish — klassik usul."),
       (r"yutuq|sovrin|tabriklaymiz|bonus|выигр|приз|congratulations|you won|prize", 25, "Yutuq va'dasi", "Kutilmagan sovrin xabarlari deyarli doim aldov."),
       (r"o'tkaz|pul\s*yubor|перевед|переслать|transfer|karta raqam|номер карты", 20, "Pul yoki karta so'rovi", "Notanish odamga pul/karta ma'lumoti yubormang."),
       (r"https?://|www\.|t\.me/|bit\.ly", 10, "Havola mavjud", "Xabardagi havolani ochishdan oldin tekshiring.")]

@app.post("/api/url")
def api_url():
    t = txt(500); s, r = scan_url(t); return out("URL", t, s, r)

@app.post("/api/message")
def api_msg():
    t = txt(3000); s, r = 0, []
    for p, w, a, b in PAT:
        m = re.search(p, t, re.I)
        if m: s += w; r.append((a, f"«{m.group(0)}» — {b}"))
    for u in re.findall(r"(?:https?://|www\.)[^\s]+", t, re.I)[:3]:
        us, ur = scan_url(u); s += us // 2
        r += [("Havola: " + a, b) for a, b in ur if us]
    return out("Xabar", t, s, r or [("Belgilar topilmadi", "Ma'lum firibgarlik iboralari aniqlanmadi.")])

def luhn(n):
    d = [int(c) for c in n][::-1]
    return (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0

@app.post("/api/card")
def api_card():
    t = txt(200); n = re.sub(r"\D", "", t)[:19]; s, r = 0, []
    if len(n) < 13: return out("Karta", None, 0, [("Raqam to'liq emas", "13–19 xonali karta raqamini kiriting.")])
    brand = "Uzcard" if n.startswith("8600") else "Humo" if n.startswith("9860") else "Visa" if n[0] == "4" else "Mastercard" if n[:2] in {"51", "52", "53", "54", "55"} else "Noma'lum"
    if not luhn(n): s += 60; r.append(("Luhn tekshiruvi o'tmadi", "Raqam haqiqiy karta emas yoki xato kiritilgan."))
    if brand == "Noma'lum": s += 20; r.append(("Brend aniqlanmadi", "Uzcard/Humo/Visa/Mastercard emas."))
    r.append(("Eslatma", "PIN, CVV va SMS kodni hech kimga bermang — PhishGuard ham ularni saqlamaydi."))
    return out("Karta", None, s, r, {"masked": n[:4] + " **** **** " + n[-4:], "brand": brand})

EXT_BAD = {"exe", "scr", "bat", "cmd", "js", "vbs", "jar", "msi", "apk", "ps1", "lnk", "iso"}
PERM = {"SEND_SMS": 20, "READ_SMS": 20, "RECEIVE_SMS": 15, "BIND_ACCESSIBILITY_SERVICE": 25, "SYSTEM_ALERT_WINDOW": 15,
        "REQUEST_INSTALL_PACKAGES": 20, "BIND_DEVICE_ADMIN": 25, "RECORD_AUDIO": 8, "READ_CONTACTS": 8, "READ_CALL_LOG": 12}

@app.post("/api/file")
def api_file():
    f = request.files.get("file")
    if not f: return jsonify(error="Fayl yo'q"), 400
    b = f.read(); name = f.filename or "fayl"; ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""; s, r = 0, []
    ex = {"sha256": hashlib.sha256(b).hexdigest(), "md5": hashlib.md5(b).hexdigest(), "size": len(b), "name": name}
    if ext in EXT_BAD: s += 25; r.append((f".{ext} bajariladigan/xavfli tur", "Bunday fayllarni ishonchsiz manbadan ochmang."))
    if len(name.split(".")) > 2 and ext in EXT_BAD: s += 25; r.append(("Qo'sh kengaytma", "Masalan 'hujjat.pdf.exe' — oddiy hujjat kabi ko'rsatilgan."))
    if b[:2] == b"MZ" and ext not in EXT_BAD: s += 50; r.append(("Fayl turi yolg'on", "Ichida Windows dasturlash qismi bor, lekin kengaytma boshqacha."))
    if b[:4] == b"\x7fELF": s += 30; r.append(("ELF bajariladigan fayl", "Linux/Android ijro fayli."))
    if ext == "apk" or (b[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in b[:200000]):
        try:
            z = zipfile.ZipFile(io.BytesIO(b)); m = z.read("AndroidManifest.xml")
            txt_data = m.decode("utf-16le", "ignore") + m.decode("latin-1")
            found = sorted(p for p in PERM if p in txt_data)
            for p in found: s += PERM[p]; r.append((f"Ruxsat: {p}", "Bu ruxsat xavfli APK ilovalarda suiiste'mol qilinadi."))
            ex["permissions"] = found
        except Exception: r.append(("APK o'qilmadi", "Fayl buzilgan yoki himoyalangan bo'lishi mumkin."))
    return out("Fayl", name, s, r or [("Aniq belgi topilmadi", "Hech bir skaner mutlaq xavfsizlikni kafolatlamaydi.")], ex)

@app.get("/api/news")
def api_news():
    return jsonify([
        {
            "date": "2026-10-24",
            "title": "OpenSSL'da yangi kritik zaiflik aniqlandi: tarmoq administratorlari shoshilinch yangilanishlari shart",
            "category": "Kiberxavfsizlik",
            "content": "Kriptografik protokollarni himoya qiluvchi OpenSSL kutubxonasida masofadan turib kod bajarishga olib keluvchi xavfsizlik oshig'i topildi. Server va kompyuter tarmoqlari administratorlaridan tarmoqni zudlik bilan patch qilish talab etilmoqda."
        },
        {
            "date": "2026-10-23",
            "title": "Python 3.15 rasman e'lon qilindi: yangi JIT kompilyator va xotirani optimizatsiyalash usullari",
            "category": "Dasturlash / IT",
            "content": "Dasturchilar uchun eng ommabop bo'lgan Python tilining yangi versiyasi chiqdi. U dastur bajarilish tezligini sezilarli darajada oshiruvchi hamda tarmoq dasturlarini yozishni osonlashtiruvchi yangi funksiyalarni o'z ichiga oladi."
        },
        {
            "date": "2026-10-22",
            "title": "BGP marshrutlash protokollarida xavfsizlikni ta'minlash bo'yicha yangi xalqaro standartlar kuchga kirdi",
            "category": "Kompyuter tarmoqlari",
            "content": "Global internet magistrallarida ma'lumotlar oqimini yo'naltiruvchi BGP (Border Gateway Protocol) xavfsizligini oshirish maqsadida RPKI (Resource Public Key Infrastructure) imzolash jarayoni majburiy tus ola boshladi."
        },
        {
            "date": "2026-10-21",
            "title": "IT mutaxassislari uchun ingliz tili: Texnik hujjatlar va RFC spetsifikatsiyalarini o'qish sirlari",
            "category": "Til va Texnologiya",
            "content": "Dasturlash va kiberxavfsizlik sohasida muvaffaqiyat qozonish uchun faqat kod yozish yetarli emas. Xalqaro RFC standartlari va texnik qo'llanmalarni ingliz tilida mukammal tushunish dasturchining eng asosiy ko'nikmasidir."
        }
    ])

LANGS = {"uz": " Javob tili: o'zbek.", "kr": " Javob tili: o'zbek (kirill).", "ru": " Язык ответа: русский.", "en": " Reply in English.", "tr": " Türkçe yanıt ver."}
SYS = "Sen PhishGuard kiberxavfsizlik, dasturlash va kompyuter tarmoqlari bo'yicha mutaxassis va yordamchisan. Qisqa, professional va aniq maslahat ber."

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

@app.post("/api/ai")
def api_ai():
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return jsonify(error="AI yo'qilmagan: GEMINI_API_KEY o'rnatilmagan."), 503
    j = request.get_json(silent=True) or {}
    msg = f"Tahlil natijasi: {json.dumps(j.get('result'), ensure_ascii=False)}\nMatn: {j.get('text', '')}"
    sys_instruction = SYS + LANGS.get(j.get("lang"), "")
    model_name = os.environ.get("AI_MODEL", "gemini-2.5-flash")
    try:
        response = client.models.generate_content(
            model=model_name,
            contents=msg,
            config=genai.types.GenerateContentConfig(
                system_instruction=sys_instruction,
                max_output_tokens=400,
            )
        )
        return jsonify(text=response.text)
    except Exception as e:
        return jsonify(error=f"AI bilan bog'lanishda xatolik: {str(e)}"), 502

HTML = r'''<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>PhishGuard</title><link rel="manifest" href="/manifest.json"><link rel="icon" href="/icon.svg"><meta name="theme-color" content="#0b1020">
<style>
:root{--bg:#0b1020;--card:rgba(255,255,255,0.06);--bd:rgba(255,255,255,0.12);--tx:#e8ecf8;--mu:#93a0c4;--ac:#5eead4;--ac2:#818cf8;--low:#34d399;--mid:#fbbf24;--high:#f87171}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#312e8144,transparent),radial-gradient(700px 400px at -10% 10%,#0d948844,transparent),var(--bg);color:var(--tx);font:15px/1.5 Inter,system-ui,sans-serif;min-height:100vh;padding-bottom:90px}
header{padding:16px 20px;max-width:760px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:14px;border-bottom:1px solid var(--bd);background:rgba(11,16,32,0.85);backdrop-filter:blur(10px);position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:12px}header img{width:38px;height:38px;border-radius:12px;box-shadow:0 0 15px rgba(94,234,212,0.3)}header b{font-size:18px;letter-spacing:-0.5px}header span{color:var(--mu);font-size:11px;display:block}
.lang-select{background:rgba(94,234,212,0.1);border:1px solid var(--ac);color:var(--ac);padding:6px 12px;border-radius:10px;font-size:12px;font-weight:600;cursor:pointer;outline:none;transition:0.2s}.lang-select option{background:#0b1020;color:var(--tx)}
main{max-width:760px;margin:auto;padding:16px}section[hidden]{display:none}
.card{background:var(--card);border:1px solid var(--bd);border-radius:20px;padding:20px;margin:14px 0;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,0.3)}
h2{margin:6px 0 6px;font-size:22px;letter-spacing:-0.5px}h3{margin:0 0 10px;font-size:16px}p{margin:6px 0;color:var(--mu)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}
.tile{background:rgba(255,255,255,0.04);border:1px solid var(--bd);border-radius:16px;padding:16px;text-align:left;color:var(--tx);cursor:pointer;font:inherit;transition:all 0.2s ease}.tile:hover{border-color:var(--ac);background:rgba(94,234,212,0.06);transform:translateY(-2px)}.tile i{font-size:24px;font-style:normal;display:block;margin-bottom:8px}.tile small{color:var(--mu);display:block;margin-top:2px}
.tabs{display:flex;gap:6px;overflow-x:auto;padding-bottom:8px}.tabs button{white-space:nowrap;border:1px solid var(--bd);background:transparent;color:var(--mu);padding:8px 16px;border-radius:99px;font:inherit;cursor:pointer;transition:0.2s}.tabs button.on{background:var(--ac);color:#04201c;border-color:var(--ac);font-weight:600}
textarea,input[type=file],input[type=number]{width:100%;background:rgba(0,0,0,0.3);border:1px solid var(--bd);border-radius:14px;color:var(--tx);padding:14px;font:inherit;margin:10px 0;outline:none}textarea:focus,input:focus{border-color:var(--ac)}textarea{min-height:120px;resize:vertical}
.btn{background:linear-gradient(135deg,var(--ac),var(--ac2));color:#06121f;border:0;border-radius:14px;padding:14px 22px;font:inherit;font-weight:700;cursor:pointer;margin-top:8px;box-shadow:0 4px 20px rgba(94,234,212,0.2)}.btn.g{background:transparent;color:var(--tx);border:1px solid var(--bd)}
.res{display:flex;gap:16px;align-items:center}.ring{--c:var(--low);width:96px;height:96px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,0.1) 0);display:grid;place-items:center;flex:none}.ring b{width:76px;height:76px;border-radius:50%;background:#101733;display:grid;place-items:center;font-size:24px}
.mid{--c:var(--mid)}.high{--c:var(--high)}.lbl{font-weight:700;font-size:20px;color:var(--c)}
.rs{margin:12px 0 0;padding:0;list-style:none}.rs li{padding:12px 14px;border-left:3px solid var(--c);background:rgba(255,255,255,0.03);border-radius:0 12px 12px 0;margin:8px 0}.rs b{display:block;margin-bottom:2px}.rs span{color:var(--mu);font-size:14px}
code{word-break:break-all;font-size:12px;color:var(--ac);background:rgba(0,0,0,0.4);padding:2px 6px;border-radius:6px}
nav{position:fixed;bottom:0;left:0;right:0;display:flex;justify-content:center;gap:4px;padding:10px 12px calc(10px + env(safe-area-inset-bottom));background:rgba(11,16,32,0.85);backdrop-filter:blur(20px);
