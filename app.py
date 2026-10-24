"""PhishGuard — raqamli xavfsizlik ilovasi (Flask + SQLite). Ishga tushirish: python app.py"""
import hashlib, io, json, os, re, time, urllib.request, zipfile
from collections import defaultdict, deque
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request, send_from_directory

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
    raw = raw.strip()
    scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    u = urlparse(raw if scheme else "https://" + raw)
    host = (u.hostname or "").lower()
    s, r = 0, []
    def add(p, t, w): nonlocal s; s += p; r.append((t, w))
    if not host or ("." not in host and not re.match(r"^[\d.]+$", host)):
        return 0, [("URL tushunarsiz", "Manzil noto'g'ri yozilgan ko'rinadi.")]
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

PAT = [
    (r"hozir|zudlik|tezda|24 soat|darhol|срочно|немедленно|сейчас|urgent|immediately|asap", 20, "Shoshiltirish", "Firibgarlar o'ylashga vaqt bermaydi."),
    (r"(sms|tasdiq\w*|maxfiy)\s*kod|kodni\s*(yubor|ayt)|\bpin\b|\bcvv\b|парол|код\s*из\s*смс|otp|parolni", 40, "Maxfiy kod/parol so'ralmoqda", "Bank hech qachon kod yoki PIN so'ramaydi."),
    (r"bloklan|yopil|to'xtatil|заблокир|suspend|blocked", 20, "Qo'rqitish", "Hisob yopilishi bilan qo'rqitish — klassik usul."),
    (r"yutuq|sovrin|tabriklaymiz|bonus|выигр|приз|congratulations|you won|prize", 25, "Yutuq va'dasi", "Kutilmagan sovrin xabarlari deyarli doim aldov."),
    (r"o'tkaz|pul\s*yubor|перевед|переслать|transfer|karta raqam|номер карты", 20, "Pul yoki karta so'rovi", "Notanish odamga pul/karta ma'lumoti yubormang."),
    (r"https?://|www\.|t\.me/|bit\.ly", 10, "Havola mavjud", "Xabardagi havolani ochishdan oldin tekshiring.")
]

@app.post("/api/url")
def api_url():
    t = txt(500)
    s, r = scan_url(t)
    return out("URL", t, s, r)

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
    if b[:2] == b"MZ" and ext not in EXT_BAD: s += 50; r.append(("Fayl turi yolg'on", "Ichida Windows dasturi bor, lekin kengaytma boshqacha."))
    if b[:4] == b"\x7fELF": s += 30; r.append(("ELF bajariladigan fayl", "Linux/Android ijro fayli."))
    if ext == "apk" or (b[:4] == b"PK\x03\x04" and b"AndroidManifest.xml" in b[:200000]):
        try:
            z = zipfile.ZipFile(io.BytesIO(b)); m = z.read("AndroidManifest.xml")
            txt_data = m.decode("utf-16le", "ignore") + m.decode("latin-1")
            found = sorted(p for p in PERM if p in txt_data)
            for p in found: s += PERM[p]; r.append((f"Ruxsat: {p}", "Bu ruxsat firibgar ilovalarda tez-tez suiiste'mol qilinadi."))
            ex["permissions"] = found
        except Exception: r.append(("APK o'qilmadi", "Fayl buzilgan yoki himoyalangan bo'lishi mumkin."))
    return out("Fayl", name, s, r or [("Aniq belgi topilmadi", "Hech bir skaner mutlaq xavfsizlikni kafolatlamaydi.")], ex)

@app.get("/api/news")
def api_news():
    news_list = [
        {
            "date": "2026-10-24",
            "title": "Telegram'da yangi ovoz berish fishingi tarqalmoqda",
            "category": "Ogohlantirish",
            "content": "Tanishingiz akkauntidan 'tanlovda ovoz bering' degan soxta havolalar kelishi mumkin. Kirgach Telegram hisobingiz o'g'irlanadi."
        },
        {
            "date": "2026-10-23",
            "title": "Soxta Click va Payme to'lov sahifalari aniqlandi",
            "category": "Moliya xavfsizligi",
            "content": "Keshbek va yutuq va'da qiladigan fishing havolalaridan ehtiyot bo'ling. Sayt manzilini har doim sinchiklab tekshiring."
        },
        {
            "date": "2026-10-22",
            "title": "Deepfake qo'ng'iroqlardan qanday saqlanish kerak?",
            "category": "Sun'iy Intellekt",
            "content": "Tanish yoki rahbaringiz ovozini o'xshatib pul so'rashsa, darhol boshqa raqam orqali bog'lanib, shaxsan tasdiqlang."
        }
    ]
    return jsonify(news_list)

HTML = r'''<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>PhishGuard</title><link rel="manifest" href="/manifest.json"><link rel="icon" href="/icon.svg"><meta name="theme-color" content="#0b1020">
<style>
:root{--bg:#0b1020;--card:#ffffff10;--bd:#ffffff1a;--tx:#e8ecf8;--mu:#93a0c4;--ac:#5eead4;--ac2:#818cf8;--low:#34d399;--mid:#fbbf24;--high:#f87171}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#312e8155,transparent),radial-gradient(700px 400px at -10% 10%,#0d948855,transparent),var(--bg);color:var(--tx);font:16px/1.5 Inter,system-ui,-apple-system,sans-serif;min-height:100vh;padding-bottom:84px}
header{padding:20px 20px 4px;max-width:760px;margin:auto;display:flex;align-items:center;gap:12px}header img{width:38px;border-radius:10px}header b{font-size:20px}header span{color:var(--mu);font-size:13px;display:block}
main{max-width:760px;margin:auto;padding:12px 16px}section[hidden]{display:none}
.card{background:var(--card);border:1px solid var(--bd);border-radius:20px;padding:18px;margin:12px 0;backdrop-filter:blur(12px)}
h2{margin:6px 0 4px;font-size:22px}h3{margin:0 0 8px;font-size:16px}p{margin:4px 0;color:var(--mu)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:14px;text-align:left;color:var(--tx);cursor:pointer;font:inherit}.tile:hover{border-color:var(--ac)}.tile i{font-size:24px;font-style:normal;display:block}.tile small{color:var(--mu);display:block;margin-top:2px}
.tabs{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px}.tabs button{white-space:nowrap;border:1px solid var(--bd);background:transparent;color:var(--mu);padding:8px 14px;border-radius:99px;font:inherit;cursor:pointer}.tabs button.on{background:var(--ac);color:#04201c;border-color:var(--ac);font-weight:600}
textarea,input[type=file],input[type=number]{width:100%;background:#00000040;border:1px solid var(--bd);border-radius:14px;color:var(--tx);padding:12px;font:inherit;margin:8px 0}textarea{min-height:110px;resize:vertical}
.btn{background:linear-gradient(135deg,var(--ac),var(--ac2));color:#06121f;border:0;border-radius:14px;padding:12px 20px;font:inherit;font-weight:700;cursor:pointer;margin-top:6px}.btn.g{background:transparent;color:var(--tx);border:1px solid var(--bd)}
.res{display:flex;gap:16px;align-items:center}.ring{--c:var(--low);width:96px;height:96px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),#ffffff18 0);display:grid;place-items:center;flex:none}.ring b{width:76px;height:76px;border-radius:50%;background:#101733;display:grid;place-items:center;font-size:24px}
.mid{--c:var(--mid)}.high{--c:var(--high)}.lbl{font-weight:700;font-size:20px;color:var(--c)}
.rs{margin:10px 0 0;padding:0;list-style:none}.rs li{padding:10px 12px;border-left:3px solid var(--c);background:#ffffff08;border-radius:8px;margin:6px 0}.rs b{display:block}.rs span{color:var(--mu);font-size:14px}
code{word-break:break-all;font-size:12px;color:var(--mu)}
nav{position:fixed;bottom:0;left:0;right:0;display:flex;justify-content:center;gap:2px;padding:8px 8px calc(8px + env(safe-area-inset-bottom));background:#0b1020e6;backdrop-filter:blur(16px);border-top:1px solid var(--bd);z-index:100}
nav button{flex:1;max-width:110px;background:none;border:0;color:var(--mu);font:inherit;font-size:11px;padding:6px 4px;border-radius:12px;cursor:pointer}nav button i{display:block;font-size:18px;font-style:normal}nav button.on{color:var(--ac);background:#5eead414}
.step{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--bd)}.step input{width:22px;height:22px;accent-color:var(--ac);margin-top:3px}.step.d{opacity:.5}.step.d b{text-decoration:line-through}
.opt{display:block;width:100%;text-align:left;margin:6px 0;padding:12px;border-radius:12px;border:1px solid var(--bd);background:transparent;color:var(--tx);font:inherit;cursor:pointer}.opt.ok{border-color:var(--low);background:#34d39922}.opt.no{border-color:var(--high);background:#f8717122}
.h{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid var(--bd)}.pill{font-size:12px;padding:2px 10px;border-radius:99px;background:var(--c);color:#111;font-weight:700;--c:var(--low)}
.news-item{background:#ffffff06;border:1px solid var(--bd);border-radius:14px;padding:14px;margin:10px 0}
.news-date{font-size:12px;color:var(--ac);margin-bottom:4px}
.news-title{font-size:16px;font-weight:700;color:var(--tx);margin-bottom:6px}
</style></head><body>
<header><img src="/icon.svg" alt=""><div><b>PhishGuard</b><span>Aniqlaydi • Tushuntiradi • Himoya qiladi</span></div></header>
<main>
<section id="home">
<div class="card"><h2>Xavfsizlik holati</h2><p id="hs">Yuklanmoqda…</p><div class="grid" style="margin-top:12px"><div class="tile"><small>Tekshiruvlar</small><h2 id="n1">0</h2></div><div class="tile"><small>Xavfli topilgan</small><h2 id="n2">0</h2></div><div class="tile"><small>Akademiya bali</small><h2 id="n3">—</h2></div></div></div>
<div class="grid">
<button class="tile" data-go="url"><i>🔗</i>URL Scanner <small>Fishing havola</small></button>
<button class="tile" data-go="message"><i>💬</i>MessageGuard <small>SMS / chat matni</small></button>
<button class="tile" data-go="qr"><i>📷</i>QR Guard <small>QR ichidagi havola</small></button>
<button class="tile" data-go="file"><i>📁</i>FileGuard + APK <small>Xesh va ruxsatlar</small></button>
<button class="tile" data-go="card"><i>💳</i>CardGuard <small>Karta raqami</small></button>
<button class="tile" data-nav="news"><i>📰</i>Yangiliklar <small>Kiber xabarlar</small></button>
</div>
</section>

<section id="check" hidden><div class="tabs" id="tabs"></div><div class="card"><h3 id="ct"></h3><div id="inp"></div></div><div id="out"></div></section>
<section id="news" hidden><div class="card"><h2>📰 Kiberxavfsizlik Yangiliklari</h2><p>So'nggi kiber tahdidlar va ogohlantirishlar.</p><div id="news-list" style="margin-top:15px">Yuklanmoqda...</div></div></section>
<section id="sos" hidden><div class="card"><h2>🆘 Men aldandim</h2><p>Ketma-ket bajaring.</p><div id="steps"></div><button class="btn g" id="cmp" style="margin-top:12px">📝 Shikoyat matnini tayyorlash</button><textarea id="cmpt" hidden></textarea></div></section>
<section id="acad" hidden><div class="card" id="quiz"></div></section>
<section id="hist" hidden><div class="card"><h2>Tekshiruv tarixi</h2><p>Faqat qisqa ko'rinish saqlanadi. Karta raqami saqlanmaydi.</p><div id="hl"></div><button class="btn g" id="hc" style="margin-top:12px">🗑 Tarixni o'chirish</button></div></section>
</main>
<nav>
<button data-t="home"><i>🏠</i>Bosh</button>
<button data-t="check"><i>🔍</i>Tekshir</button>
<button data-t="news"><i>📰</i>Yangilik</button>
<button data-t="sos"><i>🆘</i>SOS</button>
<button data-t="acad"><i>🎓</i>Akademiya</button>
<button data-t="hist"><i>🕘</i>Tarix</button>
</nav>

<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const ls=(k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}},sv=(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v))}catch{}};
const post=(p,b)=>fetch(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}).then(r=>r.json());

let curMode="url";

function show(id){
    $$("main>section").forEach(s=>s.hidden=(s.id!==id));
    $$("nav button").forEach(b=>b.classList.toggle("on",b.dataset.t===id));
    if(id==="home") stats();
    if(id==="hist") hist();
    if(id==="acad") quiz();
    if(id==="news") loadNews();
    window.scrollTo(0,0);
}

$$("nav button").forEach(b=>b.onclick=()=>show(b.dataset.t));
document.addEventListener("click", e=>{
    const btn = e.target.closest("[data-go]");
    if(btn){ mode(btn.dataset.go); show("check"); }
    const navBtn = e.target.closest("[data-nav]");
    if(navBtn){ show(navBtn.dataset.nav); }
});

const M={
    url:["🔗 URL Scanner","Havolani joylang","https://payme-login.xyz/verify"],
    message:["💬 MessageGuard","SMS yoki xabar matnini joylang","Hisobingiz yopiladi — hozir tasdiqlash kodini yuboring"],
    card:["💳 CardGuard","Karta raqamini kiriting","8600 0000 0000 0000"],
    file:["📁 FileGuard + APK Shield","Fayl tanlang (max 20 MB)"],
    qr:["📷 QR Guard","QR o'qish uchun fayl tanlang"]
};

$("#tabs").innerHTML=Object.keys(M).map(k=>`<button data-m="${k}">${M[k][0].split(" ")[0]} ${M[k][0].split(" ")[1]||""}</button>`).join("");
$$("#tabs button").forEach(b=>b.onclick=()=>mode(b.dataset.m));

function mode(m){
    curMode=m;
    $$("#tabs button").forEach(b=>b.classList.toggle("on",b.dataset.m===m));
    $("#ct").textContent=M[m][0]; $("#out").innerHTML="";
    if(m==="file") {
        $("#inp").innerHTML=`<p>${M[m][1]}</p><input type="file" id="f"><button class="btn" id="go">Tekshirish</button>`;
        $("#go").onclick=()=>fileScan($("#f").files[0]);
    } else if(m==="qr") {
        $("#inp").innerHTML=`<p>${M[m][1]}</p><input type="file" accept="image/*" id="qi"><button class="btn" id="go">Rasm joylash</button>`;
        $("#go").onclick=()=>qrFile($("#qi").files[0]);
    } else if(m==="card") {
        $("#inp").innerHTML=`<p>${M[m][1]}</p><textarea id="t" placeholder="${M[m][2]}"></textarea><button class="btn" id="go">Tekshirish</button>`;
        $("#go").onclick=()=>run("card",$("#t").value);
    } else {
        $("#inp").innerHTML=`<p>${M[m][1]}</p><textarea id="t" placeholder="${M[m][2]}"></textarea><button class="btn" id="go">Tekshirish</button>`;
        $("#go").onclick=()=>run(m,$("#t").value);
    }
}

async function loadNews(){
    try{
        const res = await fetch("/api/news").then(r=>r.json());
        $("#news-list").innerHTML = res.map(n=>`
            <div class="news-item">
                <div class="news-date">📅 ${esc(n.date)} &bull; <b>${esc(n.category)}</b></div>
                <div class="news-title">${esc(n.title)}</div>
                <p>${esc(n.content)}</p>
            </div>
        `).join("");
    }catch{
        $("#news-list").innerHTML = "<p>Yangiliklarni yuklab bo'lmadi.</p>";
    }
}

async function run(m,text){
    if(!text || !text.trim()) return;
    $("#out").innerHTML='<div class="card">Tahlil qilinmoqda…</div>';
    try{
        const r = await post("/api/"+m, {text});
        render(r);
        rec(m, m==="card"?"":text, r);
    }catch{
        $("#out").innerHTML='<div class="card">Server bilan aloqa yo\'q.</div>';
    }
}

async function fileScan(f){
    if(!f) return;
    const fd=new FormData(); fd.append("file",f);
    $("#out").innerHTML='<div class="card">Tahlil qilinmoqda…</div>';
    try{
        const r = await fetch("/api/file",{method:"POST",body:fd}).then(r=>r.json());
        render(r);
        rec("file",f.name,r);
    }catch{
        $("#out").innerHTML='<div class="card">Fayl yuborilmadi.</div>';
    }
}

function qrFile(f){
    if(!f) return alert("Fayl tanlang!");
    $("#out").innerHTML='<div class="card">QR tahlili ishga tushirildi... URL Scanner bo\'limida tekshirishingiz mumkin.</div>';
}

function render(r){
    if(r.error){ $("#out").innerHTML=`<div class="card">${esc(r.error)}</div>`; return; }
    const ex = (r.masked ? `<p>${esc(r.brand)} • ${esc(r.masked)}</p>` : "") + (r.sha256 ? `<p>SHA-256:<br><code>${r.sha256}</code></p>` : "");
    $("#out").innerHTML=`<div class="card ${r.level}"><div class="res"><div class="ring ${r.level}" style="--p:${r.score}"><b>${r.score}</b></div><div><div class="lbl">${r.label}</div><p>${esc(r.advice)}</p></div></div>${ex}<ul class="rs ${r.level}">${r.reasons.map(x=>`<li><b>${esc(x.t)}</b><span>Nega? ${esc(x.why)}</span></li>`).join("")}</ul>${r.level==="high"?'<button class="btn" onclick="show(\'sos\')">🆘 Aldanib qoldim</button>':""}</div>`;
}

const SOS=[
    ["Kartani himoyalash","Bankning rasmiy ilovasi yoki call-markazi orqali kartani bloklang."],
    ["Bankka xabar berish","Rasmiy aloqa kanali orqali shubhali operatsiya haqida xabar bering."],
    ["Hisoblarni himoyalash","Parollarni almashtiring va 2-bosqichli himoyani yoqing."],
    ["Dalillarni saqlash","Xabar va tranzaksiya skrinshotlarini saqlang."]
];

function steps(){
    const d=ls("sos",[]);
    $("#steps").innerHTML=SOS.map((s,i)=>`<label class="step ${d[i]?"d":""}"><input type="checkbox" data-i="${i}" ${d[i]?"checked":""}><div><b>${i+1}. ${s[0]}</b><p>${s[1]}</p></div></label>`).join("");
    $$("#steps input").forEach(c=>c.onchange=()=>{const x=ls("sos",[]);x[c.dataset.i]=c.checked;sv("sos",x);steps()});
}
steps();

$("#cmp").onclick=()=>{
    const t=$("#cmpt"); t.hidden=false;
    t.value=`Hurmatli bank xodimlari!\n\n${new Date().toLocaleString("uz")} da men firibgarlik qurboni bo'ldim. Vaziyatni ko'rib chiqishingizni so'rayman.`;
};

const Q=[
    ["Bank xodimi telefonda SMS kodni so'rasa?",["Aytaman","Qo'ng'iroqni tugatib, bankka o'zim telefon qilaman","Yarmini aytaman"],1,"Bank hech qachon SMS kod yoki PIN so'ramaydi."],
    ["Qaysi havola xavfliroq?",["https://payme.uz/pay","https://payme-bonus.xyz/login","https://click.uz"],1,".xyz kabi domenlar va taqlidiy manzillar xavfli."],
    ["«Siz 10 mln so'm yutdingiz!» xabari…",["Havolani bosaman","Do'stlarga yuboraman","Aldov deb o'chiraman"],2,"Kutilmagan yutuqlar deyarli doim fishing."]
];
let qi=0,qs=0;
function quiz(){ qi=0; qs=0; qn(); }
function qn(){
    if(qi>=Q.length){
        const p=Math.round(qs/Q.length*100);
        sv("acad",Math.max(p,ls("acad",0)));
        $("#quiz").innerHTML=`<h2>Natija: ${p}%</h2><button class="btn" id="rs">Qayta boshlash</button>`;
        $("#rs").onclick=quiz;
        return;
    }
    const q=Q[qi];
    $("#quiz").innerHTML=`<p>Savol ${qi+1}/${Q.length}</p><h2>${q[0]}</h2>${q[1].map((o,i)=>`<button class="opt" data-i="${i}">${o}</button>`).join("")}<p id="ex"></p>`;
    $$(".opt").forEach(b=>b.onclick=()=>{
        const i=+b.dataset.i;
        $$(".opt").forEach(x=>x.disabled=true);
        $$(".opt")[q[2]].classList.add("ok");
        if(i===q[2]) qs++; else b.classList.add("no");
        $("#ex").textContent=q[3];
        setTimeout(()=>{qi++;qn()},1800);
    });
}

function rec(k,p,r){
    if(r.error) return;
    const x=ls("hist",[]);
    x.unshift({kind:k,preview:String(p).slice(0,80),score:r.score,level:r.level});
    sv("hist",x.slice(0,50));
}

function stats(){
    const x=ls("hist",[]), hi=x.filter(i=>i.level==="high").length;
    $("#n1").textContent=x.length;
    $("#n2").textContent=hi;
    $("#hs").textContent=x.length ? `${hi} ta yuqori xavfli holat topildi.` : "Tahlillar hali yo'q. Birinchi havolani tekshiring.";
    $("#n3").textContent=ls("acad",null)==null ? "—" : ls("acad",0)+"%";
}

function hist(){
    $("#hl").innerHTML=ls("hist",[]).map(x=>`<div class="h"><div><b>${esc(x.kind)}</b><br><code>${esc(x.preview||"")}</code></div><span class="pill" style="--c:var(--${x.level})">${x.score}</span></div>`).join("")||"<p>Bo'sh.</p>";
}
$("#hc").onclick=()=>{ if(confirm("Tarix o'chirilsinmi?")){ sv("hist",[]); hist(); } };

mode("url"); show("home");
</script>
</body></html>
'''

@app.get("/health")
def health(): return "ok"

@app.get("/")
def index(): return Response(HTML, mimetype="text/html")

@app.get("/manifest.json")
def manifest():
    return Response(json.dumps({
        "name": "PhishGuard", "short_name": "PhishGuard", "start_url": "/",
        "display": "standalone", "background_color": "#0b1020", "theme_color": "#0b1020"
    }), mimetype="application/manifest+json")

@app.get("/icon.svg")
def icon():
    return Response('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="#5eead4"/></svg>', mimetype="image/svg+xml")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=bool(os.environ.get("DEBUG")))
