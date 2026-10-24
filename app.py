"""PhishGuard — raqamli xavfsizlik ilovasi (Flask + SQLite). Ishga tushirish: python app.py"""
import hashlib, io, os, re, time, zipfile
from collections import defaultdict, deque
from urllib.parse import urlparse
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

LV = {"low": "Past xavf", "mid": "O'rta xavf", "high": "Yuqori xavf"}
ADV = {"low": "Aniq xavf belgisi topilmadi, lekin bu kafolat emas. Shubha bo'lsa, rasmiy kanal orqali tekshiring.",
       "mid": "Ehtiyot bo'ling: havolani ochmang, ma'lumot kiritmang, rasmiy ilova yoki call-markaz orqali tekshiring.",
       "high": "Ochmang va hech narsa yubormang. Kod, parol yoki karta ma'lumotini bermang. Aldanib qolgan bo'lsangiz — SOS bo'limiga o'ting."}

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
    except ValueError: return 0, [("URL tushunarsiz", "Manzil noto'g'ri yozilgan (masalan, ochilmagan qavs).")]

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
    t = txt(500)
    s, r = scan_url(t); return out("URL", t, s, r)

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
def api_card():  # karta raqami, CVV, PIN hech qachon saqlanmaydi
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

@app.post("/api/file")  # fayl hech qachon ishga tushirilmaydi — faqat bayt sifatida o'qiladi
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
            manifest_txt = m.decode("utf-16le", "ignore") + m.decode("latin-1")
            found = sorted(p for p in PERM if p in manifest_txt)
            for p in found: s += PERM[p]; r.append((f"Ruxsat: {p}", "Bu ruxsat firibgar ilovalarda tez-tez suiiste'mol qilinadi."))
            ex["permissions"] = found
        except Exception: r.append(("APK o'qilmadi", "Fayl buzilgan yoki himoyalangan bo'lishi mumkin."))
    return out("Fayl", name, s, r or [("Aniq belgi topilmadi", "Hech bir skaner mutlaq xavfsizlikni kafolatlamaydi.")], ex)

HTML = r'''<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>PhishGuard</title><link rel="manifest" href="/manifest.json"><link rel="icon" href="/icon.svg"><meta name="theme-color" content="#0b1020">
<style>
:root{--bg:#0b1020;--card:#ffffff10;--bd:#ffffff1a;--tx:#e8ecf8;--mu:#93a0c4;--ac:#5eead4;--ac2:#818cf8;--low:#34d399;--mid:#fbbf24;--high:#f87171}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(900px 500px at 80% -10%,#312e8155,transparent),radial-gradient(700px 400px at -10% 10%,#0d948855,transparent),var(--bg);color:var(--tx);font:16px/1.5 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;min-height:100vh;padding-bottom:84px}
header{padding:20px 20px 4px;max-width:760px;margin:auto;display:flex;align-items:center;gap:12px}header img{width:38px;border-radius:10px}header b{font-size:20px}header span{color:var(--mu);font-size:13px;display:block}
main{max-width:760px;margin:auto;padding:12px 16px}section[hidden]{display:none}
.card{background:var(--card);border:1px solid var(--bd);border-radius:20px;padding:18px;margin:12px 0;backdrop-filter:blur(12px)}
h2{margin:6px 0 4px;font-size:22px}h3{margin:0 0 8px;font-size:16px}p{margin:4px 0;color:var(--mu)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:14px;text-align:left;color:var(--tx);cursor:pointer;font:inherit}.tile:hover{border-color:var(--ac)}.tile i{font-size:24px;font-style:normal;display:block}.tile small{color:var(--mu)}
.tabs{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px}.tabs button{white-space:nowrap;border:1px solid var(--bd);background:transparent;color:var(--mu);padding:8px 14px;border-radius:99px;font:inherit;cursor:pointer}.tabs button.on{background:var(--ac);color:#04201c;border-color:var(--ac);font-weight:600}
textarea,input[type=file]{width:100%;background:#00000040;border:1px solid var(--bd);border-radius:14px;color:var(--tx);padding:12px;font:inherit;margin:8px 0}textarea{min-height:110px;resize:vertical}
.btn{background:linear-gradient(135deg,var(--ac),var(--ac2));color:#06121f;border:0;border-radius:14px;padding:12px 20px;font:inherit;font-weight:700;cursor:pointer}.btn.g{background:transparent;color:var(--tx);border:1px solid var(--bd)}
.res{display:flex;gap:16px;align-items:center}.ring{--c:var(--low);width:96px;height:96px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),#ffffff18 0);display:grid;place-items:center;flex:none}.ring b{width:76px;height:76px;border-radius:50%;background:#101733;display:grid;place-items:center;font-size:24px}
.mid{--c:var(--mid)}.high{--c:var(--high)}.lbl{font-weight:700;font-size:20px;color:var(--c)}
.rs{margin:10px 0 0;padding:0;list-style:none}.rs li{padding:10px 12px;border-left:3px solid var(--c);background:#ffffff08;border-radius:8px;margin:6px 0}.rs b{display:block}.rs span{color:var(--mu);font-size:14px}
code{word-break:break-all;font-size:12px;color:var(--mu)}
nav{position:fixed;bottom:0;left:0;right:0;display:flex;justify-content:center;gap:2px;padding:8px 8px calc(8px + env(safe-area-inset-bottom));background:#0b1020e6;backdrop-filter:blur(16px);border-top:1px solid var(--bd)}
nav button{flex:1;max-width:120px;background:none;border:0;color:var(--mu);font:inherit;font-size:12px;padding:6px;border-radius:12px;cursor:pointer}nav button i{display:block;font-size:20px;font-style:normal}nav button.on{color:var(--ac);background:#5eead414}
.step{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--bd)}.step input{width:22px;height:22px;accent-color:var(--ac);margin-top:3px}.step.d{opacity:.5}.step.d b{text-decoration:line-through}
.opt{display:block;width:100%;text-align:left;margin:6px 0;padding:12px;border-radius:12px;border:1px solid var(--bd);background:transparent;color:var(--tx);font:inherit;cursor:pointer}.opt.ok{border-color:var(--low);background:#34d39922}.opt.no{border-color:var(--high);background:#f8717122}
.h{display:flex;justify-content:space-between;gap:10px;padding:10px 0;border-bottom:1px solid var(--bd)}.pill{font-size:12px;padding:2px 10px;border-radius:99px;background:var(--c);color:#111;font-weight:700;--c:var(--low)}
video{width:100%;border-radius:14px;margin-top:8px}
</style></head><body>
<header><img src="/icon.svg" alt=""><div><b>PhishGuard</b><span>Aniqlaydi • Tushuntiradi • Harakatga yo'naltiradi</span></div></header>
<main>
<section id="home"><div class="card"><h2>Xavfsizlik holati</h2><p id="hs">Yuklanmoqda…</p><div class="grid" style="margin-top:12px"><div class="tile"><small>Tekshiruvlar</small><h2 id="n1">0</h2></div><div class="tile"><small>Xavfli topilgan</small><h2 id="n2">0</h2></div><div class="tile"><small>Akademiya bali</small><h2 id="n3">—</h2></div></div></div>
<div class="grid"><button class="tile" data-go="url"><i>🔗</i>URL Scanner<small>Fishing havola</small></button><button class="tile" data-go="message"><i>💬</i>MessageGuard<small>SMS / chat matni</small></button><button class="tile" data-go="qr"><i>📷</i>QR Guard<small>QR ichidagi havola</small></button><button class="tile" data-go="file"><i>📁</i>FileGuard + APK<small>Xesh va ruxsatlar</small></button><button class="tile" data-go="card"><i>💳</i>CardGuard<small>Karta raqami</small></button><button class="tile" data-nav="sos"><i>🆘</i>SOS<small>Men aldandim</small></button></div></section>

<section id="check" hidden><div class="tabs" id="tabs"></div><div class="card"><h3 id="ct"></h3><div id="inp"></div></div><div id="out"></div></section>

<section id="sos" hidden><div class="card"><h2>🆘 Men aldandim</h2><p>Ketma-ket bajaring. PhishGuard pulni qaytarishni kafolatlamaydi va bank nomidan harakat qilmaydi.</p><div id="steps"></div><button class="btn g" id="cmp" style="margin-top:12px">📝 Shikoyat matnini tayyorlash</button><textarea id="cmpt" hidden></textarea></div></section>

<section id="acad" hidden><div class="card" id="quiz"></div></section>

<section id="hist" hidden><div class="card"><h2>Tekshiruv tarixi</h2><p>Faqat qisqa ko'rinish saqlanadi. Karta raqami saqlanmaydi.</p><div id="hl"></div><button class="btn g" id="hc" style="margin-top:12px">🗑 Tarixni o'chirish</button></div></section>
</main>
<nav><button data-t="home"><i>🏠</i>Bosh</button><button data-t="check"><i>🔍</i>Tekshir</button><button data-t="sos"><i>🆘</i>SOS</button><button data-t="acad"><i>🎓</i>Akademiya</button><button data-t="hist"><i>🕘</i>Tarix</button></nav>
<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const ls=(k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}},sv=(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v))}catch{}};
const post=(p,b)=>fetch(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}).then(r=>r.json());
function show(id){$$("main>section").forEach(s=>s.hidden=s.id!==id);$$("nav button").forEach(b=>b.classList.toggle("on",b.dataset.t===id));({home:stats,hist:hist,acad:quiz}[id]||(()=>{}))();scrollTo(0,0)}
$$("nav button").forEach(b=>b.onclick=()=>show(b.dataset.t));$$("[data-nav]").forEach(b=>b.onclick=()=>show(b.dataset.nav));$$("[data-go]").forEach(b=>b.onclick=()=>{mode(b.dataset.go);show("check")});
const M={url:["🔗 URL Scanner","Havolani joylang","https://payme-login.xyz/verify"],message:["💬 MessageGuard","SMS yoki xabar matnini joylang","Hisobingiz yopiladi — hozir tasdiqlash kodini yuboring"],card:["💳 CardGuard","Karta raqamini kiriting (saqlanmaydi)","8600 0000 0000 0000"],file:["📁 FileGuard + APK Shield","Fayl tanlang (ishga tushirilmaydi, 20 MB gacha)"],qr:["📷 QR Guard","Kamera yoki rasm orqali QR o'qing"],voice:["🎙 VoiceGuard","Qo'ng'iroq gapini matnga aylantirib tahlil qilish"]};
$("#tabs").innerHTML=Object.keys(M).map(k=>`<button data-m="${k}">${M[k][0].split(" ")[0]} ${M[k][0].split(" ")[1]}</button>`).join("");$$("#tabs button").forEach(b=>b.onclick=()=>mode(b.dataset.m));
function mode(m){$$("#tabs button").forEach(b=>b.classList.toggle("on",b.dataset.m===m));$("#ct").textContent=M[m][0];$("#out").innerHTML="";stopCam();
 if(m==="file")$("#inp").innerHTML=`<p>${M[m][1]}</p><input type=file id=f><button class=btn id=go>Tekshirish</button>`,$("#go").onclick=()=>fileScan($("#f").files[0]);
 else if(m==="qr")$("#inp").innerHTML=`<p>${M[m][1]}</p><button class=btn id=cam>📷 Kamerani yoqish</button> <input type=file accept="image/*" id=qi><video id=v playsinline muted hidden></video>`,$("#cam").onclick=startCam,$("#qi").onchange=e=>qrFile(e.target.files[0]);
 else if(m==="voice")voiceUI();
 else $("#inp").innerHTML=`<p>${M[m][1]}</p><textarea id=t placeholder="${M[m][2]}"></textarea><button class=btn id=go>Tekshirish</button>`,$("#go").onclick=()=>run(m,$("#t").value)}
async function run(m,text){if(!text.trim())return;$("#out").innerHTML='<div class=card>Tahlil qilinmoqda…</div>';try{const r=await post("/api/"+m,{text});render(r);rec(m,m==="card"?"":text,r)}catch{$("#out").innerHTML='<div class=card>Server bilan aloqa yo\'q.</div>'}}
async function fileScan(f){if(!f)return;const fd=new FormData();fd.append("file",f);$("#out").innerHTML='<div class=card>Tahlil qilinmoqda…</div>';try{const r=await fetch("/api/file",{method:"POST",body:fd}).then(r=>r.json());render(r);rec("file",f.name,r)}catch{$("#out").innerHTML='<div class=card>Fayl yuborilmadi.</div>'}}
function render(r){if(r.error){$("#out").innerHTML=`<div class=card>${esc(r.error)}</div>`;return}
 const ex=(r.masked?`<p>${esc(r.brand)} • ${esc(r.masked)}</p>`:"")+(r.sha256?`<p>SHA-256:<br><code>${r.sha256}</code></p><p>Hajmi: ${(r.size/1024).toFixed(1)} KB</p>`:"");
 $("#out").innerHTML=`<div class="card ${r.level}"><div class=res><div class="ring ${r.level}" style="--p:${r.score}"><b>${r.score}</b></div><div><div class="lbl" style="color:var(--c)">${r.label}</div><p>${esc(r.advice)}</p></div></div>${ex}<ul class="rs ${r.level}">${r.reasons.map(x=>`<li><b>${esc(x.t)}</b><span>Nega? ${esc(x.why)}</span></li>`).join("")}</ul>${r.level==="high"?'<button class="btn" style="margin-top:12px" onclick="show(\'sos\')">🆘 Aldanib qoldim</button>':""}</div>`}
let stream,tm;function stopCam(){clearInterval(tm);stream&&stream.getTracks().forEach(t=>t.stop());stream=null}
const BD=()=>"BarcodeDetector"in window?new BarcodeDetector({formats:["qr_code"]}):null;
async function startCam(){const d=BD();if(!d)return $("#out").innerHTML='<div class=card>Brauzeringiz QR o\'qishni qo\'llamaydi. Chrome (Android/desktop) ishlating yoki rasm tanlang.</div>';
 try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});const v=$("#v");v.hidden=false;v.srcObject=stream;await v.play();tm=setInterval(async()=>{const c=await d.detect(v).catch(()=>[]);if(c[0]){stopCam();v.hidden=true;qrDone(c[0].rawValue)}},400)}catch{$("#out").innerHTML='<div class=card>Kameraga ruxsat berilmadi.</div>'}}
async function qrFile(f){const d=BD();if(!f||!d)return $("#out").innerHTML='<div class=card>Brauzer QR o\'qishni qo\'llamaydi.</div>';const c=await d.detect(await createImageBitmap(f)).catch(()=>[]);c[0]?qrDone(c[0].rawValue):$("#out").innerHTML='<div class=card>QR topilmadi.</div>'}
function qrDone(v){$("#out").innerHTML=`<div class=card><p>QR ichida:</p><code>${esc(v)}</code></div>`;run(/^(https?:\/\/|www\.)/i.test(v)?"url":"message",v);}
const SOS=[["Kartani himoyalash","Bankning rasmiy ilovasi yoki call-markazi orqali kartani bloklang."],["Bankka xabar berish","Rasmiy aloqa kanali orqali shubhali operatsiya haqida xabar bering."],["Hisoblarni himoyalash","Toza qurilmadan parollarni almashtiring, faol sessiyalarni tugating, 2 bosqichli himoyani yoqing."],["Dalillarni saqlash","Xabar, havola, vaqt va tranzaksiya skrinshotlarini saqlang."],["Shikoyat tayyorlash","Quyidagi tugma yordamida matn tuzing va bank/huquq-tartibot organlariga yuboring."]];
function steps(){const d=ls("sos",[]);$("#steps").innerHTML=SOS.map((s,i)=>`<label class="step ${d[i]?"d":""}"><input type=checkbox data-i=${i} ${d[i]?"checked":""}><div><b>${i+1}. ${s[0]}</b><p>${s[1]}</p></div></label>`).join("");$$("#steps input").forEach(c=>c.onchange=()=>{const x=ls("sos",[]);x[c.dataset.i]=c.checked;sv("sos",x);steps()})}
steps();$("#cmp").onclick=()=>{const t=$("#cmpt");t.hidden=false;t.value=`Hurmatli bank xodimlari!\n\n${new Date().toLocaleString("uz")} da men firibgarlik qurboni bo'ldim. Quyidagi holatlar yuz berdi:\n- Qanday aloqa (SMS/qo'ng'iroq/havola): ...\n- Firibgar raqami/havolasi: ...\n- Summa va vaqt: ...\n- Karta oxirgi 4 raqami: ...\n\nOperatsiyani tekshirib, kartani bloklashingizni va ariza bo'yicha chora ko'rishingizni so'rayman.\n\nIsm-familiya: ...\nTelefon: ...`}
const Q=[["Bank xodimi telefonda SMS kodni so'rasa?",["Aytaman, ishonchli","Qo'ng'iroqni tugatib, bankning rasmiy raqamiga o'zim qo'ng'iroq qilaman","Faqat kodning yarmini aytaman"],1,"Bank hech qachon SMS kod, PIN yoki CVV so'ramaydi."],["Qaysi havola xavfliroq?",["https://payme.uz/pay","https://payme-bonus.xyz/login","https://click.uz"],1,"Brend nomi boshqa domen ichida va shubhali zona (.xyz) — taqlid belgisi."],["«Siz 10 mln so'm yutdingiz!» xabari…",["Havolani bosaman","Do'stlarga yuboraman","Aldov deb hisoblab, o'chiraman"],2,"Kutilmagan yutuq va'dasi — klassik fishing."],["Notanish QR-kodni skanerlaganda…",["Havolani ochishdan oldin tekshiraman","Darhol ochaman","Karta ma'lumotini kiritaman"],0,"QR ichida zararli havola bo'lishi mumkin."],["Eng yaxshi himoya choralaridan biri?",["Bir xil parol hamma joyda","2 bosqichli tasdiqlash (2FA)","Parolni xabarda saqlash"],1,"2FA parol o'g'irlansa ham hisobni himoya qiladi."],["Qarindoshingiz ovozli xabarda pul so'rasa (ovozi o'xshash)?",["Darhol o'tkazaman","Boshqa kanal orqali qo'ng'iroq qilib, oldindan kelishilgan maxfiy so'zni so'rayman","Ovozi o'xshash — demak, haqiqiy"],1,"AI ovozni taqlid qilishi mumkin; ikkinchi kanal va maxfiy so'z eng ishonchli tekshiruv."],["Havola t.me yoki bit.ly orqali kelsa?",["Haqiqiy manzil yashirilgan — avval URL Scanner'da tekshiraman","Doim xavfsiz","Faqat kechqurun ochaman"],0,"Qisqartirilgan havola manzilni yashiradi."],["Fayl 'hujjat.pdf.exe' deb kelsa?",["PDF — ochaman","Bu dastur, hujjat emas — ochmayman","Nomini o'zgartirib ochaman"],1,"Qo'sh kengaytma — dasturni hujjat sifatida ko'rsatish usuli."]];
let qi=0,qs=0;function quiz(){qi=0;qs=0;qn()}
function qn(){if(qi>=Q.length){const p=Math.round(qs/Q.length*100);sv("acad",Math.max(p,ls("acad",0)));$("#quiz").innerHTML=`<h2>Natija: ${p}%</h2><p>${p>=80?"Ajoyib! Siz fishingni yaxshi taniysiz.":"Yana urinib ko'ring — xatolardan o'rganish eng yaxshi usul."}</p><button class=btn id=rs>Qayta boshlash</button>`;$("#rs").onclick=quiz;return}
 const q=Q[qi];$("#quiz").innerHTML=`<p>Savol ${qi+1}/${Q.length}</p><h2>${q[0]}</h2>${q[1].map((o,i)=>`<button class=opt data-i=${i}>${o}</button>`).join("")}<p id=ex></p>`;
 $$(".opt").forEach(b=>b.onclick=()=>{const i=+b.dataset.i;$$(".opt").forEach(x=>x.disabled=true);$$(".opt")[q[2]].classList.add("ok");if(i===q[2])qs++;else b.classList.add("no");$("#ex").textContent=q[3];setTimeout(()=>{qi++;qn()},1800)})}

function rec(k,p,r){if(r.error)return;const x=ls("hist",[]);x.unshift({kind:k,preview:String(p).slice(0,80),score:r.score,level:r.level});sv("hist",x.slice(0,50))}
function stats(){const x=ls("hist",[]),hi=x.filter(i=>i.level==="high").length;$("#n1").textContent=x.length;$("#n2").textContent=hi;$("#hs").textContent=x.length?`${hi} ta yuqori xavfli natija topildi.`:"Hali tekshiruv yo'q — birinchi havolani tekshirib ko'ring.";$("#n3").textContent=ls("acad",null)==null?"—":ls("acad",0)+"%"}
function hist(){$("#hl").innerHTML=ls("hist",[]).map(x=>`<div class=h><div><b>${esc(x.kind)}</b><br><code>${esc(x.preview||"")}</code></div><span class="pill" style="--c:var(--${x.level})">${x.score}</span></div>`).join("")||"<p>Bo'sh.</p>"}
$("#hc").onclick=()=>{if(confirm("Barcha tarix o'chirilsinmi?")){sv("hist",[]);hist()}};

function voiceUI(){const SR=window.SpeechRecognition||window.webkitSpeechRecognition;$("#inp").innerHTML=`<p>${M.voice[1]}. Deepfake ovozni matn orqali ishonchli aniqlab bo'lmaydi — gap mazmuni va oilaviy maxfiy so'z orqali tekshiring.</p><select id=vl><option value=uz-UZ>O'zbek</option><option value=ru-RU>Русский</option><option value=en-US>English</option></select> <button class=btn id=mic>🎙 Tinglash</button><textarea id=t placeholder="Yoki gapni shu yerga yozing"></textarea><button class="btn g" id=go>Tekshirish</button>`;$("#go").onclick=()=>run("message",$("#t").value);$("#mic").onclick=()=>{if(!SR)return alert("Brauzer ovozni matnga aylantirishni qo'llamaydi (Chrome ishlating).");const r=new SR();r.lang=$("#vl").value;r.onresult=e=>{$("#t").value+=" "+e.results[0][0].transcript;run("message",$("#t").value)};r.start()}}
mode("url");show("home");if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js").catch(()=>{});
</script></body></html>
'''
RATE = defaultdict(deque)

@app.before_request
def limit():
    if request.path.startswith("/api/"):
        ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "?").split(",")[0].strip(); q = RATE[ip]; now = time.time()
        while q and now - q[0] > 60: q.popleft()
        if len(q) >= 40: return jsonify(error="Juda ko'p so'rov. Bir daqiqadan keyin urinib ko'ring."), 429
        q.append(now)

@app.after_request
def headers(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'"})
    return r

@app.errorhandler(413)
def big(_): return jsonify(error="Fayl 20 MB dan katta."), 413

@app.get("/health")
def health(): return "ok"

@app.get("/")
def index(): return Response(HTML, mimetype="text/html")

@app.get("/manifest.json")
def manifest(): return Response(MANIFEST, mimetype="application/manifest+json")

@app.get("/icon.svg")
def icon(): return Response(ICON, mimetype="image/svg+xml")

@app.get("/sw.js")
def sw(): return Response(SW, mimetype="application/javascript")

MANIFEST = r'''{"name":"PhishGuard","short_name":"PhishGuard","start_url":"/","display":"standalone","background_color":"#0b1020","theme_color":"#0b1020","icons":[{"src":"icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}]}
'''
ICON = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" xmlns:c2pa="http://c2pa.org/manifest"><metadata><c2pa:manifest>AAAWgmp1bWIAAAAeanVtZGMycGEAEQAQgAAAqgA4m3EDYzJwYQAAABZcanVtYgAAAEdqdW1kYzJtYQARABCAAACqADibcQN1cm46YzJwYTowNDkzNjY3Yy0yY2RhLTQ2NzYtOTQ1OS01NmViZDE1Y2I4NjIAAAADl2p1bWIAAAApanVtZGMyYXMAEQAQgAAAqgA4m3EDYzJwYS5hc3NlcnRpb25zAAAAALxqdW1iAAAARGp1bWRjYm9yABEAEIAAAKoAOJtxE2MycGEuaW5ncmVkaWVudC52MwAAAAAYYzJzaDMs0X/KuRcTTHeO8wel450AAABwY2JvcqNpZDC6Zm9ybWF0bWltYWdlL3N2Zyt4bWxqaW5zdGFuY2VJRHgseG1wOmlpZDo5NjJmZjUzYi0zNWU5LTQzMTEtYmE1MC0zZjI1NmVlYmJjYmVscmVsYXRpb25zaGlshipwYXJlbnRPZgAAABhqdW1iAAAAQEp1bWRjYm9yABEAEIAAAKoAOJtxE2MycGEuYWN0aW9ucy52MgAAAABYYzJzaEoSXf8LStK+njb3J50XZaUAAAGbY2JvcqlnYWN0aW9uc4KjZmFjdGlvbmtjMnBhLm9wZW5lZGpjaGFyYW1ldGVyc6FraW5ncmVkaWVudHNpYjdjdXJseC1zZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmluZ3JlZGllbnQudjNkaGFzaFggS2CisNAz762I/8O0ufm1a+5RNz+iolli1an6R5XMWBKkZmFjdGlvbngdY29tLmFudGhyb3BpYy5jbGF1ZGUucHJvdmlkZWRqcGFyYW1ldEPn6B4H2NvbS5hbnRocm9waWMub3JpZ2luLWNvbmZpZGVuY2VndW5rbm93bmtkZXNjcmlwdGlvbnhmQ2xhdWRlIHByb3ZpZGVkIHRoaXMgZmlsZSBhdCB0aGUgcmVxdWVzdCBvZiBhIHVzZXIgYW5kIG1heSBoYXZlIGNyZWF0ZWQgb3IgbW9kaWZpZWQgdGhlIGZpbGUgY29udGVudHMubXNvZnR3YXJlQWdlbnShdnVuYW1lZmNsYXVkZXJhbGxBY3Rpb25zSW5jbHVkZWRPUAAAAMhqdW1iAAAAQEp1bWRjYm9yABEAEIAAAKoAOJtxE2MycGEuaGFzaC5kYXRhAAAAABhjMnNouith01y+1bti0D0Lgfgv1QAAAIAb2JvcqVjYWxnZnNoYTI1NmNwYWRNAAAAAAAAAAAAAAAAAGRoYXNoWCBS7EZTi1Ti/Ui78dSAEELsZyJvgB5gblsECj475fGB3GRuYW1lbmp1bWJmIG1hbmlmZXN0amV4Y2x1c2lvbnOBomVzdGFydBh9Zmxlbmd0aBkeBAAAAj5qdW1iAAAAJ2p1bWRjMmNsABEAEIAAAKoAOJtxA2MycGEuY2xhaW0udjIAAAACD2Nib3KlY2FsZ2ZzaGEyNTZpc2lnbmF0dXJleE1zZWxmI2p1bWJmPS9jMnBhL3VybjpjMnBhOjA0OTM2NjdjLTJjZGEtNDY3Ni05NDU5LTU2ZWJkMTVjYjg2Mi9jMnBhLnNpZ25hdHVyZWppbnN0YW5jZUlEeCx4bXA6aWlkOjIwZTM4YTZhLTYxMmQtNDRmNi05NDgwLWFmMmFlNjYzOWYzY3JjcmVhdGVkX2Fzc2VydGlvbnODomN1cmx4LXNlbGYjanVtYmY9YzJwYS5hc3NlcnRpb25zL2MycGEuaW5ncmVkaWVudC52M2RoYXNoWCBLYKKw0DPvrYj/w7S5+bVr7lE3P6KiWWLVqfpHlcxYEqJjdXJseCpzZWxmI2p1bWJmPWMycGEuYXNzZXJ0aW9ucy9jMnBhLmFjdGlvbnJSjVpkaGFzaFggZOZEVUgadla2U5yYNIALNg1ETQiGLf0OwcNWcab06xGiY3VybHgpc2VsZiNqdW1iZj1jMnBhLmFzc2VydGlvbnMvYzJwYS5oYXNoLmRhdGFkaGFzaFggCKtVL2/O90JufyTD0ptHcXjGgH4n5G14luzjqEEyBBR0Y2xhaW1fZ2VuZXJhdG9yX2luZm+jZG5hbWVvQW50aHJvcGljIEZpbGVzZ3ZlcnNpb25lMS4wLjBrc3BlY1ZlcnNpb25lMi40LjAAABA4anVtYgAAAChqdW1kYzJjcwARABCAAACqADibcQNjMnBhLnNpZ25hdHVyZQAAABAIY2JvctKEWQISogEmGCFZAgowggIGMIIBjaADAgECAhRA5aAK7sI50L64g/oGQgU9Z1UTADAKBggqhkjOPQQDAzBJMRcwFQYDVQQKEw5BbnRocm9waWMsIFBCQzEuMCwGA1UEAxMlQW50aHJvcGljIENvbnRlbnQgQ3JlZGVudGlhbHMgUm9vdCBDQTAeFw0yNjA4MDcxODQzNTZaFw0yODA4MDYxOTQzNTZaMEQxFzAVBgNVBAoTDkFudGhyb3BpYywgUEJDMSkwJwYDVQQDEyBBbnRocm9waWMgQ2xhdWRlIENvbnRlbnQgU2lnbmluZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJh6CmvLUBgFFNU0vUKlOVtE6djd17L5SuwX0LemFisBM3dkd/3cyjxFA3Qo5S46fX0/ihY0VZ7mfb9KF703t5OjWDBWMA4GA1UdDwEB/wQEAwIHgDAVBgNVHSUEDjAMBgorBgEEAYPoXgIBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUzlHiBIFOZFsj+OPEz5o+nMHXXMIwCgYIKoZIzj0EAwMDZwAwZAIwMXMdFJ4BetLLVY7ORuE9noqbbAZOZn/aArXyTwFAZfKrPzxF2vPoJNf1+UCdg1XGAjBwX1zd9WGqYkqmL5SFqw1QySjr1zJfpJM9+1rdDwSPLMOPOjKuiXjoU/pUUeG9RwmhY3BhZFkNngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPZYQHRZgX3pEGqf6mTLifOzVHuoaipjxevZgL0/PLXVPLo3ctAwsszbbGX3eHtpP6nuCHIItLv0kuBie9UHPg/SflI=</c2pa:manifest></metadata><rect width="100" height="100" fill="#0b1020"/><path d="M50 14 80 26v22c0 20-13 33-30 38C33 81 20 68 20 48V26z" fill="#5eead4"/><path d="m38 50 9 9 17-19" stroke="#0b1020" stroke-width="7" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
'''
SW = r'''const C="pg-v1",F=["/","/manifest.json","/icon.svg"];
self.addEventListener("install",e=>e.waitUntil(caches.open(C).then(c=>c.addAll(F))));
self.addEventListener("fetch",e=>{if(e.request.method!=="GET"||e.request.url.includes("/api/"))return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});
'''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=bool(os.environ.get("DEBUG")))
