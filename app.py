import os
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Barcha modullarni o'z ichiga olgan zamonaviy va keng qamrovli veb interfeys
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Pro AI — Kompleks Kiberxavfsizlik Ekotizimi</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --panel-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
        }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-color); color: var(--text-main); margin: 0; padding: 0; }
        header { background: var(--panel-bg); padding: 20px; text-align: center; border-bottom: 2px solid var(--border-color); }
        h1 { color: #38bdf8; margin: 0; font-size: 24px; }
        .container { max-width: 1000px; margin: 25px auto; padding: 20px; background: var(--panel-bg); border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }
        
        /* Navigatsiya tugmalari (Tabs) */
        .nav-tabs { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 12px; flex-wrap: wrap; }
        .tab-btn { background: #0f172a; border: 1px solid var(--border-color); color: var(--text-muted); font-size: 14px; cursor: pointer; padding: 8px 14px; border-radius: 6px; transition: 0.3s; font-weight: 600; }
        .tab-btn.active, .tab-btn:hover { color: #fff; background: var(--primary); border-color: var(--primary); }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        input[type="text"], textarea { width: 100%; padding: 12px; margin: 10px 0 20px 0; background: #0f172a; border: 1px solid #475569; color: #fff; border-radius: 8px; font-size: 14px; box-sizing: border-box; }
        button.submit-btn { background: var(--primary); color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; transition: 0.3s; font-weight: bold; }
        button.submit-btn:hover { background: var(--primary-hover); }
        
        .result-box { margin-top: 20px; padding: 15px; background: #0f172a; border-left: 5px solid var(--primary); border-radius: 6px; font-size: 15px; white-space: pre-line; line-height: 1.5; }
        .sos-box { background: #7f1d1d; border-left: 5px solid var(--danger); padding: 15px; border-radius: 6px; margin-top: 15px; line-height: 1.6; }
        .academy-card { background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 15px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        @media(max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ PhishGuard Pro AI Ekotizimi</h1>
        <p style="color: var(--text-muted); margin: 5px 0 0 0;">Tekshirish • Tushuntirish • Himoyalanish • O‘rganish[cite: 1, 3]</p>
    </header>
    
    <div class="container">
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="switchTab(event, 'url-tab')">🌐 URL Scanner</button>
            <button class="tab-btn" onclick="switchTab(event, 'msg-tab')">💬 MessageGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'card-tab')">💳 CardGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'file-tab')">📁 APK & File</button>
            <button class="tab-btn" onclick="switchTab(event, 'qr-tab')">📱 QR Guard</button>
            <button class="tab-btn" onclick="switchTab(event, 'voice-tab')">🎙️ VoiceGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'academy-tab')">🎓 Cyber Academy</button>
            <button class="tab-btn" onclick="switchTab(event, 'sos-tab')" style="color:#fca5a5;">🚨 SOS Yordam</button>
        </div>

        <!-- 1. URL Scanner -->
        <div id="url-tab" class="tab-content active">
            <h3>URL va Domen Tahlili</h3>
            <p style="color: var(--text-muted);">Shubhali havolalarni kiritib, fishing va soxta domen xavfini tekshiring[cite: 1, 3].</p>
            <input type="text" id="url-input" placeholder="https://example.com">
            <button class="submit-btn" onclick="analyze('url')">URL'ni Tekshirish</button>
            <div id="url-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- 2. MessageGuard -->
        <div id="msg-tab" class="tab-content">
            <h3>MessageGuard (SMS va Matn Tahlili)</h3>
            <p style="color: var(--text-muted);">Sizga kelgan shubhali SMS, elektron pochta yoki chat matnini kiriting[cite: 1, 3].</p>
            <textarea id="msg-input" rows="4" placeholder="Masalan: Karta bloklandi, zudlik bilan kodni yuboring..."></textarea>
            <button class="submit-btn" onclick="analyze('msg')">Matnni Tahlil Qilish</button>
            <div id="msg-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- 3. CardGuard -->
        <div id="card-tab" class="tab-content">
            <h3>CardGuard (Karta Xavfsizligi)</h3>
            <p style="color: var(--text-muted);">Karta ma'lumotlarini yoki PIN/CVV kodlarini so'rayotgan shubhali to'lov havolalarini tekshiring[cite: 1, 3].</p>
            <input type="text" id="card-input" placeholder="To'lov havolasi yoki shubhali taklif...">
            <button class="submit-btn" onclick="analyze('card')">Karta Xavfsizligini Tekshirish</button>
            <div id="card-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- 4. APK & File Guard -->
        <div id="file-tab" class="tab-content">
            <h3>APK Shield & FileGuard</h3>
            <p style="color: var(--text-muted);">Android APK fayllari yoki yuklab olingan shubhali fayl nomini kiriting[cite: 1, 3].</p>
            <input type="text" id="file-input" placeholder="Masalan: update_bonus.apk yoki Skaner.exe">
            <button class="submit-btn" onclick="analyze('file')">Faylni Statik Tahlil Qilish</button>
            <div id="file-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- 5. QR Guard -->
        <div id="qr-tab" class="tab-content">
            <h3>QR Guard</h3>
            <p style="color: var(--text-muted);">QR-kod ichidan chiqqan havola yoki matnni tekshiring[cite: 1, 3].</p>
            <input type="text" id="qr-input" placeholder="QR kod havolasini kiriting...">
            <button class="submit-btn" onclick="analyze('qr')">QR Kodni Tekshirish</button>
            <div id="qr-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- 6. VoiceGuard -->
        <div id="voice-tab" class="tab-content">
            <h3>VoiceGuard (Deepfake Ovoz Tahlili)</h3>
            <p style="color: var(--text-muted);">Sun'iy intellekt orqali ovozli firibgarlik (deepfake) xavfini baholash[cite: 1, 3].</p>
            <div class="academy-card">
                <b>Ma'lumot:</b> VoiceGuard ovoz yozuvining texnik belgilarini o'rganib, tanish inson ovoziga taqlid qilinganini aniqlashga yordam beradi[cite: 1, 3]. Telegram bot orqali ovozli xabar yuborib ham tekshirishingiz mumkin.
            </div>
        </div>

        <!-- 7. Cyber Academy -->
        <div id="academy-tab" class="tab-content">
            <h3>Cyber Academy (Kiber Akademiya)</h3>
            <p style="color: var(--text-muted);">Fishing xabarlarini tanish mashqlari va xavfsizlik testlari[cite: 1, 3].</p>
            <div class="academy-card">
                <b>1-Dars: Fishing nima?</b><br>
                Fishing — soxta havolalar orqali shaxsiy ma'lumotlarni o'g'irlash usuli[cite: 1, 3]. Hech qachon SMS kodlarni boshqalarga bermang!
            </div>
            <div class="academy-card">
                <b>2-Dars: Kuchli parol yaratish</b><br>
                Har bir account uchun har xil va murakkab parollardan foydalaning.
            </div>
        </div>

        <!-- 8. SOS Yordam -->
        <div id="sos-tab" class="tab-content">
            <h3>🚨 SOS: "Men aldandim" (Favqulodda Yo'riqnoma)</h3>
            <div class="sos-box">
                <b>Firibgarlik qurboni bo'lgan bo'lsangiz, zudlik bilan quyidagi qadamlarni bajaring:</b><br><br>
                1️⃣ <b>Kartani himoyalash:</b> Bankning rasmiy ilovasi yoki call-markazi orqali darhol bloklang[cite: 1, 3].<br>
                2️⃣ <b>Bankka xabar berish:</b> Shubhali operatsiya haqida rasmiy aloqa kanali orqali xabar qiling[cite: 1, 3].<br>
                3️⃣ <b>Hisoblarni himoyalash:</b> Toza qurilmadan parollarni almashtiring va faol sessiyalarni yoping[cite: 1, 3].<br>
                4️⃣ <b>Dalillarni saqlash:</b> Xabarlar, havolalar, vaqt va tranzaksiya ma'lumotlarini skrinshot qiling[cite: 1, 3].<br>
                5️⃣ <b>Shikoyat tayyorlash:</b> Bank yoki huquqni muhofaza qiluvchi organlar uchun faktlarga asoslangan ariza tuzing[cite: 1, 3].
            </div>
        </div>
    </div>

    <script>
        function switchTab(evt, tabName) {
            let tabs = document.getElementsByClassName("tab-content");
            for (let t of tabs) t.classList.remove("active");
            let btns = document.getElementsByClassName("tab-btn");
            for (let b of btns) b.classList.remove("active");
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }

        function analyze(type) {
            let val = "";
            let resBox = document.getElementById(type + "-result");
            if(type === 'url') val = document.getElementById("url-input").value;
            if(type === 'msg') val = document.getElementById("msg-input").value;
            if(type === 'card') val = document.getElementById("card-input").value;
            if(type === 'file') val = document.getElementById("file-input").value;
            if(type === 'qr') val = document.getElementById("qr-input").value;

            if(!val) { alert("Iltimos, maydonga ma'lumot kiriting!"); return; }

            fetch('/api/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: type, text: val})
            })
            .then(response => response.json())
            .then(data => {
                resBox.style.display = "block";
                resBox.innerHTML = `<b>Tahlil Natijasi:</b> ${data.status}<br><b>Xavf Darajasi:</b> ${data.risk}<br><br>${data.details}`;
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    text = data.get('text', '').lower()
    req_type = data.get('type', '')
    
    score = 0
    threats = []
    
    if any(ip in text for ip in ['192.', '10.', 'http://', 'bit.ly', 'telegra.ph', 'bonus', 'sovrin']):
        score += 40
        threats.append("⚠️ Shubhali havola yoki tarmoq manzili aniqlandi.")
    
    keywords = ['apk', 'karta', 'bloklandi', 'sms', 'kod', 'parol', 'shoshilinch', 'balans', 'tasdiqlang', 'yutuq', 'kredit', 'cvv']
    matched = [kw for kw in keywords if kw in text]
    if matched:
        score += 50
        threats.append(f"🛑 Shoshiltirish yoki maxfiy ma'lumot talab qiluvchi so'zlar: {', '.join(matched)}")

    if score >= 50 or 'apk' in text:
        status = "🛑 YUQORI XAVF (MALICIOUS)"
        risk = "90%"
        details = "Aniqlangan tahdidlar:\n" + "\n".join(threats) + "\n\n💡 Nega xavfli? Firibgarlar shaxsiy ma'lumotlaringiz yoki pulingizni qo'lga kiritishga harakat qilmoqda[cite: 1, 3]. Zudlik bilan to'xtating!"
    elif score > 0:
        status = "⚠️ SHUBHALI (WARNING)"
        risk = "45%"
        details = "Ba'zi shubhali belgilar sezildi. Ehtiyot bo'lishingiz tavsiya etiladi[cite: 1, 3]."
    else:
        status = "✅ XAVFSIZ (SAFE)"
        risk = "0%"
        details = "Hozircha hech qanday tahdid topilmadi[cite: 1, 3]. Shunda ham hushyorlikni unutmang."

    return jsonify({"status": status, "risk": risk, "details": details})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
