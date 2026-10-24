import os
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Veb sahifa dizayni va interfeysi (Slaydlar asosida)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Pro AI Ekotizimi</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 0; }
        header { background: #1e293b; padding: 20px; text-align: center; border-bottom: 2px solid #334155; }
        h1 { color: #38bdf8; margin: 0; font-size: 24px; }
        .container { max-width: 900px; margin: 30px auto; padding: 20px; background: #1e293b; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
        .nav-tabs { display: flex; justify-content: space-around; margin-bottom: 20px; border-bottom: 1px solid #334155; padding-bottom: 10px; flex-wrap: wrap; }
        .tab-btn { background: none; border: none; color: #94a3b8; font-size: 16px; cursor: pointer; padding: 10px 15px; transition: 0.3s; font-weight: 600; }
        .tab-btn.active, .tab-btn:hover { color: #38bdf8; border-bottom: 2px solid #38bdf8; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        input[type="text"], textarea { width: 100%; padding: 12px; margin: 10px 0 20px 0; background: #0f172a; border: 1px solid #475569; color: #fff; border-radius: 8px; font-size: 14px; box-sizing: border-box; }
        button.submit-btn { background: #0284c7; color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; transition: 0.3s; }
        button.submit-btn:hover { background: #0369a1; }
        .result-box { margin-top: 20px; padding: 15px; background: #0f172a; border-left: 5px solid #38bdf8; border-radius: 6px; font-size: 15px; white-space: pre-line; }
        .sos-box { background: #7f1d1d; border-left: 5px solid #ef4444; padding: 15px; border-radius: 6px; margin-top: 15px; }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ PhishGuard Pro AI — Raqamli Tahdidlarga Qarshi Kompleks Himoya</h1>
        <p style="color: #94a3b8; margin: 5px 0 0 0;">Tekshirish • Tushuntirish • Himoyalanish • O‘rganish</p>
    </header>
    
    <div class="container">
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="switchTab(event, 'url-tab')">🌐 URL Scanner</button>
            <button class="tab-btn" onclick="switchTab(event, 'msg-tab')">💬 MessageGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'card-tab')">💳 CardGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'sos-tab')">🚨 SOS Yordam</button>
        </div>

        <!-- URL Scanner -->
        <div id="url-tab" class="tab-content active">
            <h3>URL va Domen Tahlili</h3>
            <p style="color: #94a3b8;">Shubhali havolalarni kiritib, phishing xavfini tekshiring.</p>
            <input type="text" id="url-input" placeholder="https://example.com">
            <button class="submit-btn" onclick="analyze('url')">Tekshirish</button>
            <div id="url-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- MessageGuard -->
        <div id="msg-tab" class="tab-content">
            <h3>MessageGuard (SMS va Matn Tahlili)</h3>
            <p style="color: #94a3b8;">Sizga kelgan shubhali SMS yoki chat xabarini kiriting.</p>
            <textarea id="msg-input" rows="4" placeholder="Masalan: Karta bloklandi, kodni yuboring..."></textarea>
            <button class="submit-btn" onclick="analyze('msg')">Matnni Tahlil Qilish</button>
            <div id="msg-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- CardGuard -->
        <div id="card-tab" class="tab-content">
            <h3>CardGuard (Karta Xavfsizligi)</h3>
            <p style="color: #94a3b8;">Karta ma'lumotlarini so'rayotgan shubhali sahifa yoki to'lov havolasini tekshiring.</p>
            <input type="text" id="card-input" placeholder="To'lov havolasi yoki xabar...">
            <button class="submit-btn" onclick="analyze('card')">Xavfsizlikni Tekshirish</button>
            <div id="card-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- SOS Yordam -->
        <div id="sos-tab" class="tab-content">
            <h3>🚨 SOS: "Men aldandim" (Favqulodda Yo'riqnoma)</h3>
            <div class="sos-box">
                <b>Agar firibgarlik qurboni bo'lgan bo'lsangiz, zudlik bilan quyidagi qadamlarni bajaring:</b><br><br>
                1️⃣ <b>Kartani himoyalash:</b> Bankning rasmiy ilovasi yoki call-markazi orqali darhol bloklang[cite: 3].<br>
                2️⃣ <b>Bankka xabar berish:</b> Shubhali operatsiya haqida rasmiy kanalga xabar qiling[cite: 3].<br>
                3️⃣ <b>Hisoblarni himoyalash:</b> Toza qurilmadan parollarni almashtiring va faol sessiyalarni yoping[cite: 3].<br>
                4️⃣ <b>Dalillarni saqlash:</b> Xabarlar, havolalar va vaqtni skrinshot qilib saqlang[cite: 3].<br>
                5️⃣ <b>Shikoyat tayyorlash:</b> Bank yoki tegishli tashkilot uchun ariza tuzing[cite: 3].
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

            if(!val) { alert("Iltimos, ma'lumot kiriting!"); return; }

            fetch('/api/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: type, text: val})
            })
            .then(response => response.json())
            .then(data => {
                resBox.style.display = "block";
                resBox.innerHTML = `<b>Natija:</b> ${data.status}<br><b>Xavf darajasi:</b> ${data.risk}<br><br>${data.details}`;
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
    
    score = 0
    threats = []
    
    if any(ip in text for ip in ['192.', '10.', 'http://', 'bit.ly', 'telegra.ph']):
        score += 40
        threats.append("⚠️ Shubhali yoki qisqartirilgan havola aniqlandi.")
    
    keywords = ['apk', 'karta', 'bloklandi', 'sms', 'kod', 'parol', 'shoshilinch', 'balans', 'tasdiqlang', 'yutuq']
    matched = [kw for kw in keywords if kw in text]
    if matched:
        score += 45
        threats.append(f"🛑 Shoshiltirish yoki maxfiy ma'lumot so'rovchi belgilar: {', '.join(matched)}")

    if score >= 50:
        status = "🛑 YUQORI XAVF (MALICIOUS)"
        risk = "90%"
        details = "Aniqlangan tahdidlar:\n" + "\n".join(threats) + "\n\n💡 Nega xavfli? Firibgarlar shaxsiy ma'lumot yoki pulingizni o'g'irlashga harakat qilmoqda[cite: 3]."
    elif score > 0:
        status = "⚠️ SHUBHALI (WARNING)"
        risk = "45%"
        details = "Ba'zi shubhali belgilar sezildi. Ehtiyot bo'ling[cite: 3]."
    else:
        status = "✅ XAVFSIZ (SAFE)"
        risk = "0%"
        details = "Hech qanday tahdid topilmadi[cite: 3]."

    return jsonify({"status": status, "risk": risk, "details": details})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
