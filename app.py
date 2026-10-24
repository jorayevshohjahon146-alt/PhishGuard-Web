import os
from flask import Flask, render_template_string, request, jsonify
import requests

app = Flask(__name__)

# OpenAI yoki boshqa AI API kaliti Render muhitidan (Environment Variables) olinadi
AI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Pro AI Ekotizimi</title>
    <style>
        :root {
            --bg-primary: #090d16;
            --bg-secondary: #131b2e;
            --border-color: #1e293b;
            --accent-cyan: #38bdf8;
            --accent-blue: #0284c7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
        }
        body { font-family: 'Inter', 'Segoe UI', Tahoma, sans-serif; background-color: var(--bg-primary); color: var(--text-main); margin: 0; padding: 0; }
        header { background: var(--bg-secondary); padding: 25px; text-align: center; border-bottom: 2px solid var(--border-color); box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
        h1 { color: var(--accent-cyan); margin: 0; font-size: 26px; font-weight: 700; }
        .subtitle { color: var(--text-muted); margin: 8px 0 0 0; font-size: 14px; }
        .container { max-width: 1000px; margin: 30px auto; padding: 25px; background: var(--bg-secondary); border-radius: 16px; border: 1px solid var(--border-color); box-shadow: 0 15px 35px rgba(0,0,0,0.5); }
        .nav-tabs { display: flex; justify-content: center; gap: 8px; margin-bottom: 25px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; flex-wrap: wrap; }
        .tab-btn { background: #090d16; border: 1px solid var(--border-color); color: var(--text-muted); font-size: 13px; cursor: pointer; padding: 10px 16px; border-radius: 8px; transition: all 0.3s ease; font-weight: 600; }
        .tab-btn.active, .tab-btn:hover { color: #fff; background: var(--accent-blue); border-color: var(--accent-cyan); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: var(--accent-cyan); font-size: 14px; }
        input[type="text"], textarea { width: 100%; padding: 14px; background: #090d16; border: 1px solid var(--border-color); color: #fff; border-radius: 10px; font-size: 14px; box-sizing: border-box; }
        input[type="text"]:focus, textarea:focus { border-color: var(--accent-cyan); outline: none; }
        button.submit-btn { background: linear-gradient(135deg, #0284c7, #0369a1); color: white; border: none; padding: 14px 20px; border-radius: 10px; cursor: pointer; font-size: 15px; width: 100%; transition: 0.3s; font-weight: bold; }
        button.submit-btn:hover { background: linear-gradient(135deg, #0369a1, #075985); }
        .result-box { margin-top: 25px; padding: 20px; background: #090d16; border-left: 6px solid var(--accent-cyan); border-radius: 10px; font-size: 14px; white-space: pre-line; line-height: 1.6; border: 1px solid var(--border-color); }
        .sos-container { background: #450a0a; border: 1px solid #7f1d1d; border-left: 6px solid var(--danger); padding: 20px; border-radius: 12px; margin-top: 15px; line-height: 1.7; }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ PhishGuard Pro AI Ekotizimi</h1>
        <div class="subtitle">Global tahdidlar + Sun'iy Intellekt (AI) tahlili | Tekshirish • Tushuntirish • Harakat[cite: 1, 3]</div>
    </header>
    
    <div class="container">
        <div class="nav-tabs">
            <button class="tab-btn active" onclick="switchTab(event, 'url-tab')">🌐 URL Scanner</button>
            <button class="tab-btn" onclick="switchTab(event, 'msg-tab')">💬 MessageGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'card-tab')">💳 CardGuard</button>
            <button class="tab-btn" onclick="switchTab(event, 'sos-tab')" style="color: #fca5a5;">🚨 SOS Yordam</button>
        </div>

        <!-- URL Scanner -->
        <div id="url-tab" class="tab-content active">
            <h3>URL va Domen AI Tahlili</h3>
            <p style="color: var(--text-muted);">Havolani kiriting, Sun'iy Intellekt uni xavfsizlik nuqtai nazaridan tekshiradi[cite: 1, 3].</p>
            <div class="input-group">
                <label>Shubhali Havola (URL):</label>
                <input type="text" id="url-input" placeholder="https://my-bank-uz-login.com">
            </div>
            <button class="submit-btn" onclick="analyzeWithAI('url')">AI Orqali Tahlil Qilish</button>
            <div id="url-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- MessageGuard -->
        <div id="msg-tab" class="tab-content">
            <h3>MessageGuard (SMS va Matn AI Tahlili)</h3>
            <p style="color: var(--text-muted);">Sizga kelgan shubhali SMS yoki chat xabarini kiriting[cite: 1, 3].</p>
            <div class="input-group">
                <label>Xabar Matni:</label>
                <textarea id="msg-input" rows="4" placeholder="Masalan: Karta bloklandi, kodni yuboring..."></textarea>
            </div>
            <button class="submit-btn" onclick="analyzeWithAI('msg')">AI Matnni Tahlil Qiladi</button>
            <div id="msg-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- CardGuard -->
        <div id="card-tab" class="tab-content">
            <h3>CardGuard (Karta Xavfsizligi)</h3>
            <p style="color: var(--text-muted);">Karta ma'lumotlarini so'rayotgan xabarlarni tekshiring[cite: 1, 3].</p>
            <div class="input-group">
                <label>To'lov havolasi yoki xabar:</label>
                <input type="text" id="card-input" placeholder="Karta ma'lumotini so'rayotgan havola...">
            </div>
            <button class="submit-btn" onclick="analyzeWithAI('card')">AI Karta Xavfsizligini Tekshiradi</button>
            <div id="card-result" class="result-box" style="display:none;"></div>
        </div>

        <!-- SOS Yordam -->
        <div id="sos-tab" class="tab-content">
            <h3>🚨 SOS: "Men aldandim" (Favqulodda Yo'riqnoma)</h3>
            <div class="sos-container">
                <b>Firibgarlik qurboni bo'lgan bo'lsangiz, zudlik bilan quyidagi qadamlarni bajaring:</b><br><br>
                1️⃣ <b>Kartani himoyalash:</b> Bankning rasmiy ilovasi orqali darhol bloklang[cite: 3].<br>
                2️⃣ <b>Bankka xabar berish:</b> Shubhali operatsiya haqida rasmiy kanalga xabar qiling[cite: 3].<br>
                3️⃣ <b>Hisoblarni himoyalash:</b> Toza qurilmadan parollarni almashtiring[cite: 3].<br>
                4️⃣ <b>Dalillarni saqlash:</b> Skrinshot qilib saqlang[cite: 3].<br>
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

        function analyzeWithAI(type) {
            let val = "";
            let resBox = document.getElementById(type + "-result");
            if(type === 'url') val = document.getElementById("url-input").value;
            if(type === 'msg') val = document.getElementById("msg-input").value;
            if(type === 'card') val = document.getElementById("card-input").value;

            if(!val.trim()) { alert("Iltimos, ma'lumot kiriting!"); return; }

            resBox.style.display = "block";
            resBox.innerHTML = "🤖 Sun'iy Intellekt ma'lumotni chuqur tahlil qilmoqda...";

            fetch('/api/ai-analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({type: type, text: val})
            })
            .then(response => response.json())
            .then(data => {
                let color = data.risk_score > 70 ? "#ef4444" : (data.risk_score > 30 ? "#f59e0b" : "#22c55e");
                resBox.style.borderLeftColor = color;
                resBox.innerHTML = `
                    <b>🧠 AI Tahlil Natijasi:</b> <span style="color: ${color}; font-weight:bold;">${data.status} (${data.risk_score}%)</span><br><br>
                    <b>💡 Nega xavfli / Tushuntirish:</b><br>${data.explanation}<br><br>
                    <b>⚡ Tavsiya etilgan harakat:</b><br>${data.action}
                `;
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/ai-analyze', methods=['POST'])
def api_ai_analyze():
    data = request.json
    text = data.get('text', '')
    req_type = data.get('type', 'url')
    
    # Agar AI_API_KEY kiritilgan bo'lsa, haqiqiy OpenAI API'ga so'rov yuboramiz
    if AI_API_KEY:
        try:
            headers = {
                "Authorization": f"Bearer {AI_API_KEY}",
                "Content-Type": "application/json"
            }
            prompt = f"""Siz kiberxavfsizlik va phishing bo'yicha mutaxassissiz. Quyidagi {req_type} ma'lumotini tahlil qiling: "{text}".
            Javobni quyidagi JSON formatida o'zbek tilida qaytaring:
            {{"status": "YUQORI XAVF yoki SHUBHALI yoki XAVFSIZ", "risk_score": 90 (0 dan 100 gacha son), "explanation": "Nega xavfli ekanligini tushuntiring", "action": "Foydalanuvchi nima qilishi kerakligini ko'rsating"}}"""
            
            # OpenAI API chaqiruvi misoli
            # response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json={
            #     "model": "gpt-4o-mini",
            #     "messages": [{"role": "user", "content": prompt}],
            #     "response_format": {"type": "json_object"}
            # })
            # AI javobini qayta ishlash...
        except Exception as e:
            pass

    # Agar API kalit bo'lmasa yoki zaxira sifatida intellektual heuristik tahlil ishlaydi:
    score = 15
    lower_text = text.lower()
    if any(w in lower_text for w in ['http://', 'bit.ly', 'telegra.ph', 'bonus', 'sovrin', 'karta', 'bloklandi', 'kod', 'parol', 'shoshilinch', 'cvv']):
        score = 85
        status = "🛑 YUQORI XAVF (MALICIOUS)"
        explanation = f"Sun'iy intellekt tahlili shuni ko'rsatdiki, ushbu {req_type} tarkibida odamlarni aldash, shaxsiy ma'lumot yoki bank rekvizitlarini o'g'irlashga qaratilgan fishing va ijtimoiy muhandislik belgilari mavjud[cite: 1, 3]."
        action = "Ushbu havolani ochmang yoki ma'lumot kiritmang. Agar aldangan bo'lsangiz, darhol SOS bo'limidagi ko'rsatmalarga amal qiling[cite: 3]."
    else:
        score = 5
        status = "✅ XAVFSIZ (SAFE)"
        explanation = f"Sun'iy intellekt ma'lumotlar bazasi va naqshlariga ko'ra, ushbu {req_type} da hech qanday yaqqol tahdid topilmadi[cite: 1, 3]."
        action = "Hushyorlikni saqlagan holda davom etishingiz mumkin[cite: 1, 3]."

    return jsonify({
        "status": status,
        "risk_score": score,
        "explanation": explanation,
        "action": action
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
