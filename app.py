from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

# Bosh sahifani (index.html) ochish uchun
@app.route('/')
def index():
    return render_template('index.html')

# Tahlil qilish API marshruti
@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json() or {}
    text = data.get('text', '').strip()

    if not text:
        return jsonify({'error': "Matn yoki havola kiritilmadi"}), 400

    # 1. Indikatorlar va so'zlar bazasi
    phishing_domains = ['.top', '.free.nf', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.site', 'login', 'verify']
    legit_domains = ['tatu.uz', 'gov.uz', 'click.uz', 'payme.uz', 'uzcard.uz', 'humocard.uz', 'google.com']
    suspicious_words = ['bloklandi', 'kod', 'parol', 'shoshiling', 'yutib oldingiz', 'bonus', 'sovrin', 'sms']

    text_lower = text.lower()
    risk_score = 0
    reasons = []

    # Rasmiy saytlarni tekshirish
    is_legit = any(domain in text_lower for domain in legit_domains)

    if is_legit and not any(word in text_lower for word in suspicious_words):
        risk_score = 2
        reasons.append("Rasmiy va ishonchli manba aniqlandi.")
    else:
        # Shubhali domenlar
        if any(ext in text_lower for ext in phishing_domains):
            risk_score += 45
            reasons.append("Shubhali domen kengaytmasi yoki soxta havola indikatori.")

        # IP-manzil ishtiroki
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text):
            risk_score += 35
            reasons.append("Havola domen o'rniga to'g'ridan-to mezonli IP-manzildan iborat.")

        # Shubhali kalit so'zlar
        matched_words = [word for word in suspicious_words if word in text_lower]
        if matched_words:
            risk_score += len(matched_words) * 15
            reasons.append(f"Firibgarlik belgilari va kalit so'zlar aniqlandi: {', '.join(matched_words)}")

        # HTTP protokoli
        if text_lower.startswith('http://'):
            risk_score += 15
            reasons.append("Xavfsiz shifrlash (HTTPS) mavjud emas.")

    # Risk ko'rsatkichini chegaralash
    risk_score = min(max(risk_score, 0), 99)

    # Agar xavf belgisi topilmagan oddiy so'z yoki ism bo'lsa
    if risk_score == 0 and not is_legit:
        risk_score = 5
        reasons.append("Oddiy matn: hech qanday shubhali kiber-tahdid belgisi topilmadi.")

    # Status va tavsiyani shakllantirish
    if risk_score >= 70:
        status = "XAVFLI"
        color = "danger"
        recommendation = "Tashrif buyurmang va shaxsiy/bank ma'lumotlarini kiritmang!"
    elif risk_score >= 30:
        status = "SHUBHALI"
        color = "warning"
        recommendation = "Ehtiyot bo'ling, manbani va xabar yuboruvchini qayta tekshiring."
    else:
        status = "XAVFSIZ"
        color = "success"
        recommendation = "Ruxsat berilgan, xavf alomatlari aniqlanmadi."

    return jsonify({
        'risk_score': risk_score,
        'status': status,
        'color': color,
        'reasons': reasons,
        'recommendation': recommendation
    })

# SERVERNI ISHGA TUSHIRUVCHI ENG MUHIM QISM:
if __name__ == '__main__':
    app.run(debug=True, port=5000)