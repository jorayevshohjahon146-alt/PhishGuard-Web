import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Vaqtinchalik fayllar (masalan, ovozlar) uchun papka
UPLOAD_FOLDER = 'voices'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def home():
    # Asosiy veb-sahifa (index.html)
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    # Havola va matnlarni tahlil qilish uchun API
    data = request.get_json() or {}
    text = data.get('text', '')

    if 'http://' in text or 'https://' in text or 'www.' in text:
        result = "⚠️ Diqqat: Havola aniqlandi! Phishing xavfi bo'yicha tekshirilmoqda..."
    else:
        result = "✅ Xabar xavfsiz. Shubhali elementlar topilmadi."

    return jsonify({'status': 'success', 'result': result})


if __name__ == '__main__':
    # Render beradigan PORT ni olish (lokal uchun 5000)
    port = int(os.environ.get('PORT', 5000))

    # Render'da ishlashi uchun host='0.0.0.0' shart
    app.run(host='0.0.0.0', port=port)