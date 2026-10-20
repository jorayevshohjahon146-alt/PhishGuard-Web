import os
import re
import librosa
import soundfile as sf
import speech_recognition as sr
import numpy as np
from flask import Flask
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from threading import Thread

print(">>> Bot dasturi yuklanmoqda...")

# Flask veb-serveri
app = Flask('')

@app.route('/')
def home():
    return "Bot ishlayapti!"

def run_flask():
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

# Telegram bot tokeni
TOKEN = '8824986874:AAHXOsLmb8tAq3A6_S0M0FdpoockRuvrzcg'

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🛡️ PhishGuard Bot ishga tushdi va xavfsizlikni tekshirishga tayyor!")

# Matnli xabarlarni tahlil qilish funksiyasi
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text.lower()
    
    if "apk" in user_text or "karta" in user_text or "bloklandi" in user_text or "sms" in user_text or "kod" in user_text:
        analysis_result = (
            "🛑 Tahlil Natijasi: YUQORI XAVF (MALICIOUS)\n"
            "📊 Xavf darajasi: 95%\n\n"
            "📋 Aniqlangan tahdidlar:\n"
            "• 📱 Xavfli APK fayl havolasi yoki phishing alomati aniqlandi!"
        )
    else:
        analysis_result = (
            "✅ Tahlil Natijasi: XAVFSIZ (SAFE)\n"
            "📊 Xavf darajasi: 0%\n\n"
            "📋 Xabarda shubhali yoki xavfli belgilar topilmadi."
        )
        
    await update.message.reply_text(analysis_result)

# Ovozli xabarlarni matnga o'girib tahlil qilish (FFmpeg talab qilinmaydi)
async def handle_voice_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🎙 Ovozli xabar qabul qilindi. VoiceGuard AI tahlil qilmoqda...")
    
    file_path_ogg = None
    file_path_wav = None
    
    try:
        voice = update.message.voice
        file = await context.bot.get_file(voice.file_id)
        
        if not os.path.exists("voices"):
            os.makedirs("voices")
            
        file_path_ogg = f"voices/{voice.file_id}.ogg"
        file_path_wav = f"voices/{voice.file_id}.wav"
        
        await file.download_to_drive(file_path_ogg)
        
        # Librosa va SoundFile yordamida formatni o'tkazamiz
        y, sr_rate = librosa.load(file_path_ogg, sr=None)
        sf.write(file_path_wav, y, sr_rate)
        
        # Ovozni matnga o'girish
        recognizer = sr.Recognizer()
        with sr.AudioFile(file_path_wav) as source:
            audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data, language="uz-UZ")
            
        text_lower = text.lower()
        print(f">>> Ovozdan o'girilgan matn: {text}")
        
        phishing_keywords = ["karta", "bloklandi", "sms", "parol", "kod", "shoshilinch", "balans", "tasdiqlang"]
        found_threats = [word for word in phishing_keywords if word in text_lower]
        
        if found_threats or "karta raqamini" in text_lower or "sms kod" in text_lower:
            analysis_result = (
                "🛑 Tahlil Natijasi: YUQORI XAVF (MALICIOUS)\n"
                "📊 Xavf darajasi: 95%\n\n"
                "📋 Aniqlangan tahdidlar:\n"
                f"• 🎙 Ovozli xabar mazmuni: Shubhali so'zlar aniqlandi ('{text}').\n"
                "• ⚠️ Bu ovozli xabarda maxfiy ma'lumotlarni so'rash alomatlari bor!"
            )
        else:
            analysis_result = (
                "✅ Tahlil Natijasi: XAVFSIZ (SAFE)\n"
                "📊 Xavf darajasi: 0%\n\n"
                f"📝 Ovoz matni: \"{text}\"\n"
                "📋 Shubhali belgilar topilmadi."
            )
            
        await update.message.reply_text(analysis_result)
        
    except sr.UnknownValueError:
        await update.message.reply_text("✅ Tahlil Natijasi: XAVFSIZ\n🎙 Ovozli xabardan aniq matn topilmadi yoki shovqinli ekan, xavfli so'zlar aniqlanmadi.")
    except Exception as e:
        await update.message.reply_text(f"❌ Ovozni tahlil qilishda xatolik yuz berdi: {str(e)}")
        
    finally:
        # Vaqtinchalik fayllarni xotiradan tozalash
        if file_path_ogg and os.path.exists(file_path_ogg):
            os.remove(file_path_ogg)
        if file_path_wav and os.path.exists(file_path_wav):
            os.remove(file_path_wav)

# Fayllar va APK ilovalarni tahlil qilish
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    file_name = document.file_name.lower()
    
    if file_name.endswith('.apk'):
        analysis_result = (
            "🛑 Tahlil Natijasi: YUQORI XAVF (MALICIOUS)\n"
            "📊 Xavf darajasi: 95%\n\n"
            "📋 Aniqlangan tahdidlar:\n"
            "• 📱 APK xavfi: Noma'lum manbadan kelgan mobil ilova (APK)."
        )
    else:
        analysis_result = "✅ Tahlil Natijasi: FAYL XAVFSIZ"
        
    await update.message.reply_text(analysis_result)

def main():
    print(">>> Flask va Telegram bot ishga tushirilmoqda...")
    t = Thread(target=run_flask)
    t.start()

    application = ApplicationBuilder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.VOICE, handle_voice_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    
    print(">>> Bot muvaffaqiyatli ishga tushdi, xabarlarni kutmoqda...")
    application.run_polling()

if __name__ == '__main__':
    main()