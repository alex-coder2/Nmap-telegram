import subprocess
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext

TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"

def start(update: Update, context: CallbackContext):
    update.message.reply_text("🔧 Bot çalışıyor. /mass_account_follow komutunu kullan.")

def mass_account_follow(update: Update, context: CallbackContext):
    update.message.reply_text("🚀 Hesap üretimi başlatılıyor... Lütfen bekleyin.")
    try:
        result = subprocess.run(["python", "instagram_farmer.py"], capture_output=True, text=True, timeout=300)
        update.message.reply_text(f"✅ İşlem tamamlandı.\nÇıktı:\n{result.stdout}")
        if result.stderr:
            update.message.reply_text(f"⚠️ Hatalar var:\n{result.stderr}")
    except subprocess.TimeoutExpired:
        update.message.reply_text("⏰ İşlem zaman aşımına uğradı.")
    except Exception as e:
        update.message.reply_text(f"❌ Hata: {str(e)}")

def main():
    updater = Updater(TELEGRAM_TOKEN, use_context=True)
    dp = updater.dispatcher
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("mass_account_follow", mass_account_follow))
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()