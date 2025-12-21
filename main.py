import logging
import os
import json
import random
from datetime import datetime
from dotenv import load_dotenv
import asyncio
import subprocess
import shlex

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# =====================================================
# GİRİŞ AYARLARI VE LOG
# =====================================================

load_dotenv()

# Logging ayarları
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Ortam değişkenleri
REQUIRED_ENV_VARS = ["BOT_TOKEN"]
for var in REQUIRED_ENV_VARS:
    if not os.getenv(var):
        raise RuntimeError(f"{var} ortam değişkeni tanımlanmamış!")

# =====================================================
# VERİ YÖNETİMİ
# =====================================================

DATA_FILE = "bot_data.json"

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "global_stats": {}}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_user_record(user_id, updates):
    data = load_data()
    user_id_str = str(user_id)
    if "users" not in data:
        data["users"] = {}
    if user_id_str not in data["users"]:
        data["users"][user_id_str] = {
            "join_date": datetime.now().isoformat(),
            "commands_used": 0,
            "quizzes_taken": 0,
            "last_command": None
        }
    for key, value in updates.items():
        data["users"][user_id_str][key] = value
    save_data(data)

def increment_user_stat(user_id, stat, amount=1):
    data = load_data()
    user_id_str = str(user_id)
    if "users" in data and user_id_str in data["users"]:
        if stat in data["users"][user_id_str]:
            data["users"][user_id_str][stat] += amount
        else:
            data["users"][user_id_str][stat] = amount
        save_data(data)

def get_global_stats():
    data = load_data()
    return data.get("global_stats", {})

def increment_global_stat(stat, amount=1):
    data = load_data()
    if "global_stats" not in data:
        data["global_stats"] = {}
    if stat in data["global_stats"]:
        data["global_stats"][stat] += amount
    else:
        data["global_stats"][stat] = amount
    save_data(data)

# =====================================================
# YETKİLİ KULLANICILAR (ADMIN ID'leri buraya ekleyin)
# =====================================================

ADMINS = [int(os.getenv("ADMIN_ID"))] if os.getenv("ADMIN_ID") else []

# =====================================================
# GRUP ÜYELİĞİ KONTROLÜ (Opsiyonel)
# Bu özellik için BOT_TOKEN izinleri gerekir
# =====================================================

async def check_membership(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    REQUIRED_CHAT_ID = os.getenv("REQUIRED_CHAT_ID")
    GROUP_INVITE_LINK = os.getenv("GROUP_INVITE_LINK", "https://t.me/+bA7erSxOfp41YTA0")

    if not REQUIRED_CHAT_ID:
        return True  # Zorunluluk yoksa herkese açık

    try:
        user_id = update.effective_user.id
        chat_member = await context.bot.get_chat_member(chat_id=REQUIRED_CHAT_ID, user_id=user_id)
        if chat_member.status in ['member', 'administrator', 'creator']:
            return True
        else:
            # Grupta değilse yönlendir
            await update.message.reply_text(
                "❌ Bu botu kullanabilmek için gruba katılmış olmanız gerekiyor.\n\n"
                f"👉 {GROUP_INVITE_LINK}"
            )
            return False
    except Exception as e:
        logger.error(f"Üyelik kontrol hatası: {e}")
        await update.message.reply_text("❌ Üyelik kontrolü sırasında bir hata oluştu.")
        return False
# =====================================================
# MESAJ GÖNDERME (HATA ÖNLEYİCİ)
# =====================================================

async def send_message_safely(update: Update, text: str):
    try:
        if len(text) > 4096:
            parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
            for part in parts:
                await update.message.reply_text(part, parse_mode="Markdown")
        else:
            await update.message.reply_text(text, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Mesaj gönderme hatası: {e}")
        await update.message.reply_text("❌ Mesaj gönderilirken bir hata oluştu.")

# =====================================================
# İZİN VERİLEN NMAP PARAMETRELERİ (GÜVENLİK İÇİN)
# =====================================================

ALLOWED_NMAP_FLAGS = [
    "-sT", "-sS", "-sU", "-sV", "-O", "-A", "-p", "-F", "-T4", "-T5",
    "--open", "-v", "-vv", "-6", "-sn", "-Pn", "-n",
]

# =====================================================
# KOMUTLAR VE BİLGİLER
# =====================================================

NMAP_COMMANDS = {
    "nmap -sS target": "SYN taraması (yarı açık)",
    "nmap -sT target": "TCP connect() taraması",
    "nmap -sU target": "UDP taraması",
    "nmap -p 80,443 target": "Belirli portlara tarama",
    "nmap -A target": "Agresif tarama (OS + Versiyon + Script)",
    "nmap -O target": "İşletim sistemi tespiti",
    "nmap -v target": "Detaylı çıktı",
    "nmap -sn target": "Ping taraması",
    "nmap -Pn target": "Canlı host kontrolü olmadan tarama",
}

# =====================================================
# BAŞLANGIÇ KOMUTU
# =====================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    update_user_record(user.id, {"last_command": "/start"})
    welcome_text = (
        f"👋 Merhaba {user.first_name}!\n\n"
        "Ben eğitim amaçlı bir Nmap botuyum.\n"
        "Komutlarımı görmek için /help yazabilirsin.\n"
        "Nmap öğrenmek istersen /quiz veya /scenario komutlarını kullan."
    )
    await update.message.reply_text(welcome_text)

# -----------------------------------------------------
# YARDIM KOMUTU
# -----------------------------------------------------

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/help"})
    help_text = (
        "🔍 *Nmap Telegram Botu Komutları:*\n\n"
        "/start - Başlangıç mesajı\n"
        "/help - Bu yardım menüsü\n"
        "/flags - Yaygın Nmap parametreleri ve açıklamaları\n"
        "/nmap [target] [flags] - Nmap taraması başlat\n"
        "/quiz - Güvenlik bilgi yarışması\n"
        "/scenario - Gerçek senaryolar ve pratik\n"
        "/stats - Kullanım istatistiklerin\n"
        "\n⚠️ *Not:* Bu bot sadece eğitim ve bilgilendirme amaçlıdır. "
        "İzinsiz sistem taramaları yasal değildir."
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")

# -----------------------------------------------------
# FLAG AÇIKLAMALARI
# -----------------------------------------------------

async def flags_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/flags"})
    flags_info = (
        "🏁 *Yaygın Nmap Parametreleri:*\n\n"
        "-sS : SYN taraması (yarı açık)\n"
        "-sT : TCP connect() taraması\n"
        "-sU : UDP taraması\n"
        "-sV : Servis versiyon tespiti\n"
        "-O  : İşletim sistemi tespiti\n"
        "-A  : Agresif tarama (OS+Versiyon+Script)\n"
        "-p  : Port belirleme (örnek: -p 80,443)\n"
        "-F  : Hızlı tarama\n"
        "-T4 : Daha hızlı zamanlayıcı\n"
        "-T5 : En hızlı zamanlayıcı\n"
        "-sn : Ping taraması (port taramaz)\n"
        "-Pn : Canlı host kontrolü yapmaz\n"
        "-n  : DNS çözümleme yapmaz\n"
        "-v  : Verbose (detay verir)\n"
        "--open : Sadece açık portları gösterir\n"
    )
    await update.message.reply_text(flags_info, parse_mode="Markdown")

# -----------------------------------------------------
# NMAP KOMUTU (GERÇEK TARAMA)
# -----------------------------------------------------

async def nmap_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    increment_global_stat("total_commands", 1)
    update_user_record(user.id, {"last_command": "/nmap"})

    if len(context.args) < 1:
        await update.message.reply_text("❌ Geçersiz kullanım.\nÖrnek: `/nmap example.com -p 80,443`", parse_mode="Markdown")
        return

    # Girdiyi al ve temizle
    raw_input = " ".join(context.args)
    try:
        # Güvenlik için shlex.split kullanarak komutu parçala
        args = shlex.split(raw_input)
        target = args[0]  # İlk argüman hedeftir
        flags = args[1:]  # Diğerleri flaglerdir

        # İzin verilen flagleri kontrol et
        for flag in flags:
            if flag not in ALLOWED_NMAP_FLAGS:
                await update.message.reply_text(
                    f"❌ Geçersiz veya izin verilmeyen parametre: `{flag}`\n"
                    f"İzin verilen parametreler: {', '.join(ALLOWED_NMAP_FLAGS)}",
                    parse_mode="Markdown"
                )
                return

        # Hedef doğrulama (basit)
        if not target or len(target) < 3 or " " in target:
            await update.message.reply_text("❌ Geçersiz hedef.")
            return

        # Nmap komutunu oluştur
        cmd = ["nmap"] + flags + [target]
        
        # Kullanıcıya bilgi ver
        await update.message.reply_text(f"⏱️ Tarama başlatılıyor: `{' '.join(cmd)}`", parse_mode="Markdown")

        # Komutu async çalıştır
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Zaman aşımı ile çalıştır
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await update.message.reply_text("⏱️ Tarama zaman aşımına uğradı (120 saniye).")
            return

        # Çıktıyı kullanıcıya gönder
        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 4000:  # Telegram mesaj sınırı
                # Büyük çıktılar için dosya olarak gönder
                filename = f"nmap_{target.replace('/', '_').replace(':', '_')}.txt"
                with open(filename, 'w') as f:
                    f.write(f"--- Nmap Taraması: {target} ---\n")
                    f.write(f"Komut: {' '.join(cmd)}\n")
                    f.write(f"Tarih: {datetime.now().isoformat()}\n")
                    f.write("-"*40 + "\n")
                    f.write(output)
                with open(filename, 'rb') as f:
                    await update.message.reply_document(document=f, filename=filename, caption="🔍 Nmap taraması tamamlandı.")
                os.remove(filename)  # Temizle
            else:
                final_output = (
                    f"🔍 *Nmap Taraması Tamamlandı*\n"
                    f"*Hedef:* `{target}`\n"
                    f"*Komut:* `{' '.join(cmd)}`\n\n"
                    f"```\n{output}\n```"
                )
                await send_message_safely(update, final_output)
        else:
            error_output = stderr.decode()
            await update.message.reply_text(f"❌ Nmap taraması başarısız oldu:\n```\n{error_output}\n```")

    except Exception as e:
        await update.message.reply_text(f"💥 Bir hata oluştu:\n```\n{str(e)}\n```")

# -----------------------------------------------------
# İSTATİSTİK KOMUTU
# -----------------------------------------------------

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/stats"})
    data = load_data()
    user_id_str = str(user.id)
    user_data = data.get("users", {}).get(user_id_str, {})
    stats_text = (
        f"📊 *İstatistiklerin*\n\n"
        f"🆔 ID: `{user.id}`\n"
        f"📅 Katılım: {user_data.get('join_date', 'N/A')}\n"
        f"🔢 Komut kullanımı: {user_data.get('commands_used', 0)}\n"
        f"🧠 Quiz denemeleri: {user_data.get('quizzes_taken', 0)}\n"
        f"📋 Son komut: {user_data.get('last_command', 'N/A')}"
    )
    await update.message.reply_text(stats_text, parse_mode="Markdown")

# =====================================================
# QUIZ İŞLEVLERİ
# =====================================================

QUIZ_QUESTIONS = [
    {
        "question": "Nmap'te -sS parametresi ne tür bir taramadır?",
        "options": [
            "1) TCP connect() taraması",
            "2) SYN (yarı-açık) tarama",
            "3) UDP taraması",
            "4) Ping taraması",
        ],
        "answer": 2,
        "explanation": "-sS SYN (yarı-açık) taramadır, genelde daha stealth kabul edilir."
    },
    {
        "question": "Hangi parametre servis ve versiyon tespiti yapar?",
        "options": [
            "1) -sV",
            "2) -O",
            "3) -A",
            "4) -sU",
        ],
        "answer": 1,
        "explanation": "-sV, açık portlardaki servislerin versiyonlarını tespit etmeye çalışır."
    },
    {
        "question": "-O parametresi ne için kullanılır?",
        "options": [
            "1) Hızlı tarama",
            "2) İşletim sistemi tespiti",
            "3) UDP portları tarama",
            "4) Sadece açık portları gösterme",
        ],
        "answer": 2,
        "explanation": "-O parametresi OS detection, yani işletim sistemi tespiti içindir."
    },
    {
        "question": "İzinsiz port taraması yapmak nasıldır?",
        "options": [
            "1) Tamamen serbesttir, sıkıntı yok",
            "2) Sadece arkadaşlara yapılabilir",
            "3) Yasal ve etik olarak sakıncalıdır",
            "4) Sadece gece yapılırsa sorun olmaz",
        ],
        "answer": 3,
        "explanation": "İzinsiz port taraması hem etik değildir hem de hukuki sorunlara yol açabilir."
    },
    {
        "question": "Nmap ile UDP taraması hangi parametre ile yapılır?",
        "options": [
            "1) -sT",
            "2) -sS",
            "3) -sV",
            "4) -sU",
        ],
        "answer": 4,
        "explanation": "-sU UDP port taraması gerçekleştirir."
    },
]

async def quiz_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    question_data = random.choice(QUIZ_QUESTIONS)
    context.user_data["current_quiz"] = question_data
    increment_user_stat(user.id, "quizzes_taken", 1)
    increment_global_stat("total_quizzes", 1)
    update_user_record(user.id, {"last_command": "/quiz"})

    options_text = "\n".join(question_data["options"])
    text = f"🧠 *Soru:*\n{question_data['question']}\n\n{options_text}\n\nLütfen doğru seçeneğin numarasını yaz."
    await update.message.reply_text(text, parse_mode="Markdown")

async def handle_quiz_answer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if "current_quiz" not in context.user_data:
        return

    answer = update.message.text.strip()
    quiz = context.user_data["current_quiz"]

    correct = str(quiz["answer"])
    if answer == correct:
        result_text = f"✅ Doğru! {quiz['explanation']}"
    else:
        result_text = f"❌ Yanlış! Doğru cevap: {correct}. {quiz['explanation']}"

    await update.message.reply_text(result_text, parse_mode="Markdown")
    del context.user_data["current_quiz"]

# -----------------------------------------------------
# SENARYO İŞLEVLERİ
# -----------------------------------------------------

SCENARIOS = [
    {
        "id": 1,
        "title": "Web sunucusu keşfi",
        "description": (
            "Hedef IP: 10.10.10.10\n"
            "Bu hedefte çalışan web servislerini ve versiyonlarını tespit etmek istiyorsun.\n"
            "Sence hangi Nmap komutunu kullanmak mantıklı olur?"
        ),
        "hint": "Servis ve versiyon tespiti için hangi parametre kullanılır?",
        "expected_example": "nmap -sV 10.10.10.10",
    },
    {
        "id": 2,
        "title": "Açık port taraması (SYN)",
        "description": (
            "Hedef IP: 10.10.20.5\n"
            "Hızlı ve görece gizli bir TCP port taraması yapmak istiyorsun.\n"
            "Hangi tarama tipini kullanabilirsin?"
        ),
        "hint": "SYN taraması için hangi parametreyi hatırlıyorsun?",
        "expected_example": "nmap -sS 10.10.20.5",
    },
    {
        "id": 3,
        "title": "OS tespiti",
        "description": (
            "Hedef IP: 10.10.30.7\n"
            "Bu hedefin işletim sistemini yaklaşık olarak tahmin etmek istiyorsun.\n"
            "Nmap komutunda hangi parametre işine yarar?"
        ),
        "hint": "OS Detection hangi parametre ile yapılır?",
        "expected_example": "nmap -O 10.10.30.7",
    }
]

async def scenario_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    scenario = random.choice(SCENARIOS)
    context.user_data["current_scenario"] = scenario
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/scenario"})

    text = (
        f"🎯 *Senaryo #{scenario['id']}*: {scenario['title']}\n\n"
        f"{scenario['description']}\n\n"
        f"💡 İpucu: {scenario['hint']}\n\n"
        "Komutunu yazabilirsin veya örnek görmek için `/example` komutunu kullan."
    )
    await update.message.reply_text(text, parse_mode="Markdown")

# -----------------------------------------------------
# ADMIN İSTATİSTİKLERİ
# -----------------------------------------------------

async def admin_stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return
    user = update.effective_user
    if user.id not in ADMINS:
        await update.message.reply_text("Bu komut sadece adminler içindir.")
        return

    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/admin_stats"})

    global_stats = get_global_stats()
    data = load_data()
    total_users = len(data.get("users", {}))
    text = (
        "📊 *Global bot istatistikleri:*\n\n"
        f"- Toplam kullanıcı sayısı: {total_users}\n"
        f"- Toplam komut kullanımı: {global_stats.get('total_commands', 0)}\n"
        f"- Toplam quiz sayısı: {global_stats.get('total_quizzes', 0)}\n"
    )
    await update.message.reply_text(text, parse_mode="Markdown")

# -----------------------------------------------------
# FALLBACK MESAJ (Komut olmayan metinler)
# -----------------------------------------------------

async def fallback_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Eğer aktif bir quiz varsa, bu metni quiz cevabı olarak değerlendirebiliriz
    if "current_quiz" in context.user_data:
        await handle_quiz_answer(update, context)
        return

    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "text_message"})

    await update.message.reply_text(
        "❌ Komut tanınmadı.\n"
        "Komut listesi için /help yazabilirsin.\n"
        "Quiz denemek için /quiz, senaryo için /scenario kullan."
    )

# =====================================================
# MAIN
# =====================================================

def main():
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN environment variable eksik!")

    app = ApplicationBuilder().token(token).build()

    # Komut handler'ları
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("flags", flags_command))
    app.add_handler(CommandHandler("nmap", nmap_command))
    app.add_handler(CommandHandler("quiz", quiz_command))
    app.add_handler(CommandHandler("scenario", scenario_command))
    app.add_handler(CommandHandler("stats", stats_command))

app.add_handler(CommandHandler("admin_stats", admin_stats_command))

    # Komut olmayan tüm text mesajlar fallback'e gider
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback_message))

    logger.info("Bot başlatılıyor...")
    app.run_polling()

if __name__ == "__main__":
    main()