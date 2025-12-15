import os
import json
import logging
import random
from datetime import datetime
from typing import Dict, Any, Optional, Final

from telegram import Update, ChatMember
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# =====================================================
# LOGGING
# =====================================================
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# =====================================================
# SABİTLER / AYARLAR
# =====================================================

# Grubunun ID'sini buraya koy
GROUP_ID: Final[int] = -1003426505501  # ÖRNEK, değiştirmen gerek
GROUP_LINK: Final[str] = "https://t.me/+bA7erSxOfp41YTA0"  # Grup davet linki

# Admin kullanıcı ID'leri (sen kendi ID'ni ekleyebilirsin)
ADMINS = {
    7999336769,  # ÖRNEK ID, değiştir
}

DATA_FILE: Final[str] = "data.json"

# =====================================================
# NMAP PARAMETRE AÇIKLAMALARI
# =====================================================
NMAP_FLAGS_EXPLANATION: Dict[str, str] = {
    "-sS": "SYN taraması (yarı-açık tarama). Hızlı ve genelde daha gizli sayılır.",
    "-sT": "TCP connect() taraması. Basit ama daha belirgin.",
    "-sV": "Servis ve versiyon tespiti yapar.",
    "-O": "Hedef işletim sistemini tahmin etmeye çalışır.",
    "-A": "Agresif tarama: -O, -sV, traceroute vb. birçok özelliği birleştirir.",
    "-Pn": "Ping atlamayı kapatır, host down görünse de tarama yapmaya çalışır.",
    "-sU": "UDP port taraması yapar. Genelde yavaştır.",
    "-p": "Belirli portları taramak için kullanılır. Örn: -p 22,80,443",
    "-v": "Daha detaylı çıktı için verbosity artırır.",
    "-vv": "Çok daha detaylı çıktı.",
    "--open": "Sadece açık portları gösterir.",
}

# =====================================================
# QUIZ SORULARI (Nmap + Güvenlik farkındalığı)
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

# =====================================================
# SENARYOLAR (CTF / Eğitim amaçlı)
# =====================================================
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
        "hint": "OS detection parametresini düşün.",
        "expected_example": "nmap -O 10.10.30.7",
    },
]

# =====================================================
# BASİT JSON "VERİTABANI"
# =====================================================

def load_data() -> Dict[str, Any]:
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "global_stats": {"total_commands": 0, "total_quizzes": 0}}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading data.json: {e}")
        return {"users": {}, "global_stats": {"total_commands": 0, "total_quizzes": 0}}


def save_data(data: Dict[str, Any]) -> None:
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error saving data.json: {e}")


def get_user_record(user_id: int) -> Dict[str, Any]:
    data = load_data()
    uid = str(user_id)
    if "users" not in data:
        data["users"] = {}
    if uid not in data["users"]:
        data["users"][uid] = {
            "commands_used": 0,
            "quizzes_taken": 0,
            "quizzes_correct": 0,
            "last_command": None,
            "last_quiz_result": None,
        }
        save_data(data)
    return data["users"][uid]


def update_user_record(user_id: int, updates: Dict[str, Any]) -> None:
    data = load_data()
    uid = str(user_id)
    if "users" not in data:
        data["users"] = {}
    if uid not in data["users"]:
        data["users"][uid] = {}
    data["users"][uid].update(updates)
    save_data(data)


def increment_user_stat(user_id: int, field: str, amount: int = 1) -> None:
    data = load_data()
    uid = str(user_id)
    if "users" not in data:
        data["users"] = {}
    if uid not in data["users"]:
        data["users"][uid] = {
            "commands_used": 0,
            "quizzes_taken": 0,
            "quizzes_correct": 0,
            "last_command": None,
            "last_quiz_result": None,
        }
    data["users"][uid][field] = data["users"][uid].get(field, 0) + amount

    # global stats
    if "global_stats" not in data:
        data["global_stats"] = {"total_commands": 0, "total_quizzes": 0}
    if field == "commands_used":
        data["global_stats"]["total_commands"] = data["global_stats"].get("total_commands", 0) + amount
    if field == "quizzes_taken":
        data["global_stats"]["total_quizzes"] = data["global_stats"].get("total_quizzes", 0) + amount

    save_data(data)


def get_global_stats() -> Dict[str, Any]:
    data = load_data()
    return data.get("global_stats", {"total_commands": 0, "total_quizzes": 0})


# =====================================================
# GRUP ÜYELİĞİ KONTROLÜ
# =====================================================
async def check_membership(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user:
        return False
    user_id = user.id

    try:
        member: ChatMember = await context.bot.get_chat_member(GROUP_ID, user_id)
        if member.status in ["member", "administrator", "creator"]:
            return True

        await update.message.reply_text(
            f"Bu botu kullanmak için gruba katılmalısın.\n\n👉 {GROUP_LINK}"
        )
        return False

    except Exception as e:
        logger.warning(f"get_chat_member error: {e}")
        await update.message.reply_text(
            f"Bu botu kullanmak için gruba katılmalısın.\n\n👉 {GROUP_LINK}"
        )
        return False


# =====================================================
# NMAP SAHTE ÇIKTI ÜRETİCİ
# =====================================================
def generate_fake_output(cmd: str) -> str:
    cmd_lower = cmd.lower()

    # Biraz daha detaylı, Nmap tarzı sahte çıktılar
    header = (
        "Starting Nmap 7.93 ( https://nmap.org ) at "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    target_line = "Nmap scan report for 10.10.10.10\nHost is up (0.030s latency).\n"
    sep = "-" * 50 + "\n"

    if "-sV" in cmd_lower:
        body = (
            "PORT    STATE SERVICE  VERSION\n"
            "22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)\n"
            "80/tcp  open  http     Apache httpd 2.4.52\n"
            "443/tcp open  ssl/http nginx 1.20.1\n\n"
            "Service detection performed. This is a simulated output for training.\n"
        )
        return header + target_line + body + sep

    if "-sS" in cmd_lower:
        body = (
            "Not shown: 995 closed tcp ports\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
            "443/tcp  open  https\n"
            "3306/tcp open  mysql\n"
            "8080/tcp open  http-proxy\n\n"
            "SYN scan example (simulated). No real target was scanned.\n"
        )
        return header + target_line + body + sep

    if "-sU" in cmd_lower:
        body = (
            "Warning: UDP scan is often slow. This is only a simulated example.\n"
            "PORT      STATE         SERVICE\n"
            "53/udp    open          domain\n"
            "123/udp   open          ntp\n"
            "161/udp   open          snmp\n"
            "1900/udp  open|filtered upnp\n\n"
            "UDP scan result (fake, for training).\n"
        )
        return header + target_line + body + sep

    if "-A" in cmd_lower or "-O" in cmd_lower:
        body = (
            "PORT    STATE SERVICE  VERSION\n"
            "22/tcp  open  ssh      OpenSSH 8.2 (protocol 2.0)\n"
            "80/tcp  open  http     Apache httpd 2.4.52\n"
            "443/tcp open  ssl/http nginx 1.20.1\n\n"
            "Device type: general purpose\n"
            "Running: Linux 5.X\n"
            "OS CPE: cpe:/o:linux:linux_kernel:5\n"
            "OS details: Linux 5.4 - 5.18\n\n"
            "Aggressive scan (simulated OS detection). No real host probed.\n"
        )
        return header + target_line + body + sep

    body = (
        "PORT    STATE SERVICE\n"
        "22/tcp  open  ssh\n"
        "80/tcp  open  http\n"
        "443/tcp open  https\n\n"
        "Generic fake result. Use parameters like -sV, -sS, -O, -A for more examples.\n"
    )
    return header + target_line + body + sep


def explain_flags(cmd: str) -> str:
    parts = cmd.split()
    explanations = []

    for p in parts:
        if p in NMAP_FLAGS_EXPLANATION:
            explanations.append(f"{p}: {NMAP_FLAGS_EXPLANATION[p]}")
        if p.startswith("-p") and p != "-p":
            explanations.append("-p: Belirli portları taramak için kullanılır (örn: -p 22,80,443).")

    if not explanations:
        return "Bu komutta bilinen bir Nmap parametresi tespit edemedim. Sadece hedef yazılmış olabilir."

    return "\n".join(explanations)


# =====================================================
# KOMUT HANDLER'LARI
# =====================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    name = user.full_name if user else "kullanıcı"

    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/start"})

    text = (
        f"Merhaba {name}, Nmap Eğitim Botuna hoş geldin.\n\n"
        "Bu bot:\n"
        "- Gerçek sistemlere tarama yapmaz.\n"
        "- Nmap komutlarını açıklar.\n"
        "- Örnek (simüle) çıktılar üretir.\n"
        "- Quiz ve senaryolarla seni destekler.\n\n"
        "Başlamak için:\n"
        "- /help ile komutları gör\n"
        "- /nmap -sV 10.10.10.10 örneğini dene\n"
        "- /quiz ile kendini test et\n"
        "- /scenario ile eğitim senaryosu gör\n\n"
        "⚠️ Uyarı: İzinsiz tarama yapmak hem etik değildir hem de hukuki sorun doğurabilir."
    )
    await update.message.reply_text(text)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/help"})

    text = (
        "Komut listesi:\n\n"
        "/start - Bot hakkında bilgi\n"
        "/help - Bu yardım menüsü\n"
        "/flags - Sık kullanılan Nmap parametreleri\n"
        "/nmap <parametreler> <hedef> - Komutu açıkla + sahte çıktı üret\n"
        "   Örn: /nmap -sV 10.10.10.10\n"
        "/quiz - Nmap / güvenlik farkındalığı quiz'i\n"
        "/stats - Kendi kullanım istatistiklerini gör\n"
        "/scenario - Eğitim amaçlı mini senaryolar\n\n"
        "Admin komutları:\n"
        "/admin_stats - Global kullanım istatistikleri (sadece admin için)\n"
    )
    await update.message.reply_text(text)


async def flags_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/flags"})

    lines = ["Sık kullanılan Nmap parametreleri:\n"]
    for flag, desc in NMAP_FLAGS_EXPLANATION.items():
        lines.append(f"{flag}: {desc}")
    await update.message.reply_text("\n".join(lines))


async def nmap_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/nmap"})

    message_text = update.message.text.strip()
    cmd_part = message_text.replace("/nmap", "", 1).strip()

    if not cmd_part:
        await update.message.reply_text(
            "Lütfen /nmap komutundan sonra Nmap parametrelerini ve hedefi yaz.\n"
            "Örn: /nmap -sV 10.10.10.10"
        )
        return

    explanation = explain_flags(cmd_part)
    fake_output = generate_fake_output(cmd_part)

    response = (
        f"Girdiğin Nmap komutu:\n"
        f"`nmap {cmd_part}`\n\n"
        f"Parametre açıklamaları:\n{explanation}\n\n"
        f"Örnek (simüle) Nmap çıktısı:\n"
        f"```text\n{fake_output}```\n"
        f"⚠️ Bu çıktılar GERÇEK tarama değildir, tamamen eğitim amaçlıdır.\n"
        f"İzinsiz tarama yapmak yasa dışıdır ve etik değildir."
    )

    await update.message.reply_markdown(response)


# -----------------------------------------------------
# QUIZ (Soru-cevap)
# -----------------------------------------------------
async def quiz_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/quiz"})

    question = random.choice(QUIZ_QUESTIONS)
    q_id = QUIZ_QUESTIONS.index(question)

    # Soru bilgisini context.user_data'ya kaydedelim
    context.user_data["current_quiz"] = {
        "id": q_id,
        "question": question["question"],
        "answer": question["answer"],
    }

    increment_user_stat(user.id, "quizzes_taken", 1)

    text = question["question"] + "\n\n" + "\n".join(question["options"]) + "\n\nCevabını 1-4 arasında bir sayı olarak yaz."
    await update.message.reply_text(text)


async def handle_quiz_answer(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "current_quiz" not in context.user_data:
        # quiz modunda değil
        return

    if not await check_membership(update, context):
        return

    user = update.effective_user
    answer_text = update.message.text.strip()

    if not answer_text.isdigit():
        await update.message.reply_text("Lütfen cevabını 1-4 arasında bir sayı olarak yaz.")
        return

    chosen = int(answer_text)
    quiz_data = context.user_data.get("current_quiz")
    q_id = quiz_data["id"]
    correct_answer = QUIZ_QUESTIONS[q_id]["answer"]

    explanation = QUIZ_QUESTIONS[q_id]["explanation"]

    result_text = ""
    if chosen == correct_answer:
        result_text = "Doğru cevap! Güzel iş."
        increment_user_stat(user.id, "quizzes_correct", 1)
        update_user_record(user.id, {"last_quiz_result": "Doğru"})
    else:
        result_text = f"Yanlış cevap. Doğru cevap: {correct_answer}."
        update_user_record(user.id, {"last_quiz_result": "Yanlış"})

    # Quiz bitti, current_quiz'i temizle
    context.user_data.pop("current_quiz", None)

    await update.message.reply_text(f"{result_text}\n\nAçıklama: {explanation}")


# -----------------------------------------------------
# SENARYO KOMUTU
# -----------------------------------------------------
async def scenario_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/scenario"})

    scenario = random.choice(SCENARIOS)

    text = (
        f"Senaryo #{scenario['id']} - {scenario['title']}\n\n"
        f"{scenario['description']}\n\n"
        f"İpucu istersen: {scenario['hint']}\n"
        f"Örnek cevap komutu (sadece fikir): {scenario['expected_example']}"
    )

    await update.message.reply_text(text)


# -----------------------------------------------------
# KULLANICI İSTATİSTİKLERİ
# -----------------------------------------------------
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_membership(update, context):
        return

    user = update.effective_user
    increment_user_stat(user.id, "commands_used", 1)
    update_user_record(user.id, {"last_command": "/stats"})

    rec = get_user_record(user.id)
    text = (
        f"Kullanıcı istatistiklerin:\n\n"
        f"- Toplam komut kullanımı: {rec.get('commands_used', 0)}\n"
        f"- Çözülen quiz sayısı: {rec.get('quizzes_taken', 0)}\n"
        f"- Doğru quiz sayısı: {rec.get('quizzes_correct', 0)}\n"
        f"- Son komut: {rec.get('last_command', 'Yok')}\n"
        f"- Son quiz sonucu: {rec.get('last_quiz_result', 'Yok')}\n"
    )
    await update.message.reply_text(text)


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
        "Global bot istatistikleri:\n\n"
        f"- Toplam kullanıcı sayısı: {total_users}\n"
        f"- Toplam komut kullanımı: {global_stats.get('total_commands', 0)}\n"
        f"- Toplam quiz sayısı: {global_stats.get('total_quizzes', 0)}\n"
    )
    await update.message.reply_text(text)


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
        "Komut tanınmadı.\n"
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

    app.run_polling()


if __name__ == "__main__":
    main()
