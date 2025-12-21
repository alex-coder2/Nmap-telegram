import random
import time
import string
import requests
import re
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# === AYARLAR ===
TARGET_ACCOUNT = "ali.cagan1427"
DELAY = 3
PASSWORD = "Ali123**"
PROXIES = [
    "http://138.197.150.238:80",
    "http://167.99.31.193:80",
    "http://159.89.113.105:80",
    "http://159.203.124.150:80"
]

# === GEÇİCİ E-POSTA: TempMail.ninja ===
def create_temp_email():
    url = "https://www.tempmail.ninja/api/v1/mailbox"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        data = res.json()
        email = data.get("email")
        if email:
            print(f"📬 Temp e-posta alındı: {email}")
            return email
        print("⚠️ Geçersiz e-posta yanıt.")
        return None
    except Exception as e:
        print(f"⛔ TempMail.ninja yanıt vermedi: {e}")
        return None

# === (Şimdilik kod okuma pasif, ileride entegre edebiliriz) ===
def get_verification_code():
    print("🚨 TempMail.ninja'da kod okuma henüz desteklenmiyor.")
    return None

# === DRIVER SETUP ===
def setup_driver(proxy=None):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    if proxy:
        options.add_argument(f'--proxy-server={proxy}')
    driver = webdriver.Chrome(options=options)
    return driver

# === USERNAME GENERATOR ===
def generate_random_username():
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"GALIX_{suffix}"

# === REGISTER ===
def register_instagram_account(driver, email, username, password):
    driver.get("https://www.instagram.com/accounts/emailsignup/")
    time.sleep(DELAY)
    driver.find_element(By.NAME, "emailOrPhone").send_keys(email)
    time.sleep(1)
    driver.find_element(By.NAME, "fullName").send_keys(username)
    time.sleep(1)
    driver.find_element(By.NAME, "username").send_keys(username)
    time.sleep(1)
    driver.find_element(By.NAME, "password").send_keys(password)
    time.sleep(1)
    driver.find_element(By.XPATH, "//button[contains(text(),'Sign up')]").click()
    time.sleep(DELAY * 2)

    print("🔔 Lütfen doğrulama kodunu manuel olarak girin...")
    input("✅ Doğrulama tamamlandıysa ENTER tuşuna basın...")

    return True

# === LOGIN ===
def login_to_instagram(driver, username, password):
    driver.get("https://www.instagram.com/accounts/login/")
    time.sleep(DELAY)
    driver.find_element(By.NAME, "username").send_keys(username)
    time.sleep(1)
    driver.find_element(By.NAME, "password").send_keys(password)
    time.sleep(1)
    driver.find_element(By.XPATH, "//button[@type='submit']").click()
    time.sleep(DELAY * 2)

# === FOLLOW ===
def follow_target_user(driver, target):
    driver.get(f"https://www.instagram.com/{target}/")
    time.sleep(DELAY)
    try:
        follow_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, "//button[contains(text(),'Follow')]"))
        )
        follow_button.click()
        print(f"✅ @{target} takip edildi.")
    except Exception as e:
        print(f"❌ Takip başarısız: {e}")

# === MAIN LOOP ===
def main():
    for i in range(5):
        print(f"[{i+1}/5] Yeni hesap oluşturuluyor...")
        proxy = random.choice(PROXIES) if PROXIES else None
        driver = setup_driver(proxy)

        try:
            email = create_temp_email()
            if not email:
                print(f"[{i+1}/5] ❌ E-posta alınamadı.")
                driver.quit()
                continue

            username = generate_random_username()
            password = PASSWORD
            print(f"[{i+1}/5] E-posta: {email}, Kullanıcı: {username}")

            if not register_instagram_account(driver, email, username, password):
                print(f"[{i+1}/5] ❌ Kayıt başarısız.")
                driver.quit()
                continue

            login_to_instagram(driver, username, password)
            follow_target_user(driver, TARGET_ACCOUNT)
            driver.get("https://www.instagram.com/accounts/logout/")
            print(f"[{i+1}/5] ✅ @{username} çıkış yapıldı.")

        except Exception as e:
            print(f"[{i+1}/5] ❌ Hata: {e}")
        finally:
            driver.quit()

if __name__ == "__main__":
    main()