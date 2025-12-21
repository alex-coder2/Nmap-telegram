import random
import time
import string
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

# === AYARLAR ===
TARGET_ACCOUNT = "ali.cagan1427"
DELAY = 3
PROXIES = [
    "http://138.197.150.238:80",
    "http://167.99.31.193:80",
    "http://159.89.113.105:80",
    "http://159.203.124.150:80"
]

# === GEÇİCİ E-POSTA (Guerrillamail) ===
session_id = None

def create_temp_email():
    global session_id
    try:
        response = requests.get("https://www.guerrillamail.com/ajax.php?f=get_email_address", timeout=10)
        response.raise_for_status()
        data = response.json()
        session_id = data.get("sid")
        email = data.get("email_addr")
        if not email or not session_id:
            print("⚠️ Geçersiz e-posta veya session.")
            return None
        return email
    except Exception as e:
        print(f"⛔ Guerrillamail e-posta alınamadı: {e}")
        return None

def get_verification_code():
    global session_id
    if not session_id:
        return None
    url = f"https://www.guerrillamail.com/ajax.php?f=get_emails&sid_token={session_id}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        emails = response.json().get("list", [])
        for email in emails:
            if "Instagram" in email.get("mail_subject", ""):
                body = email.get("mail_body", "")
                import re
                code = re.search(r'\b\d{6}\b', body)
                if code:
                    return code.group()
        return None
    except Exception as e:
        print(f"⛔ Kod okunamadı: {e}")
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

    # Doğrulama kodu bekle
    for _ in range(10):
        code = get_verification_code()
        if code:
            inputs = driver.find_elements(By.XPATH, "//input[@aria-label='Confirmation Code']")
            for i, digit in enumerate(code):
                inputs[i].send_keys(digit)
            time.sleep(DELAY)
            driver.find_element(By.XPATH, "//button[contains(text(),'Confirm')]").click()
            time.sleep(DELAY)
            return True
        time.sleep(5)
    return False

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
        follow_button = driver.find_element(By.XPATH, "//button[contains(text(),'Follow')]")
        follow_button.click()
        print(f"@{target} takip edildi.")
    except Exception as e:
        print(f"Takip başarısız: {e}")

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
            password = "Ali123**"
            print(f"[{i+1}/5] E-posta: {email}")

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