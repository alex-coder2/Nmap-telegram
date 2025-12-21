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

# === GEÇİCİ E-POSTA ===
def create_temp_email():
    response = requests.get("https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1")
    email = response.json()[0]
    login, domain = email.split("@")
    return email, login, domain

def get_verification_code(login, domain):
    for _ in range(10):
        time.sleep(5)
        inbox = requests.get(f"https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}")
        messages = inbox.json()
        if messages:
            msg_id = messages[0]['id']
            msg = requests.get(f"https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={msg_id}")
            content = msg.json()['body']
            import re
            code = re.search(r'\b\d{6}\b', content)
            return code.group() if code else None
    return None

# === DRIVER SETUP ===
def setup_driver(proxy):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
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
    time.sleep(DELAY*2)

    code = get_verification_code(*email.split("@"))
    if code:
        inputs = driver.find_elements(By.XPATH, "//input[@aria-label='Confirmation Code']")
        for i, digit in enumerate(code):
            inputs[i].send_keys(digit)
        time.sleep(DELAY)
        driver.find_element(By.XPATH, "//button[contains(text(),'Confirm')]").click()
        time.sleep(DELAY)
        return True
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
        proxy = random.choice(PROXIES)
        driver = setup_driver(proxy)
        try:
            email, login, domain = create_temp_email()
            username = generate_random_username()
            password = "Aali1234**"
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