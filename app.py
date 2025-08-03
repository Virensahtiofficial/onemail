import os
import json
import time
import urllib.parse
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'users'

# Data bestanden paden
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ADMIN_FILE = os.path.join(DATA_DIR, 'admin.json')
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, 'blocked_ips.json')
SHUTDOWN_FILE = os.path.join(DATA_DIR, 'shutdown.json')
RATE_LIMIT_FILE = os.path.join(DATA_DIR, 'rate_limiter.json')
VERIFIED_USERS_FILE = os.path.join(DATA_DIR, 'verified_users.json')

RATE_LIMIT_MAX = 10  # max 10 requests
RATE_LIMIT_WINDOW = 1  # per 1 seconde

# --- Init data folder en bestanden ---
def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def initialize_files():
    ensure_data_dir()
    if not os.path.exists(ADMIN_FILE):
        with open(ADMIN_FILE, 'w') as f:
            json.dump({"password": "admin"}, f)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump([], f)
    if not os.path.exists(SHUTDOWN_FILE):
        with open(SHUTDOWN_FILE, 'w') as f:
            json.dump({"shutdown": False}, f)
    if not os.path.exists(RATE_LIMIT_FILE):
        with open(RATE_LIMIT_FILE, 'w') as f:
            json.dump({}, f)

# Init direct bij import (belangrijk voor Gunicorn!)
initialize_files()

# ----------- Helper functies -----------

def load_json(filename):
    if not os.path.exists(filename):
        # fallback als toch niet bestaat
        with open(filename, 'w') as f:
            json.dump({}, f)
    with open(filename, 'r') as f:
        return json.load(f)

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def create_user_folders(username):
    base = os.path.join(app.config['UPLOAD_FOLDER'], username)
    for folder in ['inbox', 'sent', 'deleted', 'attachments']:
        os.makedirs(os.path.join(base, folder), exist_ok=True)

def get_mail_folder(username, folder):
    return os.path.join(app.config['UPLOAD_FOLDER'], username, folder)

def save_mail(username, folder, mail_obj):
    folder_path = get_mail_folder(username, folder)
    os.makedirs(folder_path, exist_ok=True)
    mail_id = str(int(time.time()*1000))
    with open(os.path.join(folder_path, f'{mail_id}.json'), 'w') as f:
        json.dump(mail_obj, f, indent=4)
    return mail_id

def load_all_mails(username, folder):
    folder_path = get_mail_folder(username, folder)
    mails = []
    verified_users = load_verified_users()
    if not os.path.exists(folder_path):
        return mails
    for filename in sorted(os.listdir(folder_path), reverse=True):
        if filename.endswith('.json'):
            with open(os.path.join(folder_path, filename), 'r') as f:
                mail = json.load(f)
                mail_id = filename[:-5]
                if 'emoji' not in mail:
                    mail['emoji'] = None
                mail['verified'] = mail.get('from') in verified_users
                mails.append({'id': mail_id, **mail})
    return mails
    
def load_single_mail(username, folder, mail_id):
    path = os.path.join(get_mail_folder(username, folder), f'{mail_id}.json')
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return json.load(f)

def delete_mail(username, folder, mail_id):
    src = os.path.join(get_mail_folder(username, folder), f'{mail_id}.json')
    dst = os.path.join(get_mail_folder(username, 'deleted'), f'{mail_id}.json')
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.replace(src, dst)

def load_blocked_ips():
    if not os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump([], f)
    with open(BLOCKED_IPS_FILE) as f:
        return json.load(f)

def save_blocked_ips(ips):
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(ips, f, indent=4)

def load_shutdown_status():
    if not os.path.exists(SHUTDOWN_FILE):
        with open(SHUTDOWN_FILE, 'w') as f:
            json.dump({"shutdown": False}, f)
    with open(SHUTDOWN_FILE) as f:
        return json.load(f).get("shutdown", False)

def save_shutdown_status(status: bool):
    with open(SHUTDOWN_FILE, 'w') as f:
        json.dump({"shutdown": status}, f, indent=4)

def load_rate_limiter():
    if not os.path.exists(RATE_LIMIT_FILE):
        with open(RATE_LIMIT_FILE, 'w') as f:
            json.dump({}, f)
    with open(RATE_LIMIT_FILE) as f:
        return json.load(f)

def save_rate_limiter(data):
    with open(RATE_LIMIT_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def simple_hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f'{salt}${hashed}'

def simple_check_password(stored, password):
    try:
        salt, hashed = stored.split('$')
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except:
        return False

def load_verified_users():
    if not os.path.exists(VERIFIED_USERS_FILE):
        with open(VERIFIED_USERS_FILE, 'w') as f:
            json.dump([], f)
    with open(VERIFIED_USERS_FILE, 'r') as f:
        return json.load(f)

def save_verified_users(users_list):
    with open(VERIFIED_USERS_FILE, 'w') as f:
        json.dump(users_list, f, indent=4)
        
def logged_in():
    return 'username' in session

# ----------- IP Block Middleware -----------

@app.before_request
def block_check():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    blocked_ips = load_blocked_ips()
    shutdown = load_shutdown_status()

    allowed_endpoints = [
        'admin_login', 'admin_panel', 'block_ip', 'unblock_ip',
        'admin_shutdown', 'admin_start', 'static'
    ]

    now = time.time()
    rate_data = load_rate_limiter()
    user_logs = rate_data.get(ip, [])

    # Oude timestamps verwijderen
    user_logs = [t for t in user_logs if now - t <= RATE_LIMIT_WINDOW]
    user_logs.append(now)
    rate_data[ip] = user_logs
    save_rate_limiter(rate_data)

    if request.path.startswith('/url_api'):
        if len(user_logs) > 3:
            if ip not in blocked_ips:
                blocked_ips.append(ip)
                save_blocked_ips(blocked_ips)
            return "Access denied: too many API requests (IP blocked).", 429

    elif len(user_logs) > RATE_LIMIT_MAX:
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            save_blocked_ips(blocked_ips)
        return "Access denied: too many requests (IP blocked).", 429

    if ip in blocked_ips and request.endpoint not in allowed_endpoints:
        return "Access denied: your IP is blocked.", 403

    if shutdown and request.endpoint not in allowed_endpoints:
        return "System is in shutdown mode. Please try again later.", 503

# ----------- Routes -----------

@app.route('/')
def index():
    return redirect(url_for('inbox')) if logged_in() else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if logged_in():
        return redirect(url_for('inbox'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash("Please fill in username and password", "error")
            return redirect(url_for('register'))

        users = load_json(USERS_FILE)
        if username in users:
            flash("Username is already taken", "error")
            return redirect(url_for('register'))

        hashed = simple_hash_password(password)
        users[username] = hashed
        save_json(USERS_FILE, users)
        create_user_folders(username)
        flash("Registration successful, please login!", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if logged_in():
        return redirect(url_for('inbox'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        users = load_json(USERS_FILE)
        if username not in users or not simple_check_password(users[username], password):
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))
        session['username'] = username
        flash("Logged in successfully!", "success")
        return redirect(url_for('inbox'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for('login'))

@app.route('/inbox')
def inbox():
    if not logged_in():
        return redirect(url_for('login'))
    username = session['username']
    mails = load_all_mails(username, 'inbox')
    return render_template('inbox.html', mails=mails, username=username)

@app.route('/mail/<folder>/<mail_id>')
def view_mail(folder, mail_id):
    if not logged_in():
        return redirect(url_for('login'))
    username = session['username']
    mail = load_single_mail(username, folder, mail_id)
    if not mail:
        flash("Mail not found", "error")
        return redirect(url_for('inbox'))

    verified_users = load_verified_users()
    mail['verified'] = mail.get('from') in verified_users

    return render_template('view_mail.html', mail=mail, folder=folder, mail_id=mail_id)
    
@app.route('/delete/<folder>/<mail_id>', methods=['POST'])
def delete_mail_route(folder, mail_id):
    if not logged_in():
        return redirect(url_for('login'))
    delete_mail(session['username'], folder, mail_id)
    flash("Mail deleted", "success")
    return redirect(url_for('inbox'))

@app.route('/send', methods=['GET', 'POST'])
def send_mail():
    if not logged_in():
        return redirect(url_for('login'))
    if request.method == 'POST':
        recipient = request.form['recipient'].strip()
        message = request.form['message'].strip()
        sender = session['username']
        users = load_json(USERS_FILE)
        if recipient not in users:
            flash("Recipient does not exist", "error")
            return redirect(url_for('send_mail'))

        attachments = []
        files = request.files.getlist('attachments')
        for file in files:
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                user_attach_dir = os.path.join(app.config['UPLOAD_FOLDER'], sender, 'attachments')
                os.makedirs(user_attach_dir, exist_ok=True)
                filepath = os.path.join(user_attach_dir, filename)
                file.save(filepath)
                attachments.append(filename)

        mail_obj = {
            'from': sender,
            'to': recipient,
            'message': message,
            'attachments': attachments,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M')
        }

        save_mail(sender, 'sent', mail_obj)
        save_mail(recipient, 'inbox', mail_obj)
        flash("Mail sent!", "success")
        return redirect(url_for('inbox'))
    return render_template('send_mail.html')

@app.route('/attachment/<username>/<filename>')
def get_attachment(username, filename):
    if not logged_in() or session['username'] != username:
        return "Not authorized", 403
    path = os.path.join(app.config['UPLOAD_FOLDER'], username, 'attachments')
    return send_from_directory(path, filename)

@app.route('/url_api/<username>/<password>/<mail_recipient>/<mail_message>')
def url_api_send_mail(username, password, mail_recipient, mail_message):
    users = load_json(USERS_FILE)
    if username not in users or not simple_check_password(users[username], password):
        return {"success": False, "error": "Invalid username or password"}, 403

    if mail_recipient not in users:
        return {"success": False, "error": "Recipient does not exist"}, 404

    mail_message = urllib.parse.unquote(mail_message)

    emoji = None
    emoji_param = request.args.get('emoji')
    if emoji_param:
        emoji_path = os.path.join(app.root_path, 'static', 'emojis', emoji_param)
        if os.path.exists(emoji_path):
            emoji = emoji_param
        else:
            return {"success": False, "error": "Emoji file does not exist"}, 400

    mail_obj = {
        'from': username,
        'to': mail_recipient,
        'message': mail_message,
        'attachments': [],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'emoji': emoji
    }

    save_mail(username, 'sent', mail_obj)
    save_mail(mail_recipient, 'inbox', mail_obj)

    return {"success": True, "message": "Mail sent via URL API", "emoji": emoji}

@app.route('/url_api/check_inbox/<username>/<password>')
def api_check_inbox(username, password):
    users = load_json(USERS_FILE)
    if username not in users or not simple_check_password(users[username], password):
        return {"success": False, "error": "Invalid username or password"}, 403

    inbox = load_all_mails(username, 'inbox')
    return {"success": True, "inbox": inbox}

# ----------- Admin functionaliteit -----------

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form['password']
        admin_data = load_json(ADMIN_FILE)
        # Check: admin wachtwoord is default 'admin' (in admin.json)
        if password == admin_data.get('password'):
            session['admin'] = True
            flash("Logged in as admin!", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid admin password", "error")
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    users = list(load_json(USERS_FILE).keys())
    blocked_ips = load_blocked_ips()
    verified_users = load_verified_users()  # Voeg dit toe
    return render_template('admin.html', users=users, blocked_ips=blocked_ips, verified_users=verified_users)  # Geef het mee
    
@app.route('/admin/delete_all/<username>/<folder>', methods=['POST'])
def admin_delete_all_mails(username, folder):
    if not session.get('admin'):
        return "Forbidden", 403
    folder_path = get_mail_folder(username, folder)
    if os.path.exists(folder_path):
        for filename in os.listdir(folder_path):
            if filename.endswith('.json'):
                os.remove(os.path.join(folder_path, filename))
    flash(f"All mails in {folder} of {username} deleted.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/block_ip', methods=['POST'])
def block_ip():
    if not session.get('admin'):
        return "Forbidden", 403
    ip = request.form['ip'].strip()
    blocked = load_blocked_ips()
    if ip not in blocked:
        blocked.append(ip)
        save_blocked_ips(blocked)
        flash(f"IP {ip} blocked", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/unblock_ip', methods=['POST'])
def unblock_ip():
    if not session.get('admin'):
        return "Forbidden", 403
    ip = request.form['ip'].strip()
    blocked = load_blocked_ips()
    if ip in blocked:
        blocked.remove(ip)
        save_blocked_ips(blocked)
        flash(f"IP {ip} unblocked", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/verify_user/<username>', methods=['POST'])
def verify_user(username):
    verified_users = load_verified_users()  # functie die verified_users.json inleest
    if username not in verified_users:
        verified_users.append(username)
        save_verified_users(verified_users)  # functie die verified_users.json opslaat
        flash(f'User {username} is now verified.', 'success')
    else:
        flash(f'User {username} is already verified.', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/admin/unverify_user/<username>', methods=['POST'])
def unverify_user(username):
    verified_users = load_verified_users()
    if username in verified_users:
        verified_users.remove(username)
        save_verified_users(verified_users)
        flash(f'User {username} is now unverified.', 'success')
    else:
        flash(f'User {username} was not verified.', 'error')
    return redirect(url_for('admin_panel'))
    
@app.route('/admin/shutdown', methods=['POST'])
def admin_shutdown():
    if not session.get('admin'):
        return "Forbidden", 403
    save_shutdown_status(True)
    flash("System is now in shutdown mode.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/start', methods=['POST'])
def admin_start():
    if not session.get('admin'):
        return "Forbidden", 403
    save_shutdown_status(False)
    flash("System is now started (running).", "success")
    return redirect(url_for('admin_panel'))

# ----------- Error handlers -----------

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('index'))

# ----------- Run app -----------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)