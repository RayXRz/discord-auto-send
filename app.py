# app.py (versi dengan sistem key)
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import threading
import time
from datetime import datetime
import os
import sqlite3
import generate_keys
import check_key

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "09062008DhafinARz!")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_this_secret_in_production'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:SrRRkhFqeTQxWfPNpoSpbUSNUjeZJvwv@postgres.railway.internal:5432/railway"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- Models (sesuaikan nama tabel yang sudah ada) ----------
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class RegisterKey(db.Model):
    __tablename__ = 'register_key'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)

class UserToken(db.Model):
    __tablename__ = 'user_token'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.Text, nullable=False)
    user = db.relationship(User, backref=db.backref('token', uselist=False))

class UserSetting(db.Model):
    __tablename__ = 'user_setting'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    delay = db.Column(db.Integer, nullable=False)
    is_running = db.Column(db.Integer, nullable=False, default=0)
    user = db.relationship(User, backref=db.backref('settings', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === generate key baru ===
def require_admin():
    auth = request.headers.get("x-admin-key") or request.args.get("admin_key")
    if not auth or auth != ADMIN_KEY:
        abort(401)

@app.route("/admin/list_keys", methods=["GET"])
def admin_list_keys():
    # proteksi endpoint
    require_admin()

    db_path = getattr(check_key, "DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS register_key (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, used INTEGER DEFAULT 0)")
    cur.execute("SELECT key, used FROM register_key ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    data = [{"key": r[0], "used": bool(r[1])} for r in rows]
    return jsonify({"count": len(data), "keys": data})

@app.route("/admin/generate_keys", methods=["GET"])
def admin_generate_keys():
    require_admin()
    n = int(request.args.get("n", 1))  # jumlah key yang mau dibuat
    new_keys = generate_keys.create_keys(n)
    return jsonify({"generated": new_keys})

# opsional: endpoint untuk download csv (terproteksi juga)
@app.route("/admin/download_keys.csv", methods=["GET"])
def admin_download_csv():
    require_admin()
    db_path = getattr(check_key, "DB_PATH", "app.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT key, used FROM register_key ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()

    lines = ["key,used"]
    for k, u in rows:
        lines.append(f"{k},{int(u)}")
    csv_body = "\n".join(lines)

    return (csv_body, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=keys.csv"
    })

@app.route("/admin/initdb", methods=["GET"])
def admin_initdb():
    require_admin()  # biar cuma admin yang bisa akses
    db.create_all()
    return "Database created successfully"




# ---------- In-memory runtime state ----------
# user_tasks: { user_id: { setting_id: {'thread': Thread, 'stop_event': Event, 'running': bool} } }
user_tasks = {}
user_tasks_lock = threading.Lock()

# user_logs: { user_id: [ "timestamp - message", ... ] }
user_logs = {}
user_logs_lock = threading.Lock()

# ---------- Utilities ----------
def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def add_log(user_id, text):
    with user_logs_lock:
        if user_id not in user_logs:
            user_logs[user_id] = []
        user_logs[user_id].append(f"{now_str()} - {text}")
        # cap log length
        if len(user_logs[user_id]) > 500:
            user_logs[user_id] = user_logs[user_id][-500:]

def is_setting_running(user_id, setting_id):
    with user_tasks_lock:
        return (user_id in user_tasks) and (setting_id in user_tasks[user_id]) and user_tasks[user_id][setting_id]['running']

# ---------- DB helper: ensure schema (add is_running if missing) ----------
def ensure_db_schema():
    # Use sqlite3 directly to check pragma
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA table_info(user_setting);")
        cols = [r[1] for r in cur.fetchall()]
        if 'is_running' not in cols:
            # Add column with default 0
            cur.execute("ALTER TABLE user_setting ADD COLUMN is_running INTEGER DEFAULT 0;")
            conn.commit()
            print("[db] Added 'is_running' column to user_setting")
    except Exception as e:
        print("[db] ensure schema error:", e)
    finally:
        conn.close()

# ---------- Background sender (per setting) ----------
def start_background_sender(user_id, token, setting_id):
    """
    Start background thread to send messages for a single setting.
    Returns True if started, False if already running.
    """
    setting = UserSetting.query.get(setting_id)
    if not setting:
        return False, "Setting not found"

    with user_tasks_lock:
        if user_id not in user_tasks:
            user_tasks[user_id] = {}
        if setting_id in user_tasks[user_id] and user_tasks[user_id][setting_id]['running']:
            return False, "Already running"

        stop_event = threading.Event()

        def worker():
            # 🔥 app context dibuka di DALAM thread
            with app.app_context():
                add_log(user_id, f"[Channel {setting.channel_id}] Background task started (delay={setting.delay}s).")
                headers = {"Authorization": token, "Content-Type": "application/json"}
                url = f"https://discord.com/api/v10/channels/{setting.channel_id}/messages"

                while not stop_event.is_set():
                    try:
                        s = UserSetting.query.get(setting_id)
                        if not s:
                            add_log(user_id, f"[Channel {setting.channel_id}] Setting removed, stopping task.")
                            break

                        payload = {"content": s.message}
                        r = requests.post(url, headers=headers, json=payload, timeout=15)
                        if r.status_code in (200, 201, 204):
                            add_log(user_id, f"[Channel {s.channel_id}] Sent message (len={len(s.message)}).")
                        else:
                            body = r.text or ''
                            snippet = (body[:200] + '...') if len(body) > 200 else body
                            add_log(user_id, f"[Channel {s.channel_id}] Send failed: {r.status_code} - {snippet}")
                    except Exception as e:
                        add_log(user_id, f"[Channel {setting.channel_id}] Exception while sending: {str(e)}")

                    sleep_total = 0.0
                    while sleep_total < s.delay and not stop_event.is_set():
                        time.sleep(0.5)
                        sleep_total += 0.5

                add_log(user_id, f"[Channel {setting.channel_id}] Background task stopped.")

        thread = threading.Thread(target=worker, daemon=True)
        user_tasks[user_id][setting_id] = {'thread': thread, 'stop_event': stop_event, 'running': True}
        thread.start()

        try:
            setting.is_running = 1
            db.session.commit()
        except Exception:
            db.session.rollback()

        return True, "Started"


def stop_background_sender(user_id, setting_id):
    with user_tasks_lock:
        if user_id not in user_tasks or setting_id not in user_tasks[user_id]:
            return False, "Not running"
        entry = user_tasks[user_id][setting_id]
        try:
            entry['stop_event'].set()
        except Exception:
            pass
        entry['running'] = False
        # remove entry from dict
        try:
            del user_tasks[user_id][setting_id]
            if not user_tasks[user_id]:
                del user_tasks[user_id]
        except KeyError:
            pass
    # update DB is_running flag
    try:
        s = UserSetting.query.get(setting_id)
        if s:
            s.is_running = 0
            db.session.commit()
    except Exception:
        db.session.rollback()
    add_log(user_id, f"[Setting {setting_id}] Stop requested.")
    return True, "Stopped"

# ---------- Startup: ensure schema and resume running tasks ----------
def resume_running_tasks_on_startup():
    # find settings where is_running == 1
    with app.app_context():
        try:
            running_settings = UserSetting.query.filter_by(is_running=1).all()
            for s in running_settings:
                token_obj = UserToken.query.filter_by(user_id=s.user_id).first()
                if token_obj and token_obj.token:
                    started, msg = start_background_sender(s.user_id, token_obj.token, s.id)
                    if started:
                        add_log(s.user_id, f"Resumed setting {s.id} on startup.")
                    else:
                        add_log(s.user_id, f"Failed resume {s.id}: {msg}")
                else:
                    add_log(s.user_id, f"Cannot resume {s.id}: token missing.")
        except Exception as e:
            print("[startup] resume tasks error:", e)

# ---------- Routes (UI) ----------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        register_key = request.form.get('register_key', '').strip()

        if not username or not password or not register_key:
            flash('Semua kolom harus diisi!')
            return render_template('register.html')
        
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            flash('Username sudah ada!')
            return render_template('register.html')

        valid_key = RegisterKey.query.filter_by(key=register_key, used=0).first()
        if not valid_key:
            flash('Key tidak valid atau sudah dipakai!')
            return render_template('register.html')

        valid_key.used = 1
        db.session.commit()

        hashed = generate_password_hash(password)
        u = User(username=username, password=hashed)
        db.session.add(u)
        db.session.commit()
        flash('Registrasi berhasil. Silakan login.')
        return redirect(url_for('login'))

    # kalau GET, render form kosong aja
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Username atau password salah!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # IMPORTANT: do NOT stop tasks on logout — tasks should keep running until user explicitly stops them
    logout_user()
    flash('Logout berhasil.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    token = current_user.token.token if hasattr(current_user, 'token') and current_user.token else ''
    settings_list = list(current_user.settings) if hasattr(current_user, 'settings') else []
    return render_template('settings.html', token=token, settings=settings_list)

@app.route('/monitor')
@login_required
def monitor():
    token = current_user.token.token if hasattr(current_user, 'token') and current_user.token else None
    settings_list = list(current_user.settings) if hasattr(current_user, 'settings') else []
    # annotate running status for template
    for s in settings_list:
        s.is_running = is_setting_running(s.user_id, s.id)
    logs = user_logs.get(current_user.id, [])
    return render_template('monitor.html', token=token, settings=settings_list, logs=logs)

# ---------- API endpoints ----------
@app.route('/api/save_token', methods=['POST'])
@login_required
def api_save_token():
    try:
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        existing = UserToken.query.filter_by(user_id=current_user.id).first()
        if existing:
            existing.token = token
        else:
            if token:
                ut = UserToken(user_id=current_user.id, token=token)
                db.session.add(ut)
        db.session.commit()
        add_log(current_user.id, "Token disimpan.")
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/save_setting', methods=['POST'])
@login_required
def api_save_setting():
    try:
        data = request.get_json() or {}
        setting_id = data.get('id')
        channel_id = (data.get('channel_id') or '').strip()
        message = (data.get('message') or '').strip()
        delay = int(data.get('delay') or 0)
        if not channel_id or not message or delay <= 0:
            return jsonify({'status': 'error', 'message': 'Channel, message, delay harus valid.'}), 400

        if setting_id:
            s = UserSetting.query.get(setting_id)
            if not s or s.user_id != current_user.id:
                return jsonify({'status': 'error', 'message': 'Setting tidak ditemukan.'}), 404
            # if currently running, stop it first (we stop but do not remove DB flag until user restarts)
            if is_setting_running(current_user.id, s.id):
                stop_background_sender(current_user.id, s.id)
            s.channel_id = channel_id
            s.message = message
            s.delay = delay
            # on edit we keep is_running as 0 (stopped) — user can start again
            s.is_running = 0
            saved_id = s.id
        else:
            new_s = UserSetting(user_id=current_user.id, channel_id=channel_id, message=message, delay=delay, is_running=0)
            db.session.add(new_s)
            db.session.flush()
            saved_id = new_s.id
        db.session.commit()
        add_log(current_user.id, f"Setting disimpan (id={saved_id}).")
        return jsonify({'status': 'success', 'id': saved_id})
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Delay harus angka.'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/delete_setting', methods=['POST'])
@login_required
def api_delete_setting():
    try:
        data = request.get_json() or {}
        setting_id = data.get('id')
        if not setting_id:
            return jsonify({'status': 'error', 'message': 'ID setting diperlukan.'}), 400
        s = UserSetting.query.get(setting_id)
        if not s or s.user_id != current_user.id:
            return jsonify({'status': 'error', 'message': 'Setting tidak ditemukan.'}), 404
        # stop if running
        if is_setting_running(current_user.id, s.id):
            stop_background_sender(current_user.id, s.id)
        db.session.delete(s)
        db.session.commit()
        add_log(current_user.id, f"Setting dihapus (id={setting_id}).")
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/start_channel/<int:setting_id>', methods=['POST'])
@login_required
def api_start_channel(setting_id):
    s = UserSetting.query.get(setting_id)
    if not s or s.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Setting tidak ditemukan.'}), 404
    token_obj = UserToken.query.filter_by(user_id=current_user.id).first()
    if not token_obj or not token_obj.token:
        return jsonify({'status': 'error', 'message': 'Token belum diset di Settings.'}), 400
    token = token_obj.token.strip()
    # start task
    started, msg = start_background_sender(current_user.id, token, setting_id)
    if not started:
        return jsonify({'status': 'error', 'message': msg}), 400
    add_log(current_user.id, f"Start channel requested: setting_id={setting_id}")
    return jsonify({'status': 'success'})

@app.route('/api/stop_channel/<int:setting_id>', methods=['POST'])
@login_required
def api_stop_channel(setting_id):
    s = UserSetting.query.get(setting_id)
    if not s or s.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Setting tidak ditemukan.'}), 404
    stopped, msg = stop_background_sender(current_user.id, setting_id)
    if not stopped:
        return jsonify({'status': 'error', 'message': msg}), 400
    add_log(current_user.id, f"Stop channel requested: setting_id={setting_id}")
    return jsonify({'status': 'success'})

@app.route('/api/get_logs', methods=['GET'])
@login_required
def api_get_logs():
    logs = user_logs.get(current_user.id, [])
    return jsonify({'logs': logs[-200:]})

# ---------- Run ----------
if __name__ == '__main__':
    # Ensure DB file exists and schema column present
    if not os.path.exists(DB_PATH):
        # create empty DB
        open(DB_PATH, 'a').close()
    ensure_db_schema()
    with app.app_context():
        db.create_all()
        # Resume ongoing tasks (settings with is_running == 1)
        try:
            resume_running_tasks_on_startup()
        except Exception as e:
            print("[startup] resume error:", e)
        print("App ready. DB:", DB_PATH)
    app.run(debug=True)
