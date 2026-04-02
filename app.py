from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from config import Config
from functools import wraps
import sqlite3, os, secrets, string, re, random, hashlib
import requests, json, datetime, io

app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

# ── Encryption ────────────────────────────────────────────────────────────────
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

cipher = Fernet(load_or_create_key())

def encrypt_data(plain): return cipher.encrypt(plain.encode()).decode()
def decrypt_data(token):
    try: return cipher.decrypt(token.encode()).decode()
    except: return "❌ Decryption Error"

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("vaultx.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS otp_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            category TEXT DEFAULT 'General',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS vault_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        db.commit()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        # Auto logout after 5 min inactivity
        last = session.get("last_activity")
        if last:
            elapsed = (datetime.datetime.now() - datetime.datetime.fromisoformat(last)).seconds
            if elapsed > 300:
                session.clear()
                flash("Session expired. Please login again.", "warning")
                return redirect(url_for("login"))
        session["last_activity"] = datetime.datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated

def log_action(user_id, action, detail=""):
    with get_db() as db:
        db.execute("INSERT INTO audit_logs (user_id, action, detail) VALUES (?,?,?)",
                   (user_id, action, detail))
        db.commit()

def send_otp_email(email, otp, purpose="login"):
    subject = "VaultX — Your OTP Code"
    body = f"""
Hello from VaultX 🔐

Your OTP for {purpose} is:

  ➤  {otp}

This OTP is valid for 10 minutes. Do not share it with anyone.

— VaultX Security Team
Developed by Aryan Sharma
"""
    try:
        msg = Message(subject, recipients=[email], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Mail error: {e}")
        return False

def generate_otp(user_id, purpose):
    otp = str(random.randint(100000, 999999))
    expires = (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()
    with get_db() as db:
        db.execute("DELETE FROM otp_tokens WHERE user_id=? AND purpose=?", (user_id, purpose))
        db.execute("INSERT INTO otp_tokens (user_id, otp_code, purpose, expires_at) VALUES (?,?,?,?)",
                   (user_id, otp, purpose, expires))
        db.commit()
    return otp

def verify_otp(user_id, otp, purpose):
    db = get_db()
    row = db.execute("SELECT * FROM otp_tokens WHERE user_id=? AND purpose=? AND otp_code=?",
                     (user_id, purpose, otp)).fetchone()
    if not row: return False
    if datetime.datetime.now() > datetime.datetime.fromisoformat(row["expires_at"]):
        return False
    with get_db() as d:
        d.execute("DELETE FROM otp_tokens WHERE id=?", (row["id"],))
        d.commit()
    return True

def check_password_strength(password):
    score, feedback = 0, []
    if len(password) >= 8: score += 1
    else: feedback.append("At least 8 characters")
    if len(password) >= 12: score += 1
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Add uppercase letters")
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Add lowercase letters")
    if re.search(r"\d", password): score += 1
    else: feedback.append("Add numbers")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
    else: feedback.append("Add special characters")
    levels = {0:"Weak",1:"Weak",2:"Weak",3:"Moderate",4:"Moderate",5:"Strong",6:"Very Strong"}
    return {"score": score, "level": levels[score], "feedback": feedback}

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            flash("Email already registered.", "danger")
            return render_template("register.html")
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already taken.", "danger")
            return render_template("register.html")
        with get_db() as d:
            d.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                      (username, email, hash_password(password)))
            d.commit()
        user = get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        otp = generate_otp(user["id"], "verify")
        send_otp_email(email, otp, "email verification")
        session["pending_user_id"] = user["id"]
        session["pending_email"]   = email
        flash("OTP sent to your email. Please verify!", "info")
        return redirect(url_for("verify_email"))
    return render_template("register.html")

@app.route("/verify-email", methods=["GET","POST"])
def verify_email():
    if request.method == "POST":
        otp     = request.form["otp"].strip()
        user_id = session.get("pending_user_id")
        if not user_id:
            return redirect(url_for("register"))
        if verify_otp(user_id, otp, "verify"):
            with get_db() as db:
                db.execute("UPDATE users SET is_verified=1 WHERE id=?", (user_id,))
                db.commit()
            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            flash("Email verified! Please login.", "success")
            return redirect(url_for("login"))
        flash("Invalid or expired OTP.", "danger")
    email = session.get("pending_email","your email")
    return render_template("verify_otp.html", email=email, purpose="verify")

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    if request.method == "POST":
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=? AND password=?",
                          (email, hash_password(password))).fetchone()
        if not user:
            flash("Invalid email or password.", "danger")
            return render_template("login.html")
        if not user["is_verified"]:
            flash("Please verify your email first.", "warning")
            return render_template("login.html")
        otp = generate_otp(user["id"], "login")
        send_otp_email(email, otp, "login")
        session["pending_user_id"] = user["id"]
        session["pending_email"]   = email
        return redirect(url_for("verify_login_otp"))
    return render_template("login.html")

@app.route("/verify-login", methods=["GET","POST"])
def verify_login_otp():
    if request.method == "POST":
        otp     = request.form["otp"].strip()
        user_id = session.get("pending_user_id")
        if not user_id: return redirect(url_for("login"))
        if verify_otp(user_id, otp, "login"):
            user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            session["user_id"]       = user["id"]
            session["username"]      = user["username"]
            session["last_activity"] = datetime.datetime.now().isoformat()
            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            log_action(user["id"], "LOGIN", f"User {user['username']} logged in")
            flash(f"Welcome back, {user['username']}! 🔐", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid or expired OTP.", "danger")
    email = session.get("pending_email", "your email")
    return render_template("verify_otp.html", email=email, purpose="login")

@app.route("/logout")
def logout():
    if session.get("user_id"):
        log_action(session["user_id"], "LOGOUT", "User logged out")
    session.clear()
    return redirect(url_for("login"))

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    db    = get_db()
    query = request.args.get("q","").strip()
    cat   = request.args.get("cat","").strip()
    uid   = session["user_id"]
    sql   = "SELECT * FROM credentials WHERE user_id=?"
    params= [uid]
    if query:
        sql += " AND website LIKE ?"; params.append(f"%{query}%")
    if cat:
        sql += " AND category=?"; params.append(cat)
    sql += " ORDER BY website"
    rows = db.execute(sql, params).fetchall()
    creds = []
    for r in rows:
        creds.append({"id":r["id"],"website":r["website"],"username":r["username"],
                      "password":decrypt_data(r["password"]),"category":r["category"],
                      "notes":r["notes"],"created_at":r["created_at"]})
    categories = ["General","Social","Banking","Work","Shopping","Entertainment","Other"]
    return render_template("dashboard.html", credentials=creds, query=query,
                           categories=categories, selected_cat=cat)

# ── Credentials CRUD ──────────────────────────────────────────────────────────
@app.route("/add", methods=["GET","POST"])
@login_required
def add_password():
    categories = ["General","Social","Banking","Work","Shopping","Entertainment","Other"]
    if request.method == "POST":
        website  = request.form["website"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        category = request.form.get("category","General")
        notes    = request.form.get("notes","").strip()
        if website and username and password:
            with get_db() as db:
                db.execute("INSERT INTO credentials (user_id,website,username,password,category,notes) VALUES (?,?,?,?,?,?)",
                           (session["user_id"],website,username,encrypt_data(password),category,notes))
                db.commit()
            log_action(session["user_id"], "ADD_CREDENTIAL", f"Added: {website}")
            # Send email notification
            user = get_db().execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
            try:
                msg = Message("VaultX — New Password Saved",
                    recipients=[user["email"]],
                    body=f"Hey {session['username']}!\n\nA new credential was saved in your VaultX vault:\n\n🌐 Website: {website}\n👤 Username: {username}\n📁 Category: {category}\n\nIf this wasn't you, please login and check.\n\n— VaultX Security\nDeveloped by Aryan Sharma")
                mail.send(msg)
            except: pass
            flash("Credential saved successfully! 🔐", "success")
            return redirect(url_for("dashboard"))
        flash("All fields required.", "danger")
    return render_template("add_password.html", categories=categories)

@app.route("/delete/<int:cid>", methods=["POST"])
@login_required
def delete_credential(cid):
    db = get_db()
    row = db.execute("SELECT website FROM credentials WHERE id=? AND user_id=?",
                     (cid, session["user_id"])).fetchone()
    if row:
        with get_db() as d:
            d.execute("DELETE FROM credentials WHERE id=?", (cid,))
            d.commit()
        log_action(session["user_id"], "DELETE_CREDENTIAL", f"Deleted: {row['website']}")
        flash("Credential deleted.", "info")
    return redirect(url_for("dashboard"))

# ── Analytics ─────────────────────────────────────────────────────────────────
@app.route("/analytics")
@login_required
def analytics():
    db  = get_db()
    uid = session["user_id"]
    rows = db.execute("SELECT password, category FROM credentials WHERE user_id=?", (uid,)).fetchall()
    strength_counts = {"Weak":0,"Moderate":0,"Strong":0,"Very Strong":0}
    cat_counts = {}
    for r in rows:
        pw = decrypt_data(r["password"])
        lvl = check_password_strength(pw)["level"]
        strength_counts[lvl] = strength_counts.get(lvl,0) + 1
        cat_counts[r["category"]] = cat_counts.get(r["category"],0) + 1
    total = len(rows)
    return render_template("analytics.html", strength=strength_counts,
                           categories=cat_counts, total=total)

# ── Export CSV ────────────────────────────────────────────────────────────────
@app.route("/export")
@login_required
def export_csv():
    db   = get_db()
    rows = db.execute("SELECT * FROM credentials WHERE user_id=?", (session["user_id"],)).fetchall()
    lines = ["Website,Username,Password,Category,Notes"]
    for r in rows:
        pw = decrypt_data(r["password"])
        lines.append(f'{r["website"]},{r["username"]},{pw},{r["category"]},{r["notes"]}')
    csv_data = "\n".join(lines)
    log_action(session["user_id"], "EXPORT", "Exported credentials to CSV")
    return send_file(io.BytesIO(csv_data.encode()), mimetype="text/csv",
                     as_attachment=True, download_name="vaultx_export.csv")

# ── Breach Check ──────────────────────────────────────────────────────────────
@app.route("/api/breach-check", methods=["POST"])
@login_required
def breach_check():
    password = request.get_json().get("password","")
    sha1     = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return jsonify({"breached": True, "count": int(count)})
        return jsonify({"breached": False})
    except:
        return jsonify({"breached": None, "error": "Could not check"})

# ── File Vault ────────────────────────────────────────────────────────────────
@app.route("/vault")
@login_required
def file_vault():
    db   = get_db()
    files = db.execute("SELECT * FROM vault_files WHERE user_id=? ORDER BY uploaded_at DESC",
                       (session["user_id"],)).fetchall()
    return render_template("file_vault.html", files=files)

@app.route("/vault/upload", methods=["POST"])
@login_required
def upload_file():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("file_vault"))
    original_name = f.filename
    file_type     = f.content_type
    raw_data      = f.read()
    encrypted     = cipher.encrypt(raw_data)
    stored_name   = secrets.token_hex(16) + ".enc"
    user_folder   = os.path.join(app.config["UPLOAD_FOLDER"], str(session["user_id"]))
    os.makedirs(user_folder, exist_ok=True)
    with open(os.path.join(user_folder, stored_name), "wb") as out:
        out.write(encrypted)
    with get_db() as db:
        db.execute("INSERT INTO vault_files (user_id,original_name,stored_name,file_type) VALUES (?,?,?,?)",
                   (session["user_id"], original_name, stored_name, file_type))
        db.commit()
    log_action(session["user_id"], "UPLOAD_FILE", f"Uploaded: {original_name}")
    flash("File uploaded securely! 🔒", "success")
    return redirect(url_for("file_vault"))

@app.route("/vault/view/<int:fid>")
@login_required
def view_file(fid):
    db  = get_db()
    row = db.execute("SELECT * FROM vault_files WHERE id=? AND user_id=?",
                     (fid, session["user_id"])).fetchone()
    if not row: flash("File not found.", "danger"); return redirect(url_for("file_vault"))
    path = os.path.join(app.config["UPLOAD_FOLDER"], str(session["user_id"]), row["stored_name"])
    with open(path, "rb") as f:
        decrypted = cipher.decrypt(f.read())
    return send_file(io.BytesIO(decrypted), mimetype=row["file_type"],
                     download_name=row["original_name"])

@app.route("/vault/delete/<int:fid>", methods=["POST"])
@login_required
def delete_file(fid):
    db  = get_db()
    row = db.execute("SELECT * FROM vault_files WHERE id=? AND user_id=?",
                     (fid, session["user_id"])).fetchone()
    if row:
        path = os.path.join(app.config["UPLOAD_FOLDER"], str(session["user_id"]), row["stored_name"])
        if os.path.exists(path): os.remove(path)
        with get_db() as d:
            d.execute("DELETE FROM vault_files WHERE id=?", (fid,))
            d.commit()
        log_action(session["user_id"], "DELETE_FILE", f"Deleted: {row['original_name']}")
        flash("File deleted.", "info")
    return redirect(url_for("file_vault"))

# ── Audit Log ─────────────────────────────────────────────────────────────────
@app.route("/audit")
@login_required
def audit_log():
    db   = get_db()
    logs = db.execute("SELECT * FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50",
                      (session["user_id"],)).fetchall()
    return render_template("audit_log.html", logs=logs)

# ── AJAX Helpers ──────────────────────────────────────────────────────────────
@app.route("/api/check-strength", methods=["POST"])
@login_required
def api_check_strength():
    return jsonify(check_password_strength(request.get_json().get("password","")))

@app.route("/api/generate-password")
@login_required
def api_generate_password():
    length = int(request.args.get("length", 16))
    chars  = string.ascii_letters + string.digits + "!@#$%^&*()"
    pw     = "".join(secrets.choice(chars) for _ in range(length))
    return jsonify({"password": pw, "strength": check_password_strength(pw)})

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
