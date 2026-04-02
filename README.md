# 🔐 VaultX Pro — Advanced Password Manager

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/Encryption-AES--128-gold?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/2FA-OTP%20Email-green?style=for-the-badge"/>
</p>

<p align="center">
  A full-featured, secure Password Manager & File Vault web application built with Python Flask. Supports multiple users, email OTP authentication, encrypted file storage, breach detection, and analytics.
</p>

---

## ✨ Features

### 👤 User System
- ✅ Multiple user accounts — each with their own private vault
- ✅ Email OTP verification on registration
- ✅ 2FA Login — OTP sent to email on every login
- ✅ Auto logout after 5 minutes of inactivity

### 🔑 Password Manager
- ✅ Add, View, Delete credentials
- ✅ Password Categories — Social, Banking, Work, Shopping, Entertainment
- ✅ Password Strength Checker (Real-time)
- ✅ Password Generator with adjustable length
- ✅ Show/Hide password toggle
- ✅ Copy to clipboard
- ✅ Search & filter by website/category
- ✅ Export all passwords to CSV
- ✅ Breach Check — checks if password is in known data breaches (HaveIBeenPwned API)

### 📸 Secure File Vault
- ✅ Upload photos, videos, documents
- ✅ All files encrypted with AES-128 before saving
- ✅ Each user's files stored separately
- ✅ View, Download & Delete files

### 📊 Analytics Dashboard
- ✅ Password strength breakdown (Weak/Moderate/Strong/Very Strong)
- ✅ Category-wise distribution
- ✅ Total credential count

### 📝 Audit Log
- ✅ Every action tracked — login, add, delete, upload, export
- ✅ Timestamp for each activity

### 📧 Email Notifications
- ✅ OTP email on registration and login
- ✅ Notification email when new credential is saved

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| Encryption | Cryptography (Fernet / AES-128) |
| Email | Flask-Mail + Gmail SMTP |
| Breach Check | HaveIBeenPwned API |
| Frontend | HTML, CSS, Bootstrap 5 |
| Fonts | Bebas Neue, DM Sans, JetBrains Mono |

---

## 📁 Project Structure

```
VaultX-Pro/
├── app.py                    # Main Flask application
├── config.py                 # Email & app configuration
├── requirements.txt          # Dependencies
├── render.yaml               # Render deployment config
├── .gitignore
│
├── templates/
│   ├── base.html             # Layout, navbar, footer
│   ├── register.html         # User registration
│   ├── login.html            # Login page
│   ├── verify_otp.html       # OTP verification
│   ├── dashboard.html        # Main vault dashboard
│   ├── add_password.html     # Add credentials
│   ├── file_vault.html       # Secure file vault
│   ├── analytics.html        # Security analytics
│   └── audit_log.html        # Activity log
│
└── static/
    ├── css/style.css         # Premium dark gold theme
    └── vault_uploads/        # Encrypted files (auto-created)
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Gmail account with App Password

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/Anu069/vaultx-password-manager.git
cd vaultx-password-manager

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure email in config.py
# Open config.py and fill in:
# MAIL_USERNAME = 'your_gmail@gmail.com'
# MAIL_PASSWORD = 'your_16_digit_app_password'

# 5. Run
python app.py
```

Open **http://127.0.0.1:5000** — Register, verify OTP, and start using! 🎉

---

## ⚙️ Email Setup (Required for OTP)

1. Go to **myaccount.google.com → Security → 2-Step Verification → App Passwords**
2. Create an app password for "VaultX"
3. Copy the 16-digit password into `config.py`

---

## 🔒 Security Notes

| File | Status |
|---|---|
| `secret.key` | Auto-generated — never push to GitHub |
| `vaultx.db` | Database — never push to GitHub |
| `vault_uploads/` | Encrypted files — never push to GitHub |

> ⚠️ All sensitive files are in `.gitignore` for safety.

---

## 👨‍💻 Developed By

**Aryan Sharma**  
Advanced Password Manager — College Project

---

## 📄 License

MIT License — Open Source
