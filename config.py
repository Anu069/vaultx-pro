import os

class Config:
    SECRET_KEY = os.urandom(24)

    # ── Email Config (FILL THESE IN) ─────────────────────────────
    MAIL_SERVER         = 'smtp.gmail.com'
    MAIL_PORT           = 587
    MAIL_USE_TLS        = True
    MAIL_USERNAME       = 'YOUR_GMAIL_HERE'        # ←  gmail@gmail.com 
    MAIL_PASSWORD       = 'YOUR_APP_PASSWORD_HERE' # ← 16 digit App Password 
    MAIL_DEFAULT_SENDER = 'YOUR_GMAIL_HERE'        # ← same gmail 

    # ── Upload Config ─────────────────────────────────────────────
    UPLOAD_FOLDER   = os.path.join('static', 'vault_uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max file size
