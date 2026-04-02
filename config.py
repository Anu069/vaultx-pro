import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24))

    # ── Email Config ─────────────────────────────
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")   
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")        
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_USERNAME")  
    # ── Upload Config ─────────────────────────────
    UPLOAD_FOLDER = os.path.join("static", "vault_uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
