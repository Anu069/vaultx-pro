import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24))

    # ── Email Config ─────────────────────────────
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")    #( you can your eamil here)
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")          # use 16 digit passowrd here
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_USERNAME")  #( you can your eamil here)

    # ── Upload Config ─────────────────────────────
    UPLOAD_FOLDER = os.path.join("static", "vault_uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
