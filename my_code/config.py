# config.py

import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'fallback_secret_key_for_development')

    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///prompt_arena.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email Configuration (for OTP)
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # Your email
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # App-specific password
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@promptarena.com')

    # OTP Configuration
    OTP_EXPIRY_MINUTES = int(os.getenv('OTP_EXPIRY_MINUTES', 5))
    OTP_SECRET = os.getenv('OTP_SECRET', 'super_secret_otp_key')

    # Google OAuth2 Configuration
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"  # ✅ Fixed trailing spaces

    # OpenAI API Key (for prompt evaluation)
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

    # Upload folders or other paths
    UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
    UPLOAD_FOLDER.mkdir(exist_ok=True)

    # Session and Security Settings
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_HTTPONLY = True


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True  # Logs SQL queries


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True   # HTTPS only
    REMEMBER_COOKIE_SECURE = True  # HTTPS only


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # In-memory DB
    WTF_CSRF_ENABLED = False
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)


# Dictionary to easily select config
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# === WARNINGS ===
if not Config.OPENAI_API_KEY and os.getenv('FLASK_ENV') != 'testing':
    print("⚠️  OPENAI_API_KEY is not set. AI evaluation will fail.")

if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
    print("⚠️  Email credentials (MAIL_USERNAME/PASSWORD) not set. OTP emails will fail.")