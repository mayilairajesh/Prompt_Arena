# ====================
# app.py - PromptArena Backend
# ====================
# A Flask-based AI prompt battle platform with OTP login, Google OAuth,
# AI evaluation, and 1v1 async battles.

import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from dotenv import load_dotenv
from openai import OpenAI
from flask_dance.contrib.google import make_google_blueprint
import secrets
from datetime import datetime, timedelta
from config import config_by_name

# Load environment early
load_dotenv()

# ====================
# CREATE FLASK APP
# ====================
app = Flask(__name__)

# --- Load Configuration ---
config_name = os.getenv('FLASK_ENV', 'default')
app.config.from_object(config_by_name[config_name])

# --- Database URI ---
database_url = os.getenv("DATABASE_URL")
if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print("✅ Using PostgreSQL:", database_url)
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prompt_arena.db'
    print("✅ Using SQLite (local only)")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
from models import db
db.init_app(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'main.login'  # ← Note: 'main.login' because routes are in blueprint
login_manager.init_app(app)

mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Google OAuth ---
# --- Google OAuth ---
google_client_id = os.getenv("GOOGLE_CLIENT_ID")
google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

if google_client_id and google_client_secret:
    google_bp = make_google_blueprint(
        client_id=google_client_id,
        client_secret=google_client_secret,
        scope=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        redirect_url="/google-login"
    )
    app.register_blueprint(google_bp, url_prefix="/login")
    app.config['GOOGLE_LOGIN_ENABLED'] = True
else:
    print("⚠️ GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not found in .env")
    app.config['GOOGLE_LOGIN_ENABLED'] = False


# --- OpenAI Client ---
openai_api_key = os.getenv('OPENAI_API_KEY')
if not openai_api_key:
    raise RuntimeError("OPENAI_API_KEY is required in .env")
client = OpenAI(api_key=openai_api_key)

# --- Import Models ---
from models import User, PromptSubmission, Battle, BattleSubmission

# ====================
# REGISTER BLUEPRINTS
# ====================
from routes import main
app.register_blueprint(main)

# ====================
# 8. RUN APP
# ====================
if __name__ == '__main__':
    with app.app_context():
        try:
            from flask_migrate import upgrade
            upgrade()
            print("✅ Migrations applied or already up-to-date.")
        except Exception as e:
            print(f"❌ Migration failed: {e}")

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)
