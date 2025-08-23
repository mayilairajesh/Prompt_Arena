# ====================
# 1. IMPORTS
# ====================
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy  # Only import, not instantiate
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from dotenv import load_dotenv
from openai import OpenAI
from pyotp import TOTP
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime, timedelta
import json

load_dotenv()
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# ====================
# 2. CREATE FLASK APP
# ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'fallback-secret-key'

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

# ✅ Import db from models, then init_app
from models import db, User, PromptSubmission
db.init_app(app)  # Now correct!

migrate = Migrate(app, db)

# ====================
# 3. IMPORT MODELS (NOW db is initialized)
# ====================
from models import User, PromptSubmission  # Now safe to import

# ====================
# 4. LOGIN MANAGER
# ====================
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ====================
# 5. GOOGLE OAUTH BLUEPRINT
# ====================
if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    google_bp = make_google_blueprint(
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
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

# ====================
# 6. OTP EMAIL FUNCTION
# ====================
def send_otp_email(to_email, otp):
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")

    if not sender_email or not sender_password:
        print("❌ Mail credentials missing in environment.")
        return False

    msg = MIMEMultipart("alternative")
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "Your OTP for PromptArena"

    # Plain text fallback
    text_body = f"Your OTP is: {otp}. It expires in 5 minutes."

    # HTML body
    html_body = f"""
    <html>
      <body>
        <p>Hello,</p>
        <p>Your one-time password (OTP) is:</p>
        <h2>{otp}</h2>
        <p><strong>This code will expire in 5 minutes.</strong></p>
        <p>Welcome to PromptArena – Where Words Battle!</p>
      </body>
    </html>
    """

    part1 = MIMEText(text_body, 'plain')
    part2 = MIMEText(html_body, 'html')
    msg.attach(part1)
    msg.attach(part2)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        print(f"✅ OTP email sent to {to_email}")
        return True
    except Exception as e:
        print("❌ Failed to send email:", str(e))
        return False

# ====================
# 7. ROUTES
# ====================

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        mobile_number = request.form.get('mobile_number', '').strip()
        password = request.form['password']

        if not all([first_name, last_name, email, password]):
            flash('All fields are required.')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please log in.')
            return redirect(url_for('login'))

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            mobile_number=mobile_number,
            is_guest=False
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please log in.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        # If user doesn't exist, create a guest account
        if not user:
            user = User(
                first_name="Guest",
                last_name="User",
                email=email,
                mobile_number=None,
                is_guest=True,
                otp=None
            )
            user.set_password("temp")  # Required for password hash field
            db.session.add(user)
            db.session.commit()
            flash('Welcome! You’re logged in as a guest.')

        # Generate OTP
        totp = TOTP(os.getenv('OTP_SECRET', 'defaultsecret'))
        otp = totp.now()
        user.otp = otp
        user.otp_created_at = datetime.utcnow()  # Track OTP timestamp
        db.session.commit()

        success = send_otp_email(email, otp)
        if success:
            flash('OTP has been sent to your email.')
        else:
            flash('Failed to send OTP. Please try again.')
            return redirect(url_for('login'))

        return redirect(url_for('verify_otp', email=email))

    return render_template('login.html')

@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user or not user.otp:
        flash('Invalid session. Please try again.')
        return redirect(url_for('login'))

    # Check OTP expiration (5 minutes)
    if user.otp_created_at and datetime.utcnow() - user.otp_created_at > timedelta(minutes=5):
        flash('OTP has expired. Please request a new one.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp'].strip()
        if entered_otp == user.otp:
            # Clear OTP after successful login
            user.otp = None
            user.otp_created_at = None
            db.session.commit()

            login_user(user)
            flash('✅ Login successful!')
            return redirect(url_for('welcome'))
        else:
            flash('❌ Invalid OTP. Please try again.', 'error')

    return render_template('verify_otp.html', email=email)

@app.route('/resend-otp/<email>')
def resend_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    totp = TOTP(os.getenv('OTP_SECRET', 'defaultsecret'))
    otp = totp.now()
    user.otp = otp
    user.otp_created_at = datetime.utcnow()
    db.session.commit()

    success = send_otp_email(email, otp)
    if success:
        flash('✅ A new OTP has been sent to your email.')
    else:
        flash('❌ Failed to send OTP. Please try again.')

    return redirect(url_for('verify_otp', email=email))

@app.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch your Google profile.")
        return redirect(url_for("login"))

    user_data = resp.json()
    email = user_data["email"]
    first_name = user_data.get("given_name", "Unknown")
    last_name = user_data.get("family_name", "User")

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            mobile_number=None,
            is_guest=False,
            otp=None
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"🎉 Welcome, {first_name}! You're logged in with Gmail.")
    return redirect(url_for("welcome"))

@app.route('/login/password', methods=['GET', 'POST'])
def login_with_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('✅ Logged in successfully!')
            return redirect(url_for('welcome'))
        else:
            flash('❌ Invalid email or password.')
            return redirect(url_for('login_with_password'))

    return render_template('login.html')

@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', user=current_user)

@app.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    if current_user.is_authenticated and not current_user.is_guest:
        return redirect(url_for('welcome'))  # Already full user

    if request.method == 'POST':
        current_user.first_name = request.form['first_name'].strip()
        current_user.last_name = request.form['last_name'].strip()
        current_user.mobile_number = request.form.get('mobile_number', '').strip()

        password = request.form.get('password')
        if password:
            current_user.set_password(password)

        current_user.is_guest = False  # Upgrade to full user
        db.session.commit()
        flash('🎉 Profile updated! Welcome to PromptArena.')
        return redirect(url_for('welcome'))

    return render_template('complete_profile.html')

@app.route('/prompting_space', methods=['GET', 'POST'])
@login_required
def prompting_space():
    if request.method == 'POST':
        level = request.form['level']
        battle_type = request.form['battle_type']
        session['level'] = level
        session['battle_type'] = battle_type
        flash(f"Selected: {level} Level | {battle_type}")
        return redirect(url_for('battle_arena'))
    return render_template('prompting_space.html', user=current_user)

@app.route('/battle_arena', methods=['GET', 'POST'])
@login_required
def battle_arena():
    level = session.get('level', 'Basic')
    battle_type = session.get('battle_type', '1v1')

    topics = {
        'Basic': 'Write a short story prompt about a robot who discovers friendship.',
        'Intermediate': 'Create a prompt for a thriller where time loops every 24 hours.',
        'Pro': 'Design a meta-prompt that makes an AI question its own existence.'
    }
    topic = topics.get(level, 'Create a creative prompt.')

    if request.method == 'POST':
        user_prompt = request.form['user_prompt'].strip()
        if not user_prompt:
            flash("Prompt cannot be empty.")
            return redirect(url_for('battle_arena'))

        evaluation = evaluate_prompt_with_ai(user_prompt, level)

        submission = PromptSubmission(
            user_id=current_user.id,
            level=level,
            battle_type=battle_type,
            prompt_text=user_prompt,
            creativity_score=evaluation['creativity'],
            relevance_score=evaluation['relevance'],
            clarity_score=evaluation['clarity'],
            overall_score=evaluation['overall'],
            feedback=evaluation['feedback']
        )
        db.session.add(submission)
        db.session.commit()

        session['user_prompt'] = user_prompt
        session['evaluation'] = evaluation
        flash("Prompt submitted and evaluated!")
        return redirect(url_for('evaluation'))

    return render_template('battle_arena.html', 
                         level=level, 
                         battle_type=battle_type, 
                         topic=topic,
                         user=current_user)

@app.route('/evaluation')
@login_required
def evaluation():
    user_prompt = session.get('user_prompt', 'Your prompt was not captured.')
    evaluation = session.get('evaluation', {
        'creativity': 0,
        'relevance': 0,
        'clarity': 0,
        'overall': 0,
        'feedback': 'No evaluation available.'
    })
    return render_template('evaluation.html', 
                         user_prompt=user_prompt, 
                         evaluation=evaluation,
                         user=current_user)

@app.route('/leaderboard')
@login_required
def leaderboard():
    from sqlalchemy import func

    top_users = db.session.query(
        User.first_name,
        User.last_name,
        func.avg(PromptSubmission.overall_score).label('avg_score'),
        func.count(PromptSubmission.id).label('battle_count')
    ).join(PromptSubmission).group_by(User.id).order_by(func.avg(PromptSubmission.overall_score).desc()).limit(10).all()

    return render_template('leaderboard.html', top_users=top_users)

@app.route('/payment')
@login_required
def payment():
    return render_template('payment.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

# ====================
# 8. PROMPT EVALUATION (AI)
# ====================
def evaluate_prompt_with_ai(user_prompt, level="Basic"):
    try:
        prompt_instruction = f"""
        You are a fair and strict judge in a prompt battle arena.
        Evaluate the following user-generated prompt based on three criteria: Creativity, Relevance, and Clarity.
        The prompt was submitted for the '{level}' level.

        User Prompt: "{user_prompt}"

        Respond in **strict JSON format only**:
        {{
          "creativity": <score out of 10>,
          "relevance": <score out of 10>,
          "clarity": <score out of 10>,
          "overall": <average of the three>,
          "feedback": "<2-sentence constructive feedback>"
        }}

        Do not include any extra text before or after the JSON.
        """

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful AI judge for a prompt battle."},
                {"role": "user", "content": prompt_instruction}
            ],
            max_tokens=256,
            temperature=0.7
        )

        result = response.choices[0].message.content.strip()
        evaluation = json.loads(result)
        return evaluation

    except Exception as e:
        print("OpenAI API Error:", str(e))
        return {
            "creativity": 0,
            "relevance": 0,
            "clarity": 0,
            "overall": 0,
            "feedback": "Evaluation failed due to an error. Please try again."
        }

# ====================
# 9. RUN APP
# ====================
if __name__ == '__main__':
    with app.app_context():
        from flask_migrate import upgrade
        try:
            upgrade()  # Applies any pending migrations
            print("✅ Migrations applied or already up-to-date.")
        except Exception as e:
            print(f"❌ Migration failed: {e}")

    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)