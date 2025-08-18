# routes.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User
from config import Config
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pyotp import TOTP
import requests
from urllib.parse import urlencode

# Create a Blueprint
main = Blueprint('main', __name__)

# Helper: Send OTP via Gmail SMTP
def send_otp_email(email, otp):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your OTP for PromptArena"
    msg["From"] = Config.MAIL_DEFAULT_SENDER
    msg["To"] = email

    text = f"Your OTP is: {otp}"
    html = f"""
    <html>
      <body>
        <h3>Welcome to <strong>PromptArena</strong>!</h3>
        <p>Your one-time password (OTP) is: <strong>{otp}</strong></p>
        <p>This code expires in 10 minutes.</p>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(msg["From"], msg["To"], msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# Route: Home → Redirect to Login
@main.route('/')
def home():
    return redirect(url_for('main.login'))


# Route: Login Page
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        first_name = request.form.get('first_name').strip()
        last_name = request.form.get('last_name').strip()
        mobile_number = request.form.get('mobile_number', '').strip()

        # Validate required fields
        if not first_name or not last_name or not email:
            flash("All fields marked with * are required.", "error")
            return render_template('login.html')

        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if not user:
            # Create new user
            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                mobile_number=mobile_number
            )
            db.session.add(user)
            db.session.commit()

        # Generate OTP
        totp = TOTP(Config.OTP_SECRET)
        otp = totp.now()
        user.otp = otp
        db.session.commit()

        # Send OTP
        if send_otp_email(user.email, otp):
            flash("OTP has been sent to your email.", "info")
            return redirect(url_for('main.verify_otp', email=user.email))
        else:
            flash("Failed to send OTP. Please try again.", "error")

    return render_template('login.html')


# Route: Verify OTP
@main.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user or not user.otp:
        flash("Invalid or expired session.", "error")
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        totp = TOTP(Config.OTP_SECRET)

        if totp.verify(entered_otp):  # Validates within 30s window
            user.otp = None  # Clear OTP after use
            db.session.commit()
            login_user(user)
            return redirect(url_for('main.welcome'))
        else:
            flash("Invalid OTP. Please try again.", "error")

    return render_template('verify_otp.html', email=email)


# Route: Gmail Login - Initiate OAuth
@main.route('/login/gmail')
def gmail_login():
    google_discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
    config = requests.get(google_discovery_url).json()

    auth_params = {
        'client_id': Config.GOOGLE_CLIENT_ID,
        'redirect_uri': url_for('main.gmail_callback', _external=True),
        'response_type': 'code',
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }

    auth_url = f"{config['authorization_endpoint']}?{urlencode(auth_params)}"
    return redirect(auth_url)


# Route: Gmail Callback
@main.route('/login/gmail/callback')
def gmail_callback():
    code = request.args.get('code')

    # Exchange code for token
    google_discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
    config = requests.get(google_discovery_url).json()

    token_endpoint = config["token_endpoint"]
    data = {
        'client_id': Config.GOOGLE_CLIENT_ID,
        'client_secret': Config.GOOGLE_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('main.gmail_callback', _external=True)
    }

    token_response = requests.post(token_endpoint, data=data)
    if token_response.status_code != 200:
        flash("Authentication failed with Gmail.", "error")
        return redirect(url_for('main.login'))

    token_json = token_response.json()
    userinfo_url = config["userinfo_endpoint"]
    userinfo_response = requests.get(
        userinfo_url,
        headers={'Authorization': f"Bearer {token_json['access_token']}"}
    )

    if userinfo_response.status_code != 200:
        flash("Could not retrieve user info.", "error")
        return redirect(url_for('main.login'))

    userinfo = userinfo_response.json()

    email = userinfo['email']
    first_name = userinfo.get('given_name', 'User')
    last_name = userinfo.get('family_name', '')
    # Google doesn't provide mobile number via basic profile
    mobile_number = ''

    # Get or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            mobile_number=mobile_number
        )
        db.session.add(user)
        db.session.commit()
    else:
        # Update name if needed
        user.first_name = first_name
        user.last_name = last_name
        db.session.commit()

    login_user(user)
    return redirect(url_for('main.welcome'))


# Route: Welcome Page
@main.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', user=current_user)


# Route: Prompting Space (Basic, Intermediate, Pro)
@main.route('/prompting-space', methods=['GET'])
@login_required
def prompting_space():
    level = request.args.get('level', 'basic')  # default: basic
    return render_template('prompting_space.html', level=level)


# Route: Submit Prompt
@main.route('/submit-prompt', methods=['POST'])
@login_required
def submit_prompt():
    prompt_text = request.form.get('prompt')
    if not prompt_text:
        flash("Prompt cannot be empty.", "error")
        return redirect(url_for('main.prompting_space'))

    # Save prompt to database (add prompt model later)
    # For now, just simulate
    session['last_prompt'] = prompt_text

    # Redirect to evaluation (later: call OpenAI)
    return redirect(url_for('main.evaluate_prompt'))


# Route: Evaluate Prompt (Simulated or with OpenAI)
@main.route('/evaluate')
@login_required
def evaluate_prompt():
    prompt = session.get('last_prompt', 'No prompt submitted.')
    # TODO: Call OpenAI API here
    score = 85  # Mock score
    feedback = "Well-written, creative, and on-topic!"  # Mock feedback
    return render_template('evaluation.html', prompt=prompt, score=score, feedback=feedback)


# Route: Leaderboard
@main.route('/leaderboard')
@login_required
def leaderboard():
    # TODO: Query top 10 users from DB
    mock_leaderboard = [
        {"rank": 1, "name": "Alice", "score": 940},
        {"rank": 2, "name": "Bob", "score": 890},
        {"rank": 3, "name": "Charlie", "score": 870},
    ]
    return render_template('leaderboard.html', leaderboard=mock_leaderboard)


# Route: Payment (Static Page)
@main.route('/payment')
@login_required
def payment():
    return render_template('payment.html')


# Route: Logout
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))