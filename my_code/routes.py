# routes.py
from flask_dance.contrib.google import google
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, PromptSubmission, Battle, BattleSubmission
from config import Config
from datetime import datetime, timezone, timedelta
from pyotp import TOTP
import json
from utils import send_otp_email, evaluate_prompt_with_ai  # ← Import from utils.py

def make_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware, assuming UTC if naive."""
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
# Create Blueprint
main = Blueprint('main', __name__)

# ====================
# Routes
# ====================

@main.route('/')
def home():
    return redirect(url_for('main.login'))


@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash("Email is required.")
            return redirect(url_for('main.signup'))

        user = User.query.filter_by(email=email).first()
        if user and not user.is_guest:
            flash("Email already registered. Please log in.")
            return redirect(url_for('main.login'))

        if not user:
            user = User(email=email, first_name="Guest", last_name="User", is_guest=True)
            db.session.add(user)
            db.session.commit()

        # Generate OTP
        totp = TOTP(Config.OTP_SECRET)
        otp = totp.now()
        user.otp = otp
        user.otp_created_at = datetime.now(timezone.utc)
        db.session.commit()

        # Store in session
        session['signup_email'] = email
        session['auth_flow'] = 'signup'  # ← NEW: Track flow type

        if send_otp_email(email, otp):
            flash("OTP has been sent to your email.")
            return redirect(url_for('main.verify_otp', email=email))
        else:
            flash("Failed to send OTP. Please try again.")
            return redirect(url_for('main.signup'))

    return render_template('signup.html')


@main.route('/signup/verify-otp', methods=['GET', 'POST'])
def signup_verify_otp():
    email = request.args.get('email')
    if not email:
        flash("Invalid or expired session.")
        return redirect(url_for('main.signup'))

    stored_email = session.get('signup_email')
    if not stored_email or stored_email != email:
        flash("Session expired. Please start again.")
        return redirect(url_for('main.signup'))

    user = User.query.filter_by(email=stored_email).first()
    if not user or not user.otp:
        flash("Invalid or expired session.")
        return redirect(url_for('main.signup'))

    if user.otp_created_at:
        otp_created_at = make_aware(user.otp_created_at)
        if (datetime.now(timezone.utc) - otp_created_at).total_seconds() > Config.OTP_EXPIRY_MINUTES * 60:
            flash("OTP has expired. Please request a new one.")
            return redirect(url_for('main.signup'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        totp = TOTP(Config.OTP_SECRET)

        if totp.verify(entered_otp, valid_window=1):
            return redirect(url_for('main.signup_create_password'))
        else:
            flash("❌ Invalid OTP. Please try again.")

    return render_template('verify_otp.html', email=email, from_signup=True)


@main.route('/signup/create-password', methods=['GET', 'POST'])
def signup_create_password():
    # Get email from session
    email = session.get('signup_email')
    if not email:
        flash("Session expired. Please start again.")
        return redirect(url_for('main.signup'))

    user = User.query.filter_by(email=email).first()
    if not user or not user.otp:
        flash("Session expired. Please start again.")
        return redirect(url_for('main.signup'))

    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        mobile_number = request.form.get('mobile_number', '').strip() or None
        password = request.form.get('password', '')

        if not first_name or not last_name:
            flash("First and last name are required.")
            return redirect(url_for('main.signup_create_password'))
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for('main.signup_create_password'))

        user.first_name = first_name
        user.last_name = last_name
        user.mobile_number = mobile_number
        user.is_guest = False
        user.set_password(password)
        user.otp = None
        user.otp_created_at = None
        db.session.commit()

        # Clear session
        session.pop('signup_email', None)
        flash("✅ Account created! Please log in.")
        return redirect(url_for('main.login'))

    return render_template('signup_create_password.html', email=email)


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        mobile_number = request.form.get('mobile_number', '').strip()

        if not email:
            flash("Email is required.")
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        if user:
            if not user.is_guest:
                flash("Email already registered. Please log in with password or Google.")
                return redirect(url_for('main.login'))
        else:
            user = User(
                first_name="Guest",
                last_name="User",
                email=email,
                is_guest=True
            )
            user.set_password("temp")
            db.session.add(user)
            db.session.commit()

        totp = TOTP(Config.OTP_SECRET)
        otp = totp.now()
        user.otp = otp
        user.otp_created_at = datetime.now(timezone.utc)
        db.session.commit()

        # Store in session
        session['signup_email'] = email
        session['auth_flow'] = 'guest'  # ← NEW: Track flow type

        if send_otp_email(email, otp):
            flash("OTP has been sent to your email.")
            return redirect(url_for('main.verify_otp', email=email))
        else:
            flash("Failed to send OTP. Please try again.")
            return redirect(url_for('main.login'))

    return render_template('login.html')


@main.route('/login/password', methods=['GET', 'POST'])
def login_with_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for('main.login'))

        user = User.query.filter_by(email=email).first()
        if user and not user.is_guest and user.check_password(password):
            login_user(user)
            flash("✅ Logged in successfully!")
            return redirect(url_for('main.welcome'))
        else:
            flash("❌ Invalid email or password.")
            return redirect(url_for('main.login'))

    return redirect(url_for('main.login'))


@main.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if not email:
        flash("Invalid or expired session.")
        return redirect(url_for('main.login'))

    user = User.query.filter_by(email=email).first()
    if not user or not user.otp:
        flash("Invalid or expired session.")
        return redirect(url_for('main.login'))

    if user.otp_created_at:
        otp_created_at = make_aware(user.otp_created_at)
        if (datetime.now(timezone.utc) - otp_created_at).total_seconds() > Config.OTP_EXPIRY_MINUTES * 60:
            flash("OTP has expired. Please request a new one.")
            return redirect(url_for('main.login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        totp = TOTP(Config.OTP_SECRET)

        if totp.verify(entered_otp, valid_window=1):
            user.otp = None
            user.otp_created_at = None
            db.session.commit()
            login_user(user)

            # Check flow type
            flow = session.get('auth_flow')
            if flow == 'signup':
                flash("✅ Account created! Please complete your profile and set a password.")
                return redirect(url_for('main.complete_profile'))
            elif flow == 'guest':
                flash("✅ Welcome, Guest!")
                return redirect(url_for('main.welcome'))
            else:
                return redirect(url_for('main.welcome'))

        else:
            flash("❌ Invalid OTP. Please try again.", "error")

    return render_template('verify_otp.html', email=email)


@main.route('/resend-otp/<email>')
def resend_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.')
        return redirect(url_for('main.login'))

    totp = TOTP(Config.OTP_SECRET)
    otp = totp.now()
    user.otp = otp
    user.otp_created_at = datetime.now(timezone.utc)
    db.session.commit()

    if send_otp_email(email, otp):
        flash('✅ A new OTP has been sent to your email.')
    else:
        flash('❌ Failed to send OTP. Please try again.')

    return redirect(url_for('main.verify_otp', email=email))


@main.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login", next=url_for("main.welcome")))

    resp = google.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch your Google profile.")
        return redirect(url_for("main.login"))

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
            is_guest=False
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"🎉 Welcome, {first_name}! You're logged in with Gmail.")
    return redirect(url_for("main.welcome"))


@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash("Email is required.")
            return redirect(url_for('main.forgot_password'))

        user = User.query.filter_by(email=email).first()
        if not user or user.is_guest:
            flash("No account found for this email.")
            return redirect(url_for('main.forgot_password'))

        reset_token = secrets.token_urlsafe(32)
        user.reset_token = reset_token
        user.reset_token_expires = datetime.now(timezone.utc) + timedelta(minutes=30)  # ✅ Fixed
        db.session.commit()

        reset_link = url_for('main.reset_password', token=reset_token, _external=True)
        subject = "Password Reset Request"
        body = f"""
Hello,

Click the link below to reset your password:

{reset_link}

This link will expire in 30 minutes.

Welcome to PromptArena - Where Words Battle!
        """.strip()

        try:
            from flask_mail import Message
            msg = Message(subject=subject, recipients=[email], body=body)
            current_app.extensions['mail'].send(msg)
            flash("A password reset link has been sent to your email.")
        except Exception as e:
            print(f"❌ Failed to send reset link: {e}")
            flash("Failed to send reset link. Please try again.")

        return redirect(url_for('main.forgot_password'))

    return render_template('forgot_password.html')


@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Invalid or expired reset token.")
        return redirect(url_for('main.login'))

    expires = user.reset_token_expires
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if not expires or expires < datetime.now(timezone.utc):
        flash("Invalid or expired reset token.")
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for('main.reset_password', token=token))

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()

        flash("✅ Password reset successfully! Please log in.")
        return redirect(url_for('main.login'))

    return render_template('reset_password.html', token=token)


@main.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', user=current_user)


@main.route('/complete_profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    if not current_user.is_guest:
        return redirect(url_for('main.welcome'))

    if request.method == 'POST':
        current_user.first_name = request.form['first_name'].strip()
        current_user.last_name = request.form['last_name'].strip()
        current_user.mobile_number = request.form.get('mobile_number', '').strip()

        password = request.form.get('password')
        if password:
            if len(password) < 6:
                flash("Password must be at least 6 characters.")
                return redirect(url_for('main.complete_profile'))
            current_user.set_password(password)

        current_user.is_guest = False
        db.session.commit()

        # Clear session
        session.pop('signup_email', None)
        session.pop('auth_flow', None)

        # Logout and redirect to login
        logout_user()
        flash('🎉 Account created! Please log in with your new password.')
        return redirect(url_for('main.login'))

    return render_template('complete_profile.html')


@main.route('/prompting_space', methods=['GET', 'POST'])
@login_required
def prompting_space():
    if request.method == 'POST':
        level = request.form['level']
        battle_type = request.form['battle_type']
        session['level'] = level
        session['battle_type'] = battle_type
        flash(f"Selected: {level} Level | {battle_type}")
        return redirect(url_for('main.battle_arena'))
    return render_template('prompting_space.html', user=current_user)


@main.route('/battle_arena', methods=['GET', 'POST'])
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
            return redirect(url_for('main.battle_arena'))

        evaluation = evaluate_prompt_with_ai(user_prompt, level)  # ← From utils.py

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
        session['last_submission_id'] = submission.id
        flash("Prompt submitted and evaluated!")
        return redirect(url_for('main.evaluation'))

    return render_template('battle_arena.html', level=level, battle_type=battle_type, topic=topic, user=current_user)


@main.route('/evaluation')
@login_required
def evaluation():
    submission_id = session.get('last_submission_id')
    if not submission_id:
        flash("No evaluation data found.")
        return redirect(url_for('main.welcome'))
    submission = PromptSubmission.query.get_or_404(submission_id)
    if submission.user_id != current_user.id:
        flash("Unauthorized.")
        return redirect(url_for('main.welcome'))
    return render_template('evaluation.html', submission=submission, user=current_user)


@main.route('/leaderboard')
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


@main.route('/payment')
@login_required
def payment():
    return render_template('payment.html')


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('main.login'))


# ====================
# 1V1 BATTLE ROUTES
# ====================

@main.route('/battle/create', methods=['GET', 'POST'])
@login_required
def create_battle():
    if request.method == 'POST':
        level = request.form.get('level', 'Basic').title()
        custom_topic = request.form.get('topic', '').strip()
        topics = {
            'Basic': 'A robot discovers friendship for the first time.',
            'Intermediate': 'A time loop resets every 24 hours.',
            'Pro': 'An AI begins to question its own reality.'
        }
        topic = custom_topic or topics.get(level, 'Create a creative prompt.')
        battle = Battle(
            topic=topic,
            level=level,
            status='waiting',
            creator_id=current_user.id
        )
        db.session.add(battle)
        db.session.commit()
        flash("⚔️ Battle created! Waiting for an opponent...")
        return redirect(url_for('main.join_battle', battle_id=battle.id))
    return render_template('battle_create.html', user=current_user)


@main.route('/battle/join/<int:battle_id>')
@login_required
def join_battle(battle_id):
    battle = Battle.query.get_or_404(battle_id)
    if battle.status == 'completed':
        flash("This battle has already ended.")
        return redirect(url_for('main.leaderboard'))
    if battle.has_user(current_user.id):
        return redirect(url_for('main.battle_arena_1v1', battle_id=battle_id))
    if battle.is_full():
        flash("Battle is full! Creating a new one...")
        return redirect(url_for('main.create_battle'))
    return redirect(url_for('main.battle_arena_1v1', battle_id=battle_id))


@main.route('/battle/arena/<int:battle_id>', methods=['GET', 'POST'])
@login_required
def battle_arena_1v1(battle_id):
    battle = Battle.query.get_or_404(battle_id)
    existing = BattleSubmission.query.filter_by(battle_id=battle_id, user_id=current_user.id).first()
    if existing:
        return redirect(url_for('main.battle_wait', battle_id=battle_id))
    if request.method == 'POST':
        prompt_text = request.form.get('prompt', '').strip()
        if not prompt_text:
            flash("Prompt cannot be empty.")
            return redirect(url_for('main.battle_arena_1v1', battle_id=battle_id))
        evaluation = evaluate_prompt_with_ai(prompt_text, battle.level)
        submission = BattleSubmission(
            battle_id=battle.id,
            user_id=current_user.id,
            prompt_text=prompt_text,
            creativity_score=evaluation['creativity'],
            relevance_score=evaluation['relevance'],
            clarity_score=evaluation['clarity'],
            overall_score=evaluation['overall'],
            feedback=evaluation['feedback']
        )
        db.session.add(submission)
        db.session.commit()
        if battle.is_full():
            battle.status = 'completed'
            battle.completed_at = datetime.now(timezone.utc)
        else:
            battle.status = 'active'
        db.session.commit()
        return redirect(url_for('main.battle_wait', battle_id=battle_id))
    return render_template('battle_arena_1v1.html', battle=battle, user=current_user)


@main.route('/battle/wait/<int:battle_id>')
@login_required
def battle_wait(battle_id):
    battle = Battle.query.get_or_404(battle_id)
    my_submission = BattleSubmission.query.filter_by(battle_id=battle_id, user_id=current_user.id).first()
    if battle.status == 'completed':
        submissions = BattleSubmission.query.filter_by(battle_id=battle_id).all()
        if len(submissions) < 2:
            winner = my_submission.user if my_submission else None
            message = "You win by default — opponent didn't submit!"
        else:
            sorted_subs = sorted(submissions, key=lambda x: x.overall_score, reverse=True)
            winner = sorted_subs[0].user
            message = f"{winner.first_name} wins!"
        return render_template('battle_result.html', battle=battle, winner=winner, my_submission=my_submission, submissions=submissions, message=message, user=current_user)
    opponent = battle.get_opponent(current_user.id)
    return render_template('battle_wait.html', battle=battle, my_submission=my_submission, opponent=opponent, user=current_user)