# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile_number = db.Column(db.String(20))
    otp = db.Column(db.String(6))  # For OTP login
    #password_hash = db.Column(db.String(256))  # For password login
    password_hash = db.Column(db.String(256), nullable=True)  # Nullable for Gmail users

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}>"


class PromptSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.String(20), nullable=False)  # Basic, Intermediate, Pro
    battle_type = db.Column(db.String(30), nullable=False)  # 1v1, Group, AI vs Human
    prompt_text = db.Column(db.Text, nullable=False)
    creativity_score = db.Column(db.Float, nullable=False)
    relevance_score = db.Column(db.Float, nullable=False)
    clarity_score = db.Column(db.Float, nullable=False)
    overall_score = db.Column(db.Float, nullable=False)
    feedback = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    # Relationship back to User
    user = db.relationship('User', backref=db.backref('submissions', lazy=True))

    def __repr__(self):
        return f"<PromptSubmission {self.overall_score}/10 by User {self.user_id}>"