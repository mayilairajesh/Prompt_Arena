# models.py
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Define db only once, here
db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    mobile_number = db.Column(db.String(20))
    password_hash = db.Column(db.String(256))
    otp = db.Column(db.String(6))
    otp_created_at = db.Column(db.DateTime)
    is_guest = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False

    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}>"


class PromptSubmission(db.Model):
    __tablename__ = 'prompt_submission'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    level = db.Column(db.String(20), nullable=False)
    battle_type = db.Column(db.String(30), nullable=False)
    prompt_text = db.Column(db.Text, nullable=False)
    creativity_score = db.Column(db.Float, nullable=False)
    relevance_score = db.Column(db.Float, nullable=False)
    clarity_score = db.Column(db.Float, nullable=False)
    overall_score = db.Column(db.Float, nullable=False)
    feedback = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('submissions', lazy=True))

    def __repr__(self):
        return f"<PromptSubmission {self.overall_score}/10>"