# models.py
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Define db only once
db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    mobile_number = db.Column(db.String(20), nullable=True)  # Explicitly allow NULL
    password_hash = db.Column(db.String(256), nullable=True)  # Nullable for guest users
    otp = db.Column(db.String(6))  # Consider using CHAR(6)
    otp_created_at = db.Column(db.DateTime(timezone=True))
    is_guest = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # For password reset
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expires = db.Column(db.DateTime(timezone=True), nullable=True)

    def set_password(self, password):
        """Hash and store password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check hashed password."""
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
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationship
    user = db.relationship('User', backref=db.backref('submissions', lazy=True, cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<PromptSubmission {self.overall_score}/10>"


class Battle(db.Model):
    __tablename__ = 'battle'

    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(200), nullable=False)
    level = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='waiting', nullable=False, index=True)
    max_participants = db.Column(db.Integer, default=2, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at = db.Column(db.DateTime(timezone=True))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Relationships
    creator = db.relationship('User', foreign_keys=[creator_id])
    winner = db.relationship('User', foreign_keys=[winner_id])
    submissions = db.relationship(
        'BattleSubmission',
        back_populates='battle',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def is_full(self):
        """Check if battle has reached max participants."""
        return self.submissions.count() >= self.max_participants

    def has_user(self, user_id):
        """Check if user already joined."""
        return self.submissions.filter_by(user_id=user_id).first() is not None

    def get_opponent(self, user_id):
        """Get opponent submission (if any)."""
        return self.submissions.filter(BattleSubmission.user_id != user_id).first()

    def __repr__(self):
        return f"<Battle {self.id} | {self.status}>"


class BattleSubmission(db.Model):
    __tablename__ = 'battle_submission'

    id = db.Column(db.Integer, primary_key=True)
    battle_id = db.Column(db.Integer, db.ForeignKey('battle.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    prompt_text = db.Column(db.Text, nullable=False)
    creativity_score = db.Column(db.Float, nullable=False)
    relevance_score = db.Column(db.Float, nullable=False)
    clarity_score = db.Column(db.Float, nullable=False)
    overall_score = db.Column(db.Float, nullable=False)
    feedback = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    user = db.relationship(
        'User',
        backref=db.backref('battle_submissions', lazy='dynamic', cascade='all, delete-orphan')
    )
    battle = db.relationship('Battle', back_populates='submissions')

    def __repr__(self):
        return f"<BattleSub {self.user.first_name}: {self.overall_score}/10>"