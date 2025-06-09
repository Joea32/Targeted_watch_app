from datetime import datetime
from enum import Enum
from flask_login import UserMixin
from extensions import db  # ✅ Only use this one
from encryption import encrypt, decrypt



# -------------------------------
# Enums
# -------------------------------

class UserTypeEnum(str, Enum):
    VICTIM = "victim"
    SUPPORTER = "supporter"

class VerificationStatusEnum(str, Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


# -------------------------------
# User Model
# -------------------------------

class User(UserMixin,db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)  # hashed

    # Last check-in timestamp
    last_checkin = db.Column(db.DateTime, nullable=True)

    # Activity counts
    checkin_count = db.Column(db.Integer, default=0)
    proof_upload_count = db.Column(db.Integer, default=0)
    community_votes_count = db.Column(db.Integer, default=0)
    score = db.Column(db.Integer, default=0)

    # Trust related
    trust_points = db.Column(db.Integer, default=0)
    trust_score = db.Column(db.Float, default=0.0)  # calculated trust score

    # Profile info
    #bio = db.Column(db.LargeBinary, nullable=True)
    _bio = db.Column(db.LargeBinary, nullable=True)
    @property
    def bio(self):
        if self._bio:
            return decrypt(self._bio)
        return None

    @bio.setter
    def bio(self, plaintext):
        if plaintext:
            self._bio = encrypt(plaintext)
        else:
            self._bio = None


    profile_pic = db.Column(db.String(255), nullable=True)
    badge = db.Column(db.String(50), default='New/Unverified')
    trusted = db.Column(db.Boolean, default=False)
    trust_level = db.Column(db.String(50), default='New/Unverified')

    # Negative actions
    negative_action_count = db.Column(db.Integer, default=0)
    warnings_count = db.Column(db.Integer, default=0)
    negative_marks = db.Column(db.Integer, default=0)

    # Optional proof and check-in media
    proof_file = db.Column(db.String(200), nullable=True)
    last_checkin_photo = db.Column(db.String(255), nullable=True)

    # Role-based fields
    user_type = db.Column(db.String(50), default=UserTypeEnum.VICTIM.value, nullable=False)
    is_verified_supporter = db.Column(db.Boolean, default=False)

    #supporter_id_proof = supporter_id_proof = db.Column(db.LargeBinary, nullable=True)
    _supporter_id_proof = db.Column(db.LargeBinary, nullable=True)
    @property
    def supporter_id_proof(self):
     if self._supporter_id_proof:
        return decrypt(self._supporter_id_proof)
     return None

    @supporter_id_proof.setter
    def supporter_id_proof(self, plaintext):
     if plaintext:
        self._supporter_id_proof = encrypt(plaintext)
     else:
        self._supporter_id_proof = None


    verification_status = db.Column(db.String(50), default=VerificationStatusEnum.UNVERIFIED.value)
    verified = db.Column(db.Boolean, default=False)

    # Relationships
    media_files = db.relationship('Media', backref='user', lazy=True, cascade='all, delete-orphan')
    checkins = db.relationship('CheckIn', back_populates='user', cascade='all, delete-orphan')
    proofs = db.relationship('ProofUpload', back_populates='user', cascade='all, delete-orphan')

    votes_cast = db.relationship('Vote', foreign_keys='Vote.voter_id', back_populates='voter', cascade='all, delete-orphan')
    votes_received = db.relationship('Vote', foreign_keys='Vote.target_user_id', back_populates='target_user', cascade='all, delete-orphan')

    protected = db.relationship('Protection', foreign_keys='Protection.protector_id', backref='protector', lazy='dynamic', cascade='all, delete-orphan')
    protected_by = db.relationship('Protection', foreign_keys='Protection.protected_id', backref='protected_user', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def protective_count(self):
        return self.protected.count()

    @property
    def protected_by_count(self):
        return self.protected_by.count()

    def update_trust_points(self, points):
        self.trust_points += points
        self._check_verification_status()
        db.session.commit()

    def add_negative_mark(self):
        self.negative_marks += 1
        if self.negative_marks > 3:
            self.verified = False
            self.trust_points = 0
            self.verification_status = VerificationStatusEnum.UNVERIFIED.value
        db.session.commit()

    def _check_verification_status(self):
        if self.trust_points >= 10000:
            self.verified = True
            self.verification_status = VerificationStatusEnum.VERIFIED.value
        elif self.trust_points < 10000 and self.verified:
            self.verified = False
            self.verification_status = VerificationStatusEnum.UNVERIFIED.value


# -------------------------------
# Media Model
# -------------------------------

class Media(db.Model):
    __tablename__ = 'media'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)
    media_type = db.Column(db.String(50), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Media {self.media_type}: {self.filename}>"


# -------------------------------
# Check-In Model
# -------------------------------

class CheckIn(db.Model):
    __tablename__ = 'checkins'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    photo_filename = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', back_populates='checkins')


# -------------------------------
# Proof Upload Model
# -------------------------------

class ProofUpload(db.Model):
    __tablename__ = 'proof_uploads'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='proofs')


# -------------------------------
# Protection Model
# -------------------------------

class Protection(db.Model):
    __tablename__ = 'protections'

    id = db.Column(db.Integer, primary_key=True)
    protector_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    protected_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------------
# Vote Model
# -------------------------------

class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  # 'upvote' or 'downvote'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    target_user = db.relationship('User', foreign_keys=[target_user_id], back_populates='votes_received')
    voter = db.relationship('User', foreign_keys=[voter_id], back_populates='votes_cast')

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    _message = db.Column("message", db.LargeBinary)  # encrypted message stored as bytes
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('alerts', lazy=True))

    @property
    def message(self):
        if self._message:
            return decrypt(self._message)
        return None

    @message.setter
    def message(self, plaintext):
        self._message = encrypt(plaintext)