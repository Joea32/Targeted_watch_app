from extensions import db
from models import User, CheckIn, Vote, ProofUpload
from datetime import datetime, date
from datetime import datetime, timezone

from datetime import datetime, timedelta
from models import User, Alert

from itsdangerous import URLSafeTimedSerializer
from flask import current_app

from flask import current_app
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from extensions import mail

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import current_app

def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config.get('SECURITY_PASSWORD_SALT', 'email-confirm-salt'))

#def send_email(to, subject, template):
#    sender_email = current_app.config.get('MAIL_DEFAULT_SENDER', 'not-set@example.com')
#    print(f"Sending email from: {sender_email}")  # <-- Add it here

#    msg = Message(
#        subject,
#        recipients=[to],
#        html=template,
#        sender=sender_email
#    )

#    try:
#        mail.send(msg)
#        print("[send_email] Email sent successfully!")
#    except Exception as e:
#        print(f"[send_email] Exception while sending email: {e}")

#import requests

#def send_email(to, subject, html):
#    return requests.post(
#        f"https://api.mailgun.net/v3/{current_app.config['MAILGUN_DOMAIN']}/messages",
#        auth=("api", current_app.config['MAILGUN_API_KEY']),
#        data={
#            "from": current_app.config['MAILGUN_FROM_EMAIL'],
#            "to": [to],
#            "subject": subject,
#            "html": html,
#        }
#    )



import os
from werkzeug.utils import secure_filename

#from datetime import datetime, timedelta, timezone

# Calculate trust score based on user activity
def calculate_trust_score(user):
    points_per_checkin = 10
    points_per_proof = 20
    points_per_upvote = 5

    checkin_points = user.checkin_count * points_per_checkin
    proof_points = user.proof_upload_count * points_per_proof
    upvote_points = user.community_votes_count * points_per_upvote

    return checkin_points + proof_points + upvote_points

# Update user trust level and badge based on trust score
def update_trust_level(user):
    score = calculate_trust_score(user)
    user.trust_score = score  # Save the calculated score

    if score >= 10000:
        user.trust_level = 'Verified'
        user.badge = 'verified'
        user.trusted = True
        # Reset negative counts on verification
        user.negative_action_count = 0
        user.warnings_count = 0
    elif score >= 5000:
        user.trust_level = 'Trusted Profile'
        user.badge = 'trusted'
        user.trusted = False
    elif score >= 1000:
        user.trust_level = 'Long-term Watcher'
        user.badge = 'watcher'
        user.trusted = False
    else:
        user.trust_level = 'New/Unverified'
        user.badge = 'new'
        user.trusted = False

    db.session.commit()

# Wrapper function for compatibility with app.py import
def update_user_verification(user):
    update_trust_level(user)

# Record negative actions and remove verification if needed
def record_negative_action(user):
    if user.badge != 'verified':
        return

    user.negative_action_count += 1
    user.warnings_count += 1

    if user.negative_action_count >= 3:
        user.badge = 'new'
        user.trust_level = 'New/Unverified'
        user.trusted = False
        user.negative_action_count = 0
        user.warnings_count = 0

    db.session.commit()

# User activity triggers to add trust points and update trust level
#def user_check_in(user):
#    user.checkin_count = (user.checkin_count or 0) + 1
#    update_trust_level(user)


#def user_check_in(user):
#    now = datetime.utcnow()
#    today = now.date()  # UTC date

    # Always increment checkin_count
#    user.checkin_count = (user.checkin_count or 0) + 1

    # Only increase trust_score once per day
#    if not user.last_checkin or user.last_checkin.date() < today:
#        user.score = (user.score or 0) + 5  # Add your trust points here
#        user.last_checkin = now  # update last check-in datetime

#        update_trust_level(user)  # update trust level only if trust_score changed
#    else:
        # No trust points added, just commit the checkin_count increment
#        db.session.commit()

def user_check_in(user):
    now = datetime.now(timezone.utc)  # timezone-aware UTC datetime
    today = now.date()                 # just the date part in UTC

    # Always increment checkin_count
    user.checkin_count = (user.checkin_count or 0) + 1

    # Only increase trust_score once per UTC day
    if not user.last_checkin or user.last_checkin.date() < today:
        user.score = (user.score or 0) + 5  # Add trust points here
        user.last_checkin = now             # update last check-in datetime

        update_trust_level(user)            # update trust level only if trust_score changed
    else:
        # No trust points added, just commit the checkin_count increment
        db.session.commit()

    return f"Check-in complete. Trust score: {user.score}"

def user_receive_vote(user, upvote=True):
    user.community_votes_count = (user.community_votes_count or 0) + (1 if upvote else 0)
    update_trust_level(user)

def user_upload_proof(user):
    user.proof_upload_count = (user.proof_upload_count or 0) + 1
    update_trust_level(user)

def user_reported_for_bad_behavior(user):
    record_negative_action(user)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file, upload_folder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        return filename
    return None



def check_missing_users_and_alert():
    threshold = datetime.now(timezone.utc) - timedelta(hours=24)
    missing_users = User.query.filter(User.last_checkin < threshold).all()

    for missing_user in missing_users:
        other_users = User.query.filter(User.id != missing_user.id).all()
        for user in other_users:
            alert = Alert(
                user_id=user.id,
                message=f"{missing_user.name} has not checked in in over 24 hours. Please check on them.",
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(alert)
    db.session.commit()


def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm-salt')

def confirm_token(token, expiration=3600):  # 1 hour default expiry
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='email-confirm-salt',
            max_age=expiration
        )
    except Exception:
        return False
    return email

def generate_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config.get('SECURITY_PASSWORD_SALT', 'email-confirm-salt'))

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=current_app.config['MAIL_USERNAME'])
    mail.send(msg)


def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config.get('PASSWORD_RESET_SALT', 'password-reset-salt'))

def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config.get('PASSWORD_RESET_SALT', 'password-reset-salt'),
            max_age=expiration
        )
    except SignatureExpired:
        return None  # token expired
    except BadSignature:
        return None  # invalid token
    return email

# utils.py
from flask import current_app
import requests

def verify_captcha(response_token):
    # Skip CAPTCHA check if in development mode
    if current_app.config.get('ENV') == 'development':
        return True

    secret_key = current_app.config.get('RECAPTCHA_SECRET_KEY')
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        'secret': secret_key,
        'response': response_token
    }
    r = requests.post(url, data=payload)
    result = r.json()
    return result.get("success", False)

#def verify_captcha(response_token):
#    # TEMPORARY: Always return True during development
#    return True  # <-- Remember to change this in production!
