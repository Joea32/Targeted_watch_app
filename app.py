from utils import admin_required
# ------------------ Standard Library ------------------
import os
import uuid
from datetime import datetime, timedelta
from functools import wraps

# ------------------ Third-party Imports ------------------
from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash, abort, jsonify, send_from_directory
)
from flask_login import (
    LoginManager, login_user, login_required, current_user
)
from flask_migrate import upgrade
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from dotenv import load_dotenv
from whitenoise import WhiteNoise

# ------------------ Local Imports ------------------
from extensions import db, migrate, mail, login_manager
from models import User
from auth_routes import auth as auth_blueprint
from logging_config import setup_logging
from utils import (
    verify_captcha, generate_token, send_email,
    generate_reset_token, confirm_reset_token,
    update_user_verification, user_check_in,
    user_receive_vote, save_file, update_trust_level
)
from token_utils import confirm_token

from auth import check_password

# ------------------ Load Environment ------------------
load_dotenv()

# ------------------ App Initialization ------------------

from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, jsonify, send_from_directory
#from flask_login import login_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)

# ------------------ Blueprint Registration ------------------
from auth_routes import auth as auth_blueprint
app.register_blueprint(auth_blueprint, url_prefix='/auth')

# Load config based on environment
env = os.environ.get('FLASK_ENV', 'development')
if env == 'production':
    app.config.from_object('config.ProductionConfig')
else:
    app.config.from_object('config.DevelopmentConfig')

app.secret_key = app.config['SECRET_KEY']

# ------------------ Static and Upload Folder Config ------------------
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
app.config['UPLOAD_FOLDER_PROFILE'] = os.path.join(basedir, 'static', 'profiles')
app.config['UPLOAD_FOLDER_PROOF'] = os.path.join(basedir, 'static', 'proofs')
app.config['UPLOAD_FOLDER_CHECKIN'] = os.path.join(basedir, 'static', 'checkins')

for folder in [
    app.config['UPLOAD_FOLDER'],
    app.config['UPLOAD_FOLDER_PROFILE'],
    app.config['UPLOAD_FOLDER_PROOF'],
    app.config['UPLOAD_FOLDER_CHECKIN']
]:
    os.makedirs(folder, exist_ok=True)

# ------------------ Middleware ------------------
app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/', prefix='static/')

# ------------------ App Config ------------------
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'pdf',
    'mp4', 'mov', 'avi', 'mkv', 'mp3', 'wav', 'webm'
}

# ------------------ Init Extensions ------------------
db.init_app(app)
migrate.init_app(app, db)
mail.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# ------------------ Flask-Login User Loader ------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ Before Request Handlers ------------------
@app.before_request
def block_banned_users():
    if current_user.is_authenticated and current_user.is_banned and not current_user.is_admin:
        abort(403)

# ------------------ Context Processor ------------------
@app.context_processor
def inject_user():
    return dict(user=current_user)

# ------------------ Register Blueprints ------------------
#app.register_blueprint(auth_blueprint, url_prefix='/auth')

# ------------------ Logging ------------------
setup_logging(app)

# ------------------ Routes ------------------
#@app.route('/')
#def index():
#    return render_template('index.html')

# ------------------ Run Server ------------------
if __name__ == '__main__':
    app.run()
# ------------------ ERROR HANDLERS -----------------

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    flash("File too large. Maximum allowed size is 50MB.", "danger")
    return redirect(request.url), 413

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

# ------------------ HELPERS ------------------------

def allowed_file(filename):
    """Check if uploaded file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#def login_required(f):
#    """Decorator to require login for routes."""
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#        if 'user_id' not in session:
#            flash("Please login to access this page.", "warning")
#            return redirect(url_for('login'))
#        # Refresh session expiration
#        session.permanent = True
#        return f(*args, **kwargs)
#    return decorated_function

def save_file(file, upload_folder):
    """Save uploaded file with a unique filename, handling size validation."""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)

        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)  # Reset pointer to start

        max_size = app.config.get('MAX_CONTENT_LENGTH', 50 * 1024 * 1024)
        if file_length > max_size:
            return None

        file.save(file_path)
        return unique_filename
    return None

# ------------------ ROUTES -------------------------

@app.route('/')
def index():
    return render_template('index.html')

# ----------- AUTHENTICATION ------------------------

import requests

from utils import verify_captcha  # Add this import

from auth import hash_password

#import os

@app.route('/register', methods=['GET', 'POST'])
def register(): 
    
    if request.method == 'POST':
        print("[register] POST request received")

        # ✅ CAPTCHA verification with dev bypass
        captcha_response = request.form.get('g-recaptcha-response')
        if not verify_captcha(captcha_response):
            flash("CAPTCHA verification failed. Please try again.", "danger")
            return redirect(url_for('register'))

        # Registration logic
        name = request.form.get('name', '').strip()
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user_type = request.form.get('user_type', 'victim').lower()

        if not name:
            flash("Name is required.", "danger")
            return redirect(url_for('register'))
        if not username or not password or not email:
            flash("Username, email and password are required.", "danger")
            return redirect(url_for('register'))
        if user_type not in ['victim', 'supporter']:
            user_type = 'victim'

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "warning")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for('register'))

        supporter_id_proof = None
        if user_type == 'supporter' and 'supporter_id_proof' in request.files:
            file = request.files['supporter_id_proof']
            if file and allowed_file(file.filename):
                filename = save_file(file, app.config['UPLOAD_FOLDER_PROOF'])
                if not filename:
                    flash("Supporter ID proof file too large or invalid.", "danger")
                    return redirect(url_for('register'))
                supporter_id_proof = filename

        new_user = User(
            name=name,
            username=username,
            email=email,
            password=hash_password(password),
            user_type=user_type,
            supporter_id_proof=supporter_id_proof,
            verification_status=VerificationStatusEnum.PENDING.value if supporter_id_proof else VerificationStatusEnum.UNVERIFIED.value
        )

        db.session.add(new_user)
        db.session.commit()
        print(f"[register] New user created with email: {new_user.email}")

        token = generate_token(new_user.email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"

        print("[register] About to call send_email()")
        # send_email(new_user.email, subject, html)
        print("[register] send_email() skipped")

        flash("Registration successful. A confirmation email has been sent to your email address.", "success")
        return redirect(url_for('login'))

    print("[register] GET request - showing register page")
    return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_input = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')

        # Query user by username or email
        user = User.query.filter(
            (User.username == user_input) | (User.email == user_input)
        ).first()

        if user:
            # If your passwords are bcrypt hashed (recommended)
            if user.password.startswith('$2'):  # bcrypt hash prefix
                if check_password(password, user.password):
                    login_user(user)
                    flash("Login successful.", "success")
                    return redirect(url_for('dashboard'))
            else:
                # Legacy plain text password (not recommended)
                if user.password == password:
                    # Upgrade password hash
                    user.password = hash_password(password)
                    db.session.commit()
                    login_user(user)
                    flash("Login successful. Password security upgraded.", "success")
                    return redirect(url_for('dashboard'))

        flash("Invalid username/email or password.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# ----------- DASHBOARD & USER INTERACTIONS ---------

#from flask_login import current_user

@app.route('/dashboard')
@login_required
def dashboard():
    #user = current_user  # use flask-login's current_user
    #if not user:
    #    flash("User not found. Please log in again.", "warning")
    #    return redirect(url_for('login'))

     # Re-query user from DB to verify existence
    user = User.query.get(current_user.id)
    if not user:
        logout_user()
        flash("User not found. Please log in again.", "warning")
        return redirect(url_for('login'))

    # Enforce supporter verification
    if user.user_type == UserTypeEnum.SUPPORTER.value and user.verification_status != VerificationStatusEnum.VERIFIED.value:
        return render_template('verification_pending.html'), 403

    profiles = User.query.filter(User.id != user.id).all()
    protections = {p.protected_id for p in Protection.query.filter_by(protector_id=user.id).all()}

    now = datetime.utcnow()
    missed_threshold = now - timedelta(hours=24)

    profiles_info = []
    for p in profiles:
        protects = p.id in protections
        last_checkin = p.last_checkin
        missed_checkin = (last_checkin is None) or (last_checkin < missed_threshold)
        total_protectors = Protection.query.filter_by(protected_id=p.id).count()
        user_media = Media.query.filter_by(user_id=p.id).all()

        profiles_info.append({
            'user': p,
            'protects': protects,
            'last_checkin': last_checkin,
            'last_checkin_photo': p.last_checkin_photo,
            'missed_checkin': missed_checkin,
            'total_protectors': total_protectors,
            'media_files': user_media
        })

    return render_template(
        'dashboard.html',
        user=user,               # make sure template gets `user`
        profiles_info=profiles_info
    )


@app.route('/checkin', methods=['GET', 'POST'])
@login_required
def checkin():
    user = current_user  # Authenticated user

    if request.method == 'POST':
        file = request.files.get('checkin_photo')
        if file:
            filename = save_file(file, app.config['UPLOAD_FOLDER_CHECKIN'])
            if not filename:
                flash("Check-in photo file too large or invalid.", "danger")
                return redirect(request.url)
            user.last_checkin_photo = filename

        now = datetime.utcnow()
        today = now.date()

        already_checked_in_today = user.last_checkin and user.last_checkin.date() == today

        # Increment checkin count every time
        user.checkin_count = (user.checkin_count or 0) + 1
        user.last_checkin = now

        if not already_checked_in_today:
            user.score = (user.score or 0) + 5
            update_trust_level(user)
            flash("Check-in successful. Trust score updated!", "success")
        else:
            flash("You have already checked in today, so your trust score won't increase, but please keep checking in to let us know you are safe.", "info")

        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('checkin.html', user=user)


@app.route('/update_verification', methods=['POST'])
@login_required
def update_verification_route():
    # Only supporters can update verification status
    user = current_user
    if user.user_type != UserTypeEnum.SUPPORTER.value:
        abort(403)

    user_id_to_update = request.form.get('user_id')
    new_status = request.form.get('verification_status')

    if not user_id_to_update or not new_status:
        flash("Invalid data.", "danger")
        return redirect(url_for('dashboard'))

    target_user = User.query.get(user_id_to_update)
    if not target_user:
        flash("User not found.", "warning")
        return redirect(url_for('dashboard'))

    success = update_user_verification(target_user, new_status)
    if success:
        flash("Verification status updated.", "success")
    else:
        flash("Failed to update verification status.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        abort(404)  # User not found
    return render_template('profile.html', user=user)

#@app.route('/protect/<int:protected_id>', methods=['POST'], endpoint='protect')
#@login_required
#def protect_user(protected_id):
#    protector_id = session['user_id']
#
#    # Prevent users from protecting themselves
#    if protector_id == protected_id:
#        flash("You cannot protect yourself.", "warning")
#        return redirect(url_for('dashboard'))
#    
#    # Check if protection already exists
#    existing = Protection.query.filter_by(protector_id=protector_id, protected_id=protected_id).first()
#    if existing:
#        flash("You are already protecting this user.", "info")
#    else:
#        protection = Protection(protector_id=protector_id, protected_id=protected_id)
#        db.session.add(protection)
#        db.session.commit()
#        flash("Protection set successfully.", "success")

#    return redirect(url_for('dashboard'))

@app.route('/protect/<int:protected_id>', methods=['POST'], endpoint='protect')
@login_required
def protect_user(protected_id):
    protector_id = current_user.id  # get the logged-in user ID

    # Prevent users from protecting themselves
    if protector_id == protected_id:
        flash("You cannot protect yourself.", "warning")
        return redirect(url_for('dashboard'))

    # Check if protection already exists
    existing = Protection.query.filter_by(protector_id=protector_id, protected_id=protected_id).first()
    if existing:
        flash("You are already protecting this user.", "info")
    else:
        protection = Protection(protector_id=protector_id, protected_id=protected_id)
        db.session.add(protection)
        db.session.commit()
        flash("Protection set successfully.", "success")

    return redirect(url_for('dashboard'))

@app.route('/unprotect/<int:protected_id>', methods=['POST'])
@login_required
def unprotect(protected_id):
    protector_id = current_user.id
    protection = Protection.query.filter_by(protector_id=protector_id, protected_id=protected_id).first()
    if protection:
        db.session.delete(protection)
        db.session.commit()
        flash("Protection removed.", "success")
    else:
        flash("Protection not found.", "warning")

    return redirect(url_for('dashboard'))



# --------- NEW ROUTES USING UTILS -----------------

@app.route('/checkin', methods=['GET'])
@login_required
def checkin_status():
    """GET endpoint to call user_check_in() from utils for the logged-in user."""
    user = current_user
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    try:
        result = user_check_in(user)
    except Exception as e:
        flash(f"Error during check-in: {e}", "danger")
        return redirect(url_for('dashboard'))

    flash(result, "success")
    return redirect(url_for('dashboard'))

@app.route('/vote', methods=['GET'])
@login_required
def vote_user():
    """
    GET endpoint to call user_receive_vote() from utils.
    Expects 'id' query parameter for the user receiving the vote.
    """
    user_id = request.args.get('id', type=int)
    if not user_id:
        flash("No user ID provided for voting.", "warning")
        return redirect(url_for('dashboard'))

    target_user = User.query.get(user_id)
    if not target_user:
        flash("User to vote for not found.", "warning")
        return redirect(url_for('dashboard'))

    try:
        result = user_receive_vote(target_user)
    except Exception as e:
        flash(f"Error during voting: {e}", "danger")
        return redirect(url_for('dashboard'))

    flash(f"Vote received successfully: {result}", "success")
    return redirect(url_for('dashboard'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    #user = User.query.get(session['user_id'])
    user = current_user

    if not user:
        flash("User not found. Please log in again.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user.name = request.form.get('name', '').strip()
        user.username = request.form.get('username', '').strip()
        user.bio = request.form.get('bio', '').strip()

        # Validate required fields
        if not user.name or not user.username:
            flash("Name and username cannot be empty.", "danger")
            return redirect(url_for('edit_profile'))

        # Check username availability
        existing_user = User.query.filter(User.username == user.username, User.id != user.id).first()
        if existing_user:
            flash("Username already taken by another user.", "warning")
            return redirect(url_for('edit_profile'))

        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = save_file(file, app.config['UPLOAD_FOLDER_PROFILE'])
                if filename:
                    user.profile_photo = filename
                else:
                    flash("Profile picture upload failed.", "danger")
                    return redirect(url_for('edit_profile'))

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', user=user)

@app.route('/profile/<int:user_id>')
def profile(user_id):
    user = User.query.get_or_404(user_id)

    user_is_verified = getattr(user, 'verification_status', '') == 'verified'
    #trust_score = getattr(user, 'trust_score', None)
    #trust_score = getattr(user, 'score', 0)  # or default to 0 if None
    trust_score = user.score
    media_files = getattr(user, 'media_files', [])
    user.media_files = media_files

    return render_template(
        'profile.html',
        user=user,
        user_is_verified=user_is_verified,
        trust_score=trust_score
    )


@app.route('/upload_media', methods=['GET', 'POST'])
@login_required
def upload_media():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            ext = filename.rsplit('.', 1)[1].lower()
            if ext in ['jpg', 'jpeg', 'png', 'gif']:
                media_type = 'image'
            elif ext in ['mp4', 'mov']:
                media_type = 'video'
            elif ext in ['mp3', 'wav']:
                media_type = 'audio'
            else:
                media_type = 'document'

            media = Media(
                user_id=current_user.id,
                filename=filename,
                original_filename=file.filename,
                media_type=media_type
            )
            db.session.add(media)
            db.session.commit()

            flash('Media uploaded!', 'success')
            return redirect(url_for('profile', user_id=current_user.id))

        else:
            flash('No file selected.', 'error')
            return redirect(url_for('upload_media'))

    # GET request — show upload form
    return render_template('upload_media.html')


@app.route('/user/<int:user_id>/media', methods=['GET'])
def get_user_media(user_id):
    user = User.query.get_or_404(user_id)
    media_list = [
        {
            'id': media.id,
            'filename': media.filename,
            'original_filename': media.original_filename,
            'media_type': media.media_type,
            'upload_date': media.upload_date
        }
        for media in user.media_files
    ]
    return jsonify(media_list)


@app.route('/media/<filename>')
def serve_media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400

    # Save file
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER_UPLOADS'], filename)
    file.save(path)

    # Create media record
    media = Media(user_id=current_user.id, filename=filename)
    db.session.add(media)

    # Update score
    current_user.score = (current_user.score or 0) + 2  # or 5 if selfie detection added

    db.session.commit()
    return jsonify({"message": "Upload successful and score updated!"}), 200

@app.route("/score", methods=["GET"])
@login_required
def get_score():
    return jsonify({"username": current_user.username, "score": current_user.score}), 200

with app.app_context():
    from models import User, Media, Protection, UserTypeEnum, VerificationStatusEnum

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password_token', token=token, _external=True)
            html = render_template('reset_password_email.html', reset_url=reset_url)
            subject = "Password Reset Requested"
            send_email(user.email, subject, html)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email not found.', 'warning')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = confirm_reset_token(token)
    if not email:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not password or password != confirm_password:
            flash('Passwords do not match or are empty.', 'danger')
            return redirect(url_for('reset_password_token', token=token))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('reset_password_request'))

        user.password = hash_password(password)
        db.session.commit()
        flash('Your password has been updated. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password_form.html')



#@auth.route('/confirm/<token>')
#def confirm_email(token):
#    email = confirm_token(token)
#    if not email:
#        flash('The confirmation link is invalid or has expired.', 'danger')
#        return redirect(url_for('auth.login'))

#    user = User.query.filter_by(email=email).first()
#    if not user:
#        flash('User not found.', 'danger')
#        return redirect(url_for('auth.login'))

#    if user.verified:
#        flash('Account already confirmed. Please login.', 'success')
#    else:
#        user.verified = True
#        user.verification_status = 'verified'
#        db.session.commit()
#        flash('You have confirmed your account. Thanks!', 'success')

#    return redirect(url_for('auth.login'))

#auth = Blueprint('auth', __name__)

#@auth.route('/confirm/<token>')
#def confirm_email(token):
#    email = confirm_token(token)
#    if not email:
#        flash('The confirmation link is invalid or has expired.', 'danger')
#        return redirect(url_for('auth.login'))

#    user = User.query.filter_by(email=email).first()
#    if not user:
#        flash('User not found.', 'danger')
#        return redirect(url_for('auth.login'))

#    if user.verified:
#        flash('Account already confirmed. Please login.', 'success')
#    else:
#        user.verified = True
#        user.verification_status = 'verified'
#        db.session.commit()
#        flash('You have confirmed your account. Thanks!', 'success')

#    return redirect(url_for('auth.login'))

#@app.route('/test-email')
#def test_email():
#    try:
#        msg = Message("Test Email from Flask",
#                      recipients=["josepha@peoplesdefence.org"],
#                      body="This is a test email from Flask + SendGrid.")
#        mail.send(msg)
#        return "Email sent!"
#    except Exception as e:
#        return f"Failed to send email: {str(e)}"
    
#@app.route('/test-email-debug')
#def test_email_debug():
#    print("test_email_debug called")
#    send_email('your-email@example.com', 'Test Subject', '<p>Test Body</p>')
#    return "Test email triggered. Check your console!"

#@app.route('/test-mailgun')
#def test_mailgun():
#    response = send_email('your-email@example.com', 'Test Mailgun', '<b>This is a test</b>')
#    if response.status_code == 200:
#        return "Mailgun email sent!"
#    else:
#        return f"Failed to send email: {response.text}", 500

#@app.route('/clear_users', methods=['POST'])
#def clear_users():
#    auth_header = request.headers.get('Authorization', '')
#    print(f"Auth header: {auth_header}")  # <--- Add this
#    expected_token = os.getenv('CLEAR_USERS_SECRET_KEY')
#    print(f"Expected token: Bearer {expected_token}")  # <--- And this

#    if auth_header != f"Bearer {expected_token}":
#        print("Authorization failed")
#        abort(403)

#    num_deleted = User.query.delete()
#    db.session.commit()

#    print(f"Deleted {num_deleted} users")
#    return f"Deleted {num_deleted} users", 200

#@app.route('/num_users')
#def num_users():
#    return str(User.query.count())

#@app.route('/admin/delete_all_users')
#def admin_delete_all_users():
#    num_deleted = User.query.delete()
#    db.session.commit()
#    return f"Deleted {num_deleted} users."

#@app.route('/init_db')
#def init_db():
#    # Optional: Protect this route so only admins can run it
#    if not current_user.is_authenticated or current_user.user_type != 'admin':
#        abort(403)  # Forbidden if not logged in as admin
    
#    from yourapp import db, app  # adjust import if needed
#    with app.app_context():
#        db.create_all()
#    return "Database tables created!"

#from flask_migrate import upgrade

#@app.route('/migrate-db')
#def migrate_db():
#    try:
#        upgrade()  # Applies the latest migrations
#        return "Database migrations applied successfully!"
#    except Exception as e:
#        return f"Migration failed: {e}"

#from flask import abort
#from flask_login import current_user

#@app.route('/init-db')
#def init_db():
    # OPTIONAL: protect so only logged-in admin can run this
    # Remove this `if` block if you're locked out completely
#    if not current_user.is_authenticated or current_user.user_type != 'admin':
 #       abort(403)

  #  from yourapp import db  # make sure this import is correct
   # db.create_all()  # this creates all missing tables
   # return "Database tables created!"

#from app import app, db

# Import all models here so SQLAlchemy metadata knows about tables
#from models import User, Media, CheckIn, ProofUpload, Protection, Vote, Alert

#@app.route('/init-db')
#def init_db():
#    try:
#        db.create_all()
#        return "Database tables created successfully!"
#    except Exception as e:
#        return f"Error creating tables: {e}"



######

#from flask import abort
#from flask_login import current_user

#@app.before_request
#def block_banned_users():
#    if current_user.is_authenticated and getattr(current_user, 'is_banned', False):
#        abort(403)  # Forbidden access; optionally redirect to a "banned" page

#from flask import (
#    Flask, render_template, redirect, url_for, request, flash, abort, jsonify
#)
#from flask_login import login_required, current_user
#from werkzeug.security import generate_password_hash
#from models import User, db
#from utils import admin_required  # assuming you have this decorator

#app = Flask(__name__)

# --- Block banned users (non-admins) from accessing any route ---
@app.before_request
def block_banned_users():
    if current_user.is_authenticated and current_user.is_banned and not current_user.is_admin:
        abort(403)  # Forbidden

# --- Admin user management page (GET shows users, POST handles ban/unban) ---
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        user = User.query.get(user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('admin_users'))

        if action == 'ban':
            user.is_banned = True
            flash(f"User {user.username} has been banned.", "success")
        elif action == 'unban':
            user.is_banned = False
            flash(f"User {user.username} has been unbanned.", "success")
        else:
            flash("Invalid action.", "danger")

        db.session.commit()
        return redirect(url_for('admin_users'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)

# --- Password reset for any user (admin only) ---
@app.route('/admin/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')

    if not username or not new_password:
        flash("Username and new password are required.", "danger")
        return redirect(url_for('admin_users'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_users'))

    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash(f"Password for {user.username} has been reset.", "success")
    return redirect(url_for('admin_users'))

# --- Optional: Create new admin user (admin only) ---
@app.route('/admin/create-admin', methods=['POST'])
@login_required
@admin_required
def create_admin():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists."}), 400

    hashed_password = generate_password_hash(password)
    new_admin = User(username=username, password=hashed_password, is_admin=True)
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({"message": f"Admin user '{username}' created successfully."}), 201

# --- Optional API ban/unban endpoints for AJAX or API usage ---
@app.route('/admin/ban-user', methods=['POST'])
@login_required
@admin_required
def ban_user_api():
    data = request.get_json()
    username = data.get("username")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    user.is_banned = True
    db.session.commit()
    return jsonify({"message": f"{username} has been banned."})

@app.route('/admin/unban-user', methods=['POST'])
@login_required
@admin_required
def unban_user_api():
    data = request.get_json()
    username = data.get("username")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found."}), 404
        
    user.is_banned = False
    db.session.commit()
    return jsonify({"message": f"{username} has been unbanned."})




# ------------------ RUN APP ------------------------
    
if __name__ == '__main__':
    app.run(debug=True)
