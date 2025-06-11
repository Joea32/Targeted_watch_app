# auth_routes.py

from flask import Blueprint, flash, redirect, url_for
from models import User
from extensions import db
from utils import confirm_token

# Create the blueprint
auth = Blueprint('auth', __name__)

@auth.route('/confirm/<token>')
def confirm_email(token):
    # Verify the token and extract the email
    email = confirm_token(token)
    if not email:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))

    # Look up the user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))

    # Check if already verified
    if user.verified:
        flash('Account already confirmed. Please log in.', 'info')
    else:
        user.verified = True
        user.verification_status = 'verified'
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')

    return redirect(url_for('auth.login'))
