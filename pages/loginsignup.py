import secrets
from werkzeug.security import check_password_hash,generate_password_hash
from flask import render_template, session,url_for
from pages.models import User,db,PasswordResetToken,Organizations,TempUser
from config import mail_server,FREE_EMAIL_PROVIDERS,disposable
from datetime import datetime,timedelta

def generate_nonce(length=32):
    """Generate a secure random nonce."""
    return secrets.token_urlsafe(length)

def is_work_email(email):
    """Check if the email is from a common free email provider."""
    domain = email.split('@')[-1]
    return domain in FREE_EMAIL_PROVIDERS

def is_disposable_email(email):
    """Check if the email is from a known disposable email provider."""
    domain = email.split('@')[-1]
    return domain in disposable

def can_create_user(email):
    domain = email.split('@')[-1]  # Extract the domain from the email
    domain_count = Organizations.query.filter_by(domain=domain).first()
    
    if domain_count and domain_count.user_count >= 5:
        return False  # Limit reached
    return True  # Can create a new user

def verify_user(email):
    if is_work_email(email):
        return False  # Business email required
    if is_disposable_email(email):
        return False  # Disposable email not allowed
    if not can_create_user(email):
        return False  # Limit reached for free accounts
    return True  # Email is valid

# Helper function: Validate user
def validate_user(user, password):
    """Checks if the provided password matches the stored password hash."""
    return check_password_hash(user.password, password)

def sign_in_user(user):
    try:
        session.permanent= True
        session['user'] = str(user.user_id)  # Convert user_id to string
        session['user_email'] = str(user.email)  # Ensure email is a string
    except Exception as e:
        session.clear()

def user_exists(email):
    return User.query.filter_by(email=email).first()

def temp_exists(email):
    return TempUser.query.filter_by(email=email).first()
    
def generate_reset_token(user):
    token = secrets.token_urlsafe()
    expires_at = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
    reset_token = PasswordResetToken(user_id=user.user_id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    return token

def validate_reset_token(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if reset_token and reset_token.expires_at > datetime.utcnow():
        return reset_token.user
    return None

def send_email(first_name, email, verification_token):
    """
    Sends a verification email with a link.
    """
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    subject, html_body = create_welcome_email(first_name, verification_link)
    mail_server(email, subject, html_body)

def create_password_reset_email(reset_link):
    subject = "Password Reset Request"
    html_body = render_template("emails/password_reset.html", reset_link=reset_link)
    return subject, html_body

def create_welcome_email(first_name, verification_link):
    subject = "Welcome to Acumen Intelligence - Verify Your Email"
    html_body = render_template("emails/welcome.html", first_name=first_name, verification_link=verification_link)
    return subject, html_body

def reset_password(user, new_password):
    user.password = generate_password_hash(new_password)
    PasswordResetToken.query.filter_by(user_id=user.user_id).delete()  # Delete used tokens
    db.session.commit()