import secrets,smtplib
from werkzeug.security import check_password_hash,generate_password_hash
from flask import session
from pages.models import User,db,PasswordResetToken
from config import app
from datetime import datetime,timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_nonce(length=32):
    """Generate a secure random nonce."""
    return secrets.token_urlsafe(length)

# Helper function: Validate user
def validate_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        return user
    return None

def sign_in_user(user):
    try:
        session.permanent= True
        session['user'] = str(user.user_id)  # Convert user_id to string
        session['user_email'] = str(user.email)  # Ensure email is a string
    except Exception as e:
        session.clear()


def user_exists(email):
    return User.query.filter_by(email=email).first()

def create_user(first_name, last_name, email, password):
    hashed_password = generate_password_hash(password)
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        is_google=False,
        is_paid=False
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user

def get_or_create_google_user(email, first_name, last_name):
    user = User.query.filter_by(email=email).first()
    if user:
        return user

    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password='',  # No password for Google users
        is_google=True,
        is_paid=False
    )
    db.session.add(new_user)
    db.session.commit()
    return new_user

def send_password_reset_email(recipient_email, reset_link):
    sender_email = app.config['MAIL_USERNAME']
    subject = "Password Reset Request"
    body = (
        "Hello,\n\n"
        "We received a request to reset your password. "
        "You can reset your password by clicking the link below:\n"
        f"{reset_link}\n\n"
        "If you did not request a password reset, please ignore this email.\n\n"
        "Best regards,\n"
        "Acumen Intelligence Team"
    )

    # Create a plain text email message
    msg = MIMEText(body)
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    try:
        # Set up the SMTP server and send the email
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()  # Enable TLS
            server.login(sender_email, app.config['MAIL_PASSWORD'])  # Log in to the server
            server.send_message(msg)  # Send the email
        return True
    except Exception as e:
        print(f"Failed to send password reset email: {e}")
        return False
    
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

def reset_password(user, new_password):
    user.password = generate_password_hash(new_password)
    PasswordResetToken.query.filter_by(user_id=user.user_id).delete()  # Delete used tokens
    db.session.commit()
