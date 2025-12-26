import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

from flask import render_template, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from pages.models import User, db, PasswordResetToken, Organization, TempUser
from config import mail_server, FREE_EMAIL_PROVIDERS, disposable


def generate_nonce(length: int = 32) -> str:
    """
    Generate a secure random nonce.
    
    Args:
        length (int): The length of the token (default is 32).
        
    Returns:
        str: A URL-safe random token.
    """
    return secrets.token_urlsafe(length)


def is_work_email(email: str) -> bool:
    """
    Determines if the email address belongs to a free email provider.
    
    Args:
        email (str): The email address.
        
    Returns:
        bool: True if the email is from a free provider, False otherwise.
    """
    domain = email.split('@')[-1].lower()
    return domain in FREE_EMAIL_PROVIDERS


def is_disposable_email(email: str) -> bool:
    """
    Determines if the email address is from a disposable provider.
    
    Args:
        email (str): The email address.
        
    Returns:
        bool: True if the email is disposable, False otherwise.
    """
    domain = email.split('@')[-1].lower()
    return domain in disposable


def can_create_user(email: str) -> bool:
    """
    Checks if a new user can be created based on the user count for the domain.
    
    Args:
        email (str): The user's email.
        
    Returns:
        bool: True if the domain has not reached its limit, False otherwise.
    """
    domain = email.split('@')[-1].lower()
    organization = Organization.query.filter_by(domain=domain).first()
    if organization and organization.user_count >= 5:
        return False
    return True


def verify_user(email: str) -> bool:
    """
    Validates whether the email is acceptable for user creation.
    
    Args:
        email (str): The user's email.
        
    Returns:
        bool: True if the email is acceptable, False otherwise.
    """
    if is_work_email(email):
        return False
    if is_disposable_email(email):
        return False
    if not can_create_user(email):
        return False
    return True


def validate_user(user: User, password: str) -> bool:
    """
    Checks if the provided password matches the stored password hash.
    
    Args:
        user (User): The user object.
        password (str): The plain-text password.
        
    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return check_password_hash(user.password, password)


def sign_in_user(user: User) -> None:
    """
    Signs in the user by storing their ID and email in the session.
    
    Args:
        user (User): The user to sign in.
    """
    try:
        session.permanent = True
        session['user'] = str(user.user_id)
        session['user_email'] = str(user.email)
    except Exception as e:
        # In case of an error, clear the session to avoid inconsistent state.
        session.clear()


def user_exists(email: str) -> Optional[User]:
    """
    Checks if a user exists by email.
    
    Args:
        email (str): The user's email.
        
    Returns:
        Optional[User]: The user object if found, otherwise None.
    """
    return User.query.filter_by(email=email).first()


def temp_exists(email: str) -> Optional[TempUser]:
    """
    Checks if a temporary user exists by email.
    
    Args:
        email (str): The user's email.
        
    Returns:
        Optional[TempUser]: The temporary user if found, otherwise None.
    """
    return TempUser.query.filter_by(email=email).first()


def generate_reset_token(user: User) -> str:
    """
    Generates a password reset token valid for 1 hour.
    
    Args:
        user (User): The user for whom the reset token is generated.
        
    Returns:
        str: The generated reset token.
    """
    token = secrets.token_urlsafe()
    expires_at = datetime.utcnow() + timedelta(hours=1)
    reset_token = PasswordResetToken(user_id=user.user_id, token=token, expires_at=expires_at)
    try:
        db.session.add(reset_token)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e
    return token


def validate_reset_token(token: str) -> Optional[User]:
    """
    Validates the reset token and returns the associated user if valid.
    
    Args:
        token (str): The reset token.
        
    Returns:
        Optional[User]: The user if the token is valid, otherwise None.
    """
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    if reset_token and reset_token.expires_at > datetime.utcnow():
        return reset_token.user
    return None


def send_email(first_name: str, email: str, verification_token: str) -> None:
    """
    Sends a verification email to the user.
    
    Args:
        first_name (str): The user's first name.
        email (str): The user's email.
        verification_token (str): The token used to verify the email.
    """
    verification_link = url_for('auth.verify_email', token=verification_token, _external=True)
    subject, html_body = create_welcome_email(first_name, verification_link)
    mail_server(email, subject, html_body)


def create_password_reset_email(reset_link: str) -> Tuple[str, str]:
    """
    Creates the content for a password reset email.
    
    Args:
        reset_link (str): The link for password reset.
        
    Returns:
        Tuple[str, str]: The subject and HTML body of the email.
    """
    subject = "Password Reset Request"
    html_body = render_template("emails/password_reset.html", reset_link=reset_link)
    return subject, html_body


def create_welcome_email(first_name: str, verification_link: str) -> Tuple[str, str]:
    """
    Creates the content for a welcome email.
    
    Args:
        first_name (str): The user's first name.
        verification_link (str): The link for email verification.
        
    Returns:
        Tuple[str, str]: The subject and HTML body of the welcome email.
    """
    subject = "Welcome to Acumen Intelligence - Verify Your Email"
    html_body = render_template("emails/welcome.html", first_name=first_name, verification_link=verification_link)
    return subject, html_body


def reset_password(user: User, new_password: str) -> None:
    """
    Resets the user's password and removes any existing password reset tokens.
    
    Args:
        user (User): The user whose password will be reset.
        new_password (str): The new plain-text password.
    """
    user.password = generate_password_hash(new_password)
    try:
        PasswordResetToken.query.filter_by(user_id=user.user_id).delete()
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e
