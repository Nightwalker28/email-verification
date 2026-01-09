# c:\Users\maadm\Documents\Work\email-verification\pages\loginsignup.py
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

from flask import render_template, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
# Assuming config holds the Flask app instance or a way to access its config
from flask import current_app 

from pages.models import User, db, PasswordResetToken, Organization, TempUser
from config import mail_server, FREE_EMAIL_PROVIDERS, disposable

def _get_domain(email: str) -> str:
    """Extracts the lowercased domain from an email address."""
    try:
        return email.split('@')[-1].lower()
    except IndexError:
        # Handle cases where email might not have '@'
        return ""

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
    domain = _get_domain(email)
    return domain in FREE_EMAIL_PROVIDERS


def is_disposable_email(email: str) -> bool:
    """
    Determines if the email address is from a disposable provider.

    Args:
        email (str): The email address.

    Returns:
        bool: True if the email is disposable, False otherwise.
    """
    domain = _get_domain(email)
    return domain in disposable


def can_create_user(email: str) -> bool:
    """
    Checks if a new user can be created based on the user count for the domain.

    Args:
        email (str): The user's email.

    Returns:
        bool: True if the domain has not reached its limit, False otherwise.
    """
    domain = _get_domain(email)
    # Consider making the limit configurable
    user_limit = current_app.config.get('ORGANIZATION_USER_LIMIT', 5) 
    organization = Organization.query.filter_by(domain=domain).first()
    # Check if organization exists before accessing user_count
    if organization and organization.user_count >= user_limit:
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
    # Added check for empty domain from _get_domain helper
    if not _get_domain(email): 
        return False
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
    # Ensure user object and password attribute exist before checking
    if not user or not user.password:
        return False
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
        # Consider logging the error here
        current_app.logger.error(f"Error setting session for user {user.email}: {e}")
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
    return User.query.filter(User.email.ilike(email)).first() # Case-insensitive check


def temp_exists(email: str) -> Optional[TempUser]:
    """
    Checks if a temporary user exists by email.

    Args:
        email (str): The user's email.

    Returns:
        Optional[TempUser]: The temporary user if found, otherwise None.
    """
    return TempUser.query.filter(TempUser.email.ilike(email)).first() # Case-insensitive check


def generate_reset_token(user: User) -> str:
    """
    Generates a password reset token valid for 1 hour.

    Args:
        user (User): The user for whom the reset token is generated.

    Returns:
        str: The generated reset token.
    """
    token = secrets.token_urlsafe()
    # Consider making token expiry configurable
    token_expiry_hours = current_app.config.get('RESET_TOKEN_EXPIRY_HOURS', 1)
    expires_at = datetime.utcnow() + timedelta(hours=token_expiry_hours)
    reset_token = PasswordResetToken(user_id=user.user_id, token=token, expires_at=expires_at)
    try:
        db.session.add(reset_token)
        db.session.commit()
    except Exception as e: # Consider catching specific DB errors (e.g., SQLAlchemyError)
        db.session.rollback()
        current_app.logger.error(f"Error generating reset token for user {user.email}: {e}")
        raise e # Re-raise the exception after logging
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
    # Combine checks for existence and expiry
    if reset_token and reset_token.expires_at > datetime.utcnow():
        # Eager load the user to potentially avoid a separate query later
        # from sqlalchemy.orm import joinedload
        # reset_token = PasswordResetToken.query.options(joinedload(PasswordResetToken.user)).filter_by(token=token).first()
        return reset_token.user 
    # Optionally: Delete expired tokens here or in a separate cleanup task
    # if reset_token: 
    #     db.session.delete(reset_token)
    #     db.session.commit()
    return None


def send_email(first_name: str, email: str, verification_token: str) -> None:
    """
    Sends a verification email to the user.

    Args:
        first_name (str): The user's first name.
        email (str): The user's email.
        verification_token (str): The token used to verify the email.
    """
    # Ensure url_for generates an absolute URL for emails
    verification_link = url_for('auth.verify_email', token=verification_token, _external=True)
    subject, html_body = create_welcome_email(first_name, verification_link)
    try:
        mail_server(email, subject, html_body)
    except Exception as e:
        # Log error if email sending fails
        current_app.logger.error(f"Failed to send verification email to {email}: {e}")
        # Decide if you need to raise the error or handle it silently


def create_password_reset_email(reset_link: str) -> Tuple[str, str]:
    """
    Creates the content for a password reset email.

    Args:
        reset_link (str): The link for password reset.

    Returns:
        Tuple[str, str]: The subject and HTML body of the email.
    """
    subject = "Password Reset Request"
    # Pass necessary variables to the template context
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
     # Pass necessary variables to the template context
    html_body = render_template("emails/welcome.html", first_name=first_name, verification_link=verification_link)
    return subject, html_body


def reset_password(user: User, new_password: str) -> None:
    """
    Resets the user's password and removes any existing password reset tokens for that user.

    Args:
        user (User): The user whose password will be reset.
        new_password (str): The new plain-text password.
    """
    if not user:
         # Or raise an error
        current_app.logger.error("Attempted to reset password for a non-existent user.")
        return 

    user.password = generate_password_hash(new_password)
    try:
        # Delete only tokens associated with this specific user
        PasswordResetToken.query.filter_by(user_id=user.user_id).delete()
        # Add the user object to the session if it's detached or modified
        db.session.add(user) 
        db.session.commit()
    except Exception as e: # Consider catching specific DB errors
        db.session.rollback()
        current_app.logger.error(f"Error resetting password or deleting tokens for user {user.email}: {e}")
        raise e # Re-raise the exception after logging
