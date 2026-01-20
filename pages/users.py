from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, Union
from flask import redirect, session, current_app, Response, url_for 
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from pages.models import db, User, Summary, searched_email_user, SearchedEmail
from pages.loginsignup import reset_password 
from config import error_response, success_response, logger 

# --- Constants for Configuration Keys ---
VERIFICATION_ATTEMPTS_LIMIT_KEY = 'FREE_USER_VERIFICATION_LIMIT'
DEFAULT_VERIFICATION_ATTEMPTS_LIMIT = 50

# --- Helper Functions ---

def get_user_id(user: Optional[Union[User, int, str]] = None) -> Optional[str]:
    """
    Retrieve a user ID (as string) from a User object, an ID, or the Flask session.

    Args:
        user: A User object, user ID (int or str), or None.

    Returns:
        The user ID as a string, or None if not found.
    """
    user_id_val: Optional[Union[int, str]] = None
    if user:
        user_id_val = getattr(user, "user_id", user)
    else:
        try:
            user_id_val = session.get("user")
        except RuntimeError:
            logger.warning("get_user_id called without active Flask request context and no user provided.")
            return None
            
    return str(user_id_val) if user_id_val is not None else None


def check_user_access(user: User, route_name: str) -> Optional[Response]:
    """
    Checks if the user has access based on payment status and usage limits.

    Args:
        user: The User object.
        route_name: A string identifying the route/action being accessed.

    Returns:
        A Flask Response object (redirect to pricing) if access is denied, 
        otherwise None.
    """
    if user.is_paid:
        return None 
    limit = current_app.config.get(VERIFICATION_ATTEMPTS_LIMIT_KEY, DEFAULT_VERIFICATION_ATTEMPTS_LIMIT)
    route_rules = {
        'verify_email_address': {'limit_check': True},
        'list_view': {'deny_free': True},
        'force_verify_email_address': {'deny_free': True},
        'upload_file': {'deny_free': True},
    }

    rule = route_rules.get(route_name)

    if not rule:
        return None

    if rule.get('deny_free'):
        logger.info(f"Access denied for free user {user.email} to route '{route_name}'. Redirecting to pricing.")
        return redirect(url_for('main.pricing'))

    if rule.get('limit_check') and user.verification_attempts >= limit:
        logger.info(f"Verification limit ({limit}) reached for free user {user.email}. Redirecting to pricing.")
        return redirect(url_for('main.pricing'))

    return None


def reset_verification_attempts(user: User) -> bool:
    """
    Resets the user's verification attempts if the current day is different 
    from the last reset day. Commits the change.

    Args:
        user: The User object.

    Returns:
        True if attempts were reset or didn't need resetting, False on DB error.
    """

    current_date = datetime.utcnow().date()
    last_reset_date = user.last_reset.date() if user.last_reset else None

    if last_reset_date != current_date:
        logger.info(f"Resetting verification attempts for user {user.email} (Last reset: {last_reset_date}, Current: {current_date})")
        user.verification_attempts = 0
        user.last_reset = datetime.utcnow()
        try:
            db.session.add(user)
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error resetting verification attempts for user {user.email}: {e}", exc_info=True)
            return False
    return True


def get_verification_attempts(user: User) -> int:
    """
    Returns the number of verification attempts remaining for the user.

    Args:
        user: The User object.

    Returns:
        Number of attempts remaining.
    """
    if user.is_paid:
        return float('inf') 

    limit = current_app.config.get(VERIFICATION_ATTEMPTS_LIMIT_KEY, DEFAULT_VERIFICATION_ATTEMPTS_LIMIT)
    remaining = max(limit - user.verification_attempts, 0)
    return remaining


def get_user_profile(user: User) -> Dict[str, Any]:
    """
    Retrieves the user's profile details needed for display.

    Args:
        user: The User object.

    Returns:
        A dictionary containing profile information.
    """
    return {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'subscription': user.is_paid, 
    }


def update_user_profile(user_id: Union[int, str], first_name: str, last_name: str,
                        password: Optional[str] = None) -> Response:
    """
    Updates the user's profile (name) and optionally resets the password.

    Args:
        user_id: The ID of the user to update.
        first_name: The new first name.
        last_name: The new last name.
        password: The new password (optional). If provided, it will be hashed and set.

    Returns:
        A Flask Response object (success or error).
    """
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"Attempt to update profile for non-existent user ID: {user_id}")
        return error_response('User not found.', 404) 

    if not first_name or not last_name:
         return error_response('First and last names cannot be empty.', 400)
         
    if password:
        if len(password) < 8: 
            return error_response('Password must be at least 8 characters long.', 400)

    try:
        user.first_name = first_name.strip()
        user.last_name = last_name.strip()
        db.session.add(user)

        db.session.commit() 
        logger.info(f"Updated name for user {user.email}")

        if password:
            reset_password(user, password) 
            logger.info(f"Password updated for user {user.email}")

        return success_response('Profile updated successfully.', 200)

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error updating profile for user {user.email}: {e}", exc_info=True)
        return error_response('Error updating profile due to database issue.', 500)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error updating profile for user {user.email}: {e}", exc_info=True)
        return error_response('An unexpected error occurred while updating profile.', 500)


def get_user_summary(user_id: Union[int, str]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Generates summaries of the user's list uploads and recent individual verifications.

    Args:
        user_id: The ID of the user.

    Returns:
        A tuple containing:
            - list_summary: Dictionary summarizing all list uploads.
            - recent_summary: Dictionary summarizing individual verifications 
                              in the last 30 days, or None if no recent activity.
    """

    list_summary_data = db.session.query(
        func.count(Summary.id).label('total_lists'),
        func.sum(Summary.total_emails).label('total_emails_checked'),
        func.sum(Summary.valid_emails).label('total_verified'),
        func.sum(Summary.risky_emails).label('total_risky'),
        func.sum(Summary.invalid_emails).label('total_invalid'),
        func.sum(Summary.unknown_emails).label('total_unknown')
    ).filter(Summary.user_id == user_id).first()

    list_summary = {
        'total_lists': list_summary_data.total_lists or 0,
        'total_emails_checked': list_summary_data.total_emails_checked or 0,
        'total_verified': list_summary_data.total_verified or 0,
        'total_risky': list_summary_data.total_risky or 0,
        'total_invalid': list_summary_data.total_invalid or 0,
        'total_unknown': list_summary_data.total_unknown or 0,
    }

    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)

    recent_verifications = db.session.query(
        SearchedEmail.result,
        func.sum(searched_email_user.c.search_count).label('total_count')
    ).join(
        searched_email_user, SearchedEmail.email_id == searched_email_user.c.email_id
    ).filter(
        searched_email_user.c.user_id == user_id,
        searched_email_user.c.timestamp >= thirty_days_ago
    ).group_by(
        SearchedEmail.result
    ).all()

    if not recent_verifications:
        return list_summary, None

    recent_summary = {
        'recent_verified': 0,
        'recent_invalid': 0,
        'recent_risky': 0,
        'recent_unknown': 0,
        'total_recent_emails_checked': 0,
    }
    for result, count in recent_verifications:
        count = count or 0
        recent_summary['total_recent_emails_checked'] += count
        if result == 'Email exists':
            recent_summary['recent_verified'] += count
        elif result == 'Invalid':
            recent_summary['recent_invalid'] += count
        elif result == 'Risky':
            recent_summary['recent_risky'] += count
        else:
            recent_summary['recent_unknown'] += count

    return list_summary, recent_summary

