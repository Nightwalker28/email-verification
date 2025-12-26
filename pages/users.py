from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any

from flask import redirect, session
from sqlalchemy import func

from pages.models import db, User, Summary, searched_email_user, SearchedEmail
from pages.loginsignup import reset_password
from config import error_response, success_response


def get_user_id(user=None):
    """
    Retrieve a user ID from either a user object (or directly a user ID)
    or fall back to the Flask session if available.
    """
    if user:
        # If the passed user is an object with a user_id attribute, use that; otherwise assume it's already an ID.
        return getattr(user, "user_id", user)
    try:
        return session.get("user")
    except RuntimeError:
        # This exception is raised if there is no active request context.
        return None

def check_user_access(user: User, route: str) -> Optional[Any]:
    """
    Checks whether the given user can access the specified route.
    If the user is unpaid and exceeds verification limits, returns a redirect to '/pricing'.
    Otherwise, returns None.
    """
    if not user.is_paid:
        if route == 'verify_email_address' and user.verification_attempts >= 50:
            return redirect('/pricing')
        elif route in ('listview', 'force_verify_email_address'):
            return redirect('/pricing')
    return None


def reset_verification_attempts(user: User) -> None:
    """
    Resets the user's verification attempts if the current day is different from the last reset day.
    """
    current_date = datetime.utcnow()
    if user.last_reset is None or user.last_reset.date() != current_date.date():
        user.verification_attempts = 0
        user.last_reset = current_date
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e


def get_verification_attempts(user: User) -> int:
    """
    Returns the number of verification attempts remaining (out of 50).
    """
    return max(50 - user.verification_attempts, 0)


def get_user_profile(user: Optional[User]) -> Optional[Dict[str, Any]]:
    """
    Retrieves the user's profile details.
    """
    if user:
        return {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email
        }
    return None


def update_user_profile(user_id: int, first_name: str, last_name: str,
                        password: Optional[str] = None) -> Tuple[Dict[str, Any], int]:
    """
    Updates the user's profile with new first and last name, and optionally updates the password.
    Returns a tuple of (response, status_code).
    """
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return error_response({'success': False, 'message': 'User not found.'}), 404

    user.first_name = first_name
    user.last_name = last_name

    if password:
        reset_password(user, password)

    try:
        db.session.commit()
        return success_response({'success': True, 'message': 'Profile updated successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return error_response({'success': False, 'message': 'Error updating profile.'}), 500


def get_user_summary(user_id: int) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Generates a summary for the user's activity.
    The summary includes details on uploaded lists and recent email verifications (within the last 30 days).
    Returns a tuple (list_summary, recent_summary). If no recent activity is found, recent_summary is None.
    """
    # Consolidate list summary queries
    total_lists = Summary.query.filter_by(user_id=user_id).count()
    total_emails_checked = db.session.query(func.sum(Summary.total_emails)) \
        .filter(Summary.user_id == user_id).scalar() or 0
    total_verified = db.session.query(func.sum(Summary.valid_emails)) \
        .filter(Summary.user_id == user_id).scalar() or 0
    total_risky = db.session.query(func.sum(Summary.risky_emails)) \
        .filter(Summary.user_id == user_id).scalar() or 0
    total_invalid = db.session.query(func.sum(Summary.invalid_emails)) \
        .filter(Summary.user_id == user_id).scalar() or 0
    total_unknown = db.session.query(func.sum(Summary.unknown_emails)) \
        .filter(Summary.user_id == user_id).scalar() or 0

    list_summary = {
        'total_lists': total_lists,
        'total_emails_checked': total_emails_checked,
        'total_verified': total_verified,
        'total_risky': total_risky,
        'total_invalid': total_invalid,
        'total_unknown': total_unknown,
    }

    # Recent email verifications in the last 30 days
    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)
    recent_email_entries = (
        db.session.query(searched_email_user.c.email_id, searched_email_user.c.search_count)
        .filter(searched_email_user.c.user_id == user_id)
        .filter(searched_email_user.c.timestamp >= thirty_days_ago)
        .all()
    )

    total_recent_emails_checked = sum(entry[1] for entry in recent_email_entries)
    if not recent_email_entries:
        return list_summary, None

    recent_email_ids = [entry[0] for entry in recent_email_entries]
    results = db.session.query(SearchedEmail).filter(SearchedEmail.email_id.in_(recent_email_ids)).all()

    recent_verified = recent_invalid = recent_risky = recent_unknown = 0
    for email in results:
        search_count = next((entry[1] for entry in recent_email_entries if entry[0] == email.email_id), 0)
        if email.result == 'Email exists':
            recent_verified += search_count
        elif email.result == 'Email does not exist':
            recent_invalid += search_count
        elif email.result == 'Risky':
            recent_risky += search_count
        else:
            recent_unknown += search_count

    recent_summary = {
        'recent_verified': recent_verified,
        'recent_invalid': recent_invalid,
        'recent_risky': recent_risky,
        'recent_unknown': recent_unknown,
        'total_recent_emails_checked': total_recent_emails_checked,
    }

    return list_summary, recent_summary
