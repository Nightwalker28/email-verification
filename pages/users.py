from datetime import datetime,timedelta
from pages.models import db,User,Summary,searched_email_user,SearchedEMail
from pages.loginsignup import reset_password
from flask import jsonify
import re
from sqlalchemy import func

def check_user_access(user, route):
    if not user.is_paid:
        if route == 'verify_email_address':
            if user.verification_attempts >= 50:
                return jsonify({'error': 'Free plan users can only perform 50 verifications per month.'}), 403
        elif route == 'listview':
            return jsonify({'error': 'Free plan users cannot access this feature.'}), 403
        elif route == 'force_verify_email_address':
            return jsonify({'error': 'Free plan users cannot access this feature.'}), 403

def reset_verification_attempts(user):
    current_date = datetime.utcnow()    
    if user.last_reset is None or user.last_reset.month != current_date.month or user.last_reset.day != current_date.day:
        user.verification_attempts = 0
        user.last_reset = current_date
        db.session.commit()

def get_verification_attemps(user):
    attemps_left = 50 - user.verification_attempts
    return  attemps_left

def validate_password(password):
    return (len(password) >= 8 and 
            re.search(r'[A-Z]', password) and 
            re.search(r'[a-z]', password) and 
            re.search(r'\d', password) and 
            re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),

def get_user_profile(user):
    # Query the database to get the user's profile details
    if user:
        return {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email
        }
    return None

def update_user_profile(user_id, first_name, last_name, email, password=None):
    user = User.query.filter_by(user_id=user_id).first()  # Use the correct primary key field
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    # Update user fields
    user.first_name = first_name
    user.last_name = last_name
    # Email update handling
    if email and email != user.email:
        # If the user is a Google account, they must provide a password to change their email
        if user.is_google:
            if not password:  # Check if password is provided
                return jsonify({'success': False, 'message': 'Password is required to change email for Google accounts.'}), 401
        # Update email and set is_google to False after a successful check
        user.email = email
        user.is_google = False
    # If a password is provided, update it
    if password:
        reset_password(user, password)  # Assuming reset_password handles hashing
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated successfully.'}), 200
    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        print(f"Error updating user: {e}")
        return jsonify({'success': False, 'message': 'Error updating profile.'}), 500
    
def get_user_summary(user_id):
    # Summary for uploaded lists
    total_lists = Summary.query.filter_by(user_id=user_id).count()
    total_emails_checked = db.session.query(func.sum(Summary.total_emails)).filter(Summary.user_id == user_id).scalar() or 0
    total_verified = db.session.query(func.sum(Summary.valid_emails)).filter(Summary.user_id == user_id).scalar() or 0
    total_risky = db.session.query(func.sum(Summary.risky_emails)).filter(Summary.user_id == user_id).scalar() or 0
    total_invalid = db.session.query(func.sum(Summary.invalid_emails)).filter(Summary.user_id == user_id).scalar() or 0
    total_unknown = db.session.query(func.sum(Summary.unknown_emails)).filter(Summary.user_id == user_id).scalar() or 0
    list_summary = {
        'total_lists': total_lists,
        'total_emails_checked': total_emails_checked,
        'total_verified': total_verified,
        'total_risky': total_risky,
        'total_invalid': total_invalid,
        'total_unknown': total_unknown
    }
        # Summary for single email verifications in the last 30 days
    now = datetime.utcnow()
    thirty_days_ago = now - timedelta(days=30)

    # Query to get the email ids and their respective search counts for the user in the last 30 days
    recent_email_entries = db.session.query(searched_email_user.c.email_id, searched_email_user.c.search_count) \
        .filter(searched_email_user.c.user_id == user_id) \
        .filter(searched_email_user.c.timestamp >= thirty_days_ago) \
        .all()

    # Initialize counts for recent email verification results
    recent_verified = 0
    recent_invalid = 0
    recent_risky = 0
    recent_unknown = 0
    total_recent_emails_checked = sum(entry[1] for entry in recent_email_entries)  # Sum up the search counts for total emails checked

    # If there are no emails searched in the last 30 days, return only the list summary
    if not recent_email_entries:
        return list_summary, None  # No recent email summary available

    # Flatten the list of tuples to get a list of email_ids
    recent_email_ids = [email_id for (email_id, _) in recent_email_entries]

    # Query the SearchedEMail table to get the results for these email ids
    results = db.session.query(SearchedEMail).filter(SearchedEMail.email_id.in_(recent_email_ids)).all()

    # Summarize the results for recent verifications
    for email in results:
        # Find the corresponding search count for this email
        search_count = next((entry[1] for entry in recent_email_entries if entry[0] == email.email_id), 0)

        if email.result == 'Email exists':
            recent_verified += search_count  # Increment by search_count
        elif email.result == 'Email does not exist':
            recent_invalid += search_count  # Increment by search_count
        elif email.result == 'Risky':
            recent_risky += search_count  # Increment by search_count
        else:
            recent_unknown += search_count  # Increment by search_count

    recent_summary = {
        'recent_verified': recent_verified,
        'recent_invalid': recent_invalid,
        'recent_risky': recent_risky,
        'recent_unknown': recent_unknown,
        'total_recent_emails_checked': total_recent_emails_checked  # Include total checked emails
    }
    return list_summary, recent_summary

