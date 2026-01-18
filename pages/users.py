from datetime import datetime
from pages.models import db,User
from pages.loginsignup import reset_password
from flask import jsonify
import re

def reset_verification_attempts(user):
    current_date = datetime.utcnow()    
    if user.last_reset is None or user.last_reset.month != current_date.month or user.last_reset.day != current_date.day:
        user.verification_attempts = 0
        user.last_reset = current_date
        db.session.commit()

def get_verification_attemps(user):
    attemps_left = 50 - user.verification_attempts
    return  attemps_left#

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