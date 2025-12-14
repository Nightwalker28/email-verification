from datetime import datetime
from pages.models import db

def reset_verification_attempts(user):
    current_date = datetime.utcnow()    
    if user.last_reset is None or user.last_reset.month != current_date.month or user.last_reset.day != current_date.day:
        user.verification_attempts = 0
        user.last_reset = current_date
        db.session.commit()


def get_verification_attemps(user):
    attemps_left = 50 - user.verification_attempts
    return  attemps_left