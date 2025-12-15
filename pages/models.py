from config import db
from datetime import datetime
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import aliased
from flask import session

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_google = db.Column(db.Boolean, default=False)
    is_paid = db.Column(db.Boolean, default=False)
    verification_attempts = db.Column(db.Integer, default=0)
    last_reset = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self):
        return f'<User {self.email}>'

searched_email_user = db.Table('searched_email_user',
    db.Column('user_id', db.Integer, db.ForeignKey('users.user_id'), primary_key=True),
    db.Column('email_id', db.Integer, db.ForeignKey('searched_emails.email_id'), primary_key=True),
    db.Column('timestamp', db.DateTime, default=datetime.utcnow),
    db.Column('search_count', db.Integer, default=1),
)
   
class SearchedEMail(db.Model):
    __tablename__ = 'searched_emails'
    email_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    result = db.Column(db.String(50))
    provider = db.Column(db.String(50))
    role_based = db.Column(db.Boolean)
    accept_all = db.Column(db.Boolean)
    full_inbox = db.Column(db.Boolean)
    disposable= db.Column(db.Boolean)

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))
    def __repr__(self):
        return f'<PasswordResetToken {self.token} for User {self.user_id}>'

class UserUpload(db.Model):
    __tablename__ = 'user_uploads'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)  # Store original filename
    unique_filename = db.Column(db.String(255), nullable=False)  # Unique filename
    filepath = db.Column(db.String(255), nullable=False)  # Path to the file
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class Summary(db.Model):
    __tablename__ = 'summary'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    list_name = db.Column(db.String(120), nullable=False)
    total_emails = db.Column(db.Integer, nullable=False)
    valid_emails = db.Column(db.Integer, default=0)
    risky_emails = db.Column(db.Integer, default=0)
    invalid_emails = db.Column(db.Integer, default=0)
    unknown_emails = db.Column(db.Integer, default=0)

class TempUser(db.Model):
    __tablename__ = 'temp_users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Store hashed passwords
    verification_token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_google = db.Column(db.Boolean, default=False)

class Organizations(db.Model):
    __tablename__ = 'orgs'
    
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, unique=True)
    user_count = db.Column(db.Integer, default=0)

    def increment_count(self):
        self.user_count += 1

__table_args__ = (
        UniqueConstraint('email', name='uq_searched_emails_email'),
    )

# Alias for the association table to use in the query
searched_email_user_alias = aliased(searched_email_user)

# Get the last 10 emails checked by the user, ordered by the timestamp in the association table
def get_last_checked_emails(limit=10):
    if 'user' not in session:
        return None  # Or handle the case where the user is not logged in.
    user_id = session['user']
    last_checked_emails = db.session.query(SearchedEMail) \
        .join(searched_email_user_alias, SearchedEMail.email_id == searched_email_user_alias.c.email_id) \
        .filter(searched_email_user_alias.c.user_id == user_id) \
        .order_by(searched_email_user_alias.c.timestamp.desc()) \
        .limit(limit).all()  
    return last_checked_emails

def get_or_create_searched_email(email, verification_result):
    searched_email_entry = SearchedEMail.query.filter_by(email=email).first()
    if not searched_email_entry:
        searched_email_entry = SearchedEMail(email=email, result=verification_result)
        db.session.add(searched_email_entry)
        db.session.commit()
    return searched_email_entry

def add_verified_email_for_user(user_id, email_id):
    existing_entry = db.session.query(searched_email_user).filter_by(user_id=user_id, email_id=email_id).first()
    if existing_entry:
        # Update the timestamp to the current time
        db.session.execute(
            searched_email_user.update().
            where(searched_email_user.c.user_id == user_id).
            where(searched_email_user.c.email_id == email_id).
            values(timestamp=datetime.utcnow())
        )
        db.session.commit()
    else:
        # Create a new entry if it does not exist
        new_entry = searched_email_user.insert().values(user_id=user_id, email_id=email_id, timestamp=datetime.utcnow())
        db.session.execute(new_entry)
        db.session.commit()

def create_temp_user(first_name, last_name, email, hashed_password, verification_token, is_google=False):
    """
    Creates and saves a TempUser with a verification token.
    """
    temp_user = TempUser(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        verification_token=verification_token,
        is_google=is_google
    )
    db.session.add(temp_user)
    db.session.commit()
    return temp_user

def create_user(first_name, last_name, email,password,is_google):
    domain = email.split('@')[-1]
    # Check if the domain already exists
    domain_count = Organizations.query.filter_by(domain=domain).first()
    if domain_count:
        # Increment the counter if the domain exists
        if domain_count.user_count >= 5:
            return None  # Limit reached, cannot create user
        domain_count.increment_count()  # Increment the count
    else:
        # Create a new entry for the domain with count set to 1
        new_domain_count = Organizations(domain=domain, user_count=1)
        db.session.add(new_domain_count)
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=password,
        is_google=is_google,
        is_paid=False)
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
        is_paid=False)
    db.session.add(new_user)
    db.session.commit()
    return new_user