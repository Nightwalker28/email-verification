from datetime import datetime
from typing import Optional, List
from sqlalchemy import ForeignKey, Index
from flask import session
from sqlalchemy.orm import aliased, relationship 
from config import db, logger

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

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

    def __repr__(self) -> str:
        return f'<User {self.email}>'


# Association table for many-to-many relationship between users and searched emails.
searched_email_user = db.Table(
    'searched_email_user',
    db.Column('user_id', db.Integer, db.ForeignKey('users.user_id'), primary_key=True),
    db.Column('email_id', db.Integer, db.ForeignKey('searched_emails.email_id'), primary_key=True),
    db.Column('timestamp', db.DateTime, default=datetime.utcnow),
    db.Column('search_count', db.Integer, default=1),
)


class SearchedEmail(db.Model):
    __tablename__ = 'searched_emails'
    email_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    result = db.Column(db.String(50))
    provider = db.Column(db.String(50))
    role_based = db.Column(db.Boolean)
    accept_all = db.Column(db.Boolean)
    full_inbox = db.Column(db.Boolean)
    disposable = db.Column(db.Boolean)

    def __repr__(self) -> str:
        return f'<SearchedEmail {self.email}>'


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))

    def __repr__(self) -> str:
        return f'<PasswordResetToken {self.token} for User {self.user_id}>'


class UserUpload(db.Model):
    __tablename__ = 'user_uploads'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    unique_filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    verified_filepath = db.Column(db.String(255), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = relationship('User', backref=db.backref('uploads', lazy=True))
    def __repr__(self) -> str:
        return f'<UserUpload {self.unique_filename} for user {self.user_id}>'


class Summary(db.Model):
    __tablename__ = 'summary'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, index=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('user_uploads.id'), nullable=False, unique=True, index=True)
    list_name = db.Column(db.String(120), nullable=False)
    total_emails = db.Column(db.Integer, nullable=False)
    valid_emails = db.Column(db.Integer, default=0)
    risky_emails = db.Column(db.Integer, default=0)
    invalid_emails = db.Column(db.Integer, default=0)
    unknown_emails = db.Column(db.Integer, default=0)
    upload = relationship('UserUpload', backref=db.backref('summary', uselist=False, lazy='joined')) # Use joined loading if often needed together
    user = relationship('User', backref=db.backref('summaries', lazy=True))
    def __repr__(self) -> str:
        return f'<Summary {self.list_name} for user {self.user_id}>'


class TempUser(db.Model):
    __tablename__ = 'temp_users'
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)  # hashed password
    verification_token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_google = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f'<TempUser {self.email}>'


class Organization(db.Model):
    __tablename__ = 'orgs'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, unique=True)
    user_count = db.Column(db.Integer, default=0)

    def increment_count(self) -> None:
        self.user_count += 1

    def __repr__(self) -> str:
        return f'<Organization {self.domain} ({self.user_count} users)>'


class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    api_key = db.Column(db.String(512), unique=True)
    name = db.Column(db.String(128), nullable=False)

    user = db.relationship('User', backref=db.backref('api_keys', lazy='dynamic'))

    def __repr__(self) -> str:
        return f'<ApiKey {self.name} for User {self.user_id}>'


# ------------------------------------------------------------------------------
# Helper Functions & Query Utilities
# ------------------------------------------------------------------------------

# Use an alias for the association table to avoid conflicts in queries.
searched_email_user_alias = aliased(searched_email_user)


def get_last_checked_emails(limit: int = 10) -> Optional[List[SearchedEmail]]:
    """
    Retrieves the last 'limit' checked emails for the currently logged-in user.
    Returns None if no user is in session.
    """
    if 'user' not in session:
        return None
    user_id = session['user']
    last_checked_emails = (
        db.session.query(SearchedEmail)
        .join(searched_email_user_alias, SearchedEmail.email_id == searched_email_user_alias.c.email_id)
        .filter(searched_email_user_alias.c.user_id == user_id)
        .order_by(searched_email_user_alias.c.timestamp.desc())
        .limit(limit)
        .all()
    )
    return last_checked_emails


def get_or_create_searched_email(email: str, verification_result: str) -> SearchedEmail:
    """
    Retrieves a SearchedEmail by email address or creates a new one with the given verification result.
    """
    searched_email_entry = SearchedEmail.query.filter_by(email=email).first()
    if not searched_email_entry:
        searched_email_entry = SearchedEmail(email=email, result=verification_result)
        try:
            db.session.add(searched_email_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating searched email {email}: {e}")
            raise
    return searched_email_entry


def add_verified_email_for_user(user_id: int, email_id: int) -> None:
    """
    Adds or updates a record linking a user to a searched email.
    Updates the timestamp if the record already exists.
    """
    existing_entry = db.session.query(searched_email_user).filter_by(user_id=user_id, email_id=email_id).first()
    try:
        if existing_entry:
            db.session.execute(
                searched_email_user.update()
                .where(searched_email_user.c.user_id == user_id)
                .where(searched_email_user.c.email_id == email_id)
                .values(timestamp=datetime.utcnow())
            )
        else:
            new_entry = searched_email_user.insert().values(
                user_id=user_id,
                email_id=email_id,
                timestamp=datetime.utcnow()
            )
            db.session.execute(new_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating verified email for user {user_id} and email {email_id}: {e}")
        raise


def create_temp_user(first_name: str, last_name: str, email: str, hashed_password: str,
                     verification_token: str, is_google: bool = False) -> TempUser:
    """
    Creates and persists a TempUser with a verification token.
    """
    temp_user = TempUser(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        verification_token=verification_token,
        is_google=is_google
    )
    try:
        db.session.add(temp_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating temporary user {email}: {e}")
        raise
    return temp_user


def create_user(first_name: str, last_name: str, email: str, password: str, is_google: bool) -> Optional[User]:
    """
    Creates a new user after ensuring the associated organization has not exceeded its limit.
    Returns the new user on success, or None if the domain limit has been reached.
    """
    domain = email.split('@')[-1].lower()
    organization = Organization.query.filter_by(domain=domain).first()
    try:
        if organization:
            if organization.user_count >= 5:
                return None  # Limit reached; cannot create user
            organization.increment_count()
        else:
            organization = Organization(domain=domain, user_count=1)
            db.session.add(organization)

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            is_google=is_google,
            is_paid=False
        )
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user {email}: {e}")
        raise
    return new_user


def get_or_create_google_user(email: str, first_name: str, last_name: str) -> User:
    """
    Retrieves or creates a Google-authenticated user.
    """
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
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating Google user {email}: {e}")
        raise
    return new_user
