import smtplib
import pandas as pd
import re
import dns.resolver
import numpy as np
from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for, flash
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from sqlalchemy.orm import aliased
import os
import logging
from dotenv import load_dotenv
import socket
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from logging.handlers import RotatingFileHandler
import chardet
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash

# Load environment variables
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/emailtool'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

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
    db.Column('timestamp', db.DateTime, default=datetime.utcnow)  # New timestamp column
)

class SearchedEMail(db.Model):
    __tablename__ = 'searched_emails'

    email_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    result = db.Column(db.String(50))  # Column for the result of the email verification
    provider = db.Column(db.String(50))  # Column for the email provider
    role_based = db.Column(db.Boolean)  # Column indicating if it's role-based
    accept_all = db.Column(db.Boolean)  # Column indicating if the provider accepts all emails
    full_inbox = db.Column(db.Boolean)    


# Configure OAuth
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Configure file upload
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit

# Setup logging with rotation
handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)
app.logger.handlers = []
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)


def detect_file_properties(filepath):
    """Detect the encoding and delimiter of the CSV file."""
    with open(filepath, 'rb') as file:
        raw_data = file.read(10000)
        encoding = chardet.detect(raw_data)['encoding']
    with open(filepath, 'r', encoding=encoding) as file:
        sample = file.read(1024)
        delimiter = next((d for d in [',', ';', '\t', '|'] if d in sample), ',')
    return encoding, delimiter

def detect_email_column(df):
    """Detects the column containing email addresses."""
    logger.info('Detecting email column...')
    for column in df.columns:
        # Check if the column name is related to email
        if re.search(r'email|e-mail|email address', column, re.IGNORECASE):
            logger.info(f'Email column detected: {column}')
            return column
    logger.warning('No email column found')
    return None

def sanitize_email(email):
    """Sanitize and validate email addresses."""
    if not isinstance(email, str):
        logger.warning(f'Invalid email format: {email}')
        return None
    
    sanitized_email = email.strip().lower()
    
    # Simple email validation check (you may need a more comprehensive check)
    if '@' not in sanitized_email or '.' not in sanitized_email:
        logger.warning(f'Invalid email address after sanitization: {sanitized_email}')
        return None

    return sanitized_email

def reset_verification_attempts(user):
    current_date = datetime.utcnow()
    if user.last_reset is None or user.last_reset.month != current_date.month:
        user.verification_attempts = 0
        user.last_reset = current_date
        db.session.commit()

def is_valid_email(email):
    if isinstance(email, float) and np.isnan(email):
        return False
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, str(email))

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange).lower().rstrip('.') for record in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.error(f"Error while getting MX records: {e}")
        return []

def verify_email_sync(mx_records, email):
    full_inbox = False  # Initialize full_inbox flag as False
    for mx_record in mx_records:
        try:
            with smtplib.SMTP(mx_record, timeout=30) as server:
                server.helo()
                server.mail('')
                code, message = server.rcpt(email)

                if code == 250:
                    return True, full_inbox  # Email exists and inbox is not full
                elif code == 550:
                    logger.info(f"Email does not exist for {email} at {mx_record}")
                    return False, full_inbox  # Email does not exist
                elif code == 552:
                    logger.info(f"Inbox is full for {email} at {mx_record}")
                    full_inbox = True  # Set full_inbox to True if inbox is full
                elif code in [450, 451, 452]:
                    logger.info(f"Temporary server issue for {email} at {mx_record}: {message}")
                    # Continue checking other MX records if a temporary error occurs
                    continue
                else:
                    logger.warning(f"Unhandled SMTP response code {code} for {email} at {mx_record}: {message}")
                    return False, full_inbox  # Return False for unhandled codes

        except smtplib.SMTPConnectError:
            logger.error(f"SMTP connection error for MX record {mx_record}")
        except smtplib.SMTPRecipientsRefused:
            logger.error(f"Recipient address refused for MX record {mx_record}")
        except socket.gaierror as e:
            logger.error(f"DNS resolution error for MX record {mx_record}: {e}")
        except (socket.timeout, ConnectionRefusedError) as e:
            logger.error(f"Network error for MX record {mx_record}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {e}")

    return False, full_inbox  # Return if no MX record confirms existence


def verify_email(mx_records, email):
    for mx_record in mx_records:
        email_exists, full_inbox = verify_email_sync(mx_records, email)
        if email_exists:
            return email_exists, full_inbox  # Return both values if the email exists
    return False, full_inbox



def extract_provider_from_mx(mx_record, providers):
    for keyword, provider in providers.items():
        if keyword in mx_record:
            return provider
    return 'Unknown Provider'

def perform_email_verification(email, providers, roles):
    """Perform email verification and return detailed verification information."""
    logger.info(f'Starting verification for email: {email}')
    
    if not is_valid_email(email):
        logger.warning(f'Invalid email format: {email}')
        return {
            'result': "Invalid email format",
            'provider': 'Unknown Provider',
            'role_based': 'No',
            'accept_all': 'No',
            'full_inbox': 'No'
        }

    # Step 1: Check the database for existing verification results
    existing_email = SearchedEMail.query.filter_by(email=email).first()
    if existing_email:
        logger.info(f'Found existing email verification result for {email}')
        return {
            'result': existing_email.result,
            'provider': existing_email.provider,
            'role_based': 'Yes' if existing_email.role_based else 'No',
            'accept_all': 'Yes' if existing_email.accept_all else 'No',
            'full_inbox': 'Yes' if existing_email.full_inbox else 'No'
        }

    domain = email.split('@')[-1]
    username = email.split('@')[0]

    # Fetch MX records
    try:
        mx_records = get_mx_records(domain)
    except Exception as e:
        logger.error(f'Error fetching MX records for domain {domain}: {e}')
        return {
            'result': "Error fetching MX records",
            'provider': 'Unknown Provider',
            'role_based': 'No',
            'accept_all': 'No',
            'full_inbox': 'No'
        }
    
    if not mx_records:
        logger.info(f'No MX records found for domain {domain}')
        return {
            'result': "No MX records found",
            'provider': 'Unknown Provider',
            'role_based': 'Yes' if username in roles else 'No',
            'accept_all': 'No',
            'full_inbox': 'No'
        }

    # Find provider
    provider = 'Unknown Provider'
    for mx in mx_records:
        for keyword, temp_provider in providers.items():
            if keyword in mx:
                provider = temp_provider
                break
        if provider != 'Unknown Provider':
            break 
    
    # Verify email existence and full inbox status
    try:
        email_exists, full_inbox = verify_email(mx_records, email)
    except Exception as e:
        logger.error(f'Error verifying email {email}: {e}')
        email_exists = False
        full_inbox = False

    # Check for catch-all/accept-all domain
    fake_email = f"blablabla@{domain}"
    try:
        accept_all, _ = verify_email(mx_records, fake_email)
    except Exception as e:
        logger.error(f'Error checking catch-all status for domain {domain}: {e}')
        accept_all = False

    # Determine result based on verification status
    result = "Email exists" if email_exists else "Email does not exist"
    if email_exists and accept_all:
        result = "Risky"
    
    logger.info(f'Verification result for email {email}: {result}, Provider: {provider}, Role-Based: {username in roles}, Accept-All: {accept_all}, Full Inbox: {full_inbox}')

    # Step 2: Add or update the email verification record in SearchedEMail table
    new_email_record = SearchedEMail( 
        email=email,
        result=result,
        provider=provider,
        role_based=1 if username in roles else 0,
        accept_all=1 if accept_all else 0,
        full_inbox=1 if full_inbox else 0
    )
    db.session.add(new_email_record)
    db.session.commit()

    # Get or create the SearchedEMail entry
    searched_email_entry = SearchedEMail.query.filter_by(email=email).first()

    # Step 3: Check if the user has already verified this email, if so update the timestamp
    user_id = session['user']
    existing_entry = db.session.query(searched_email_user).filter_by(user_id=user_id, email_id=searched_email_entry.email_id).first()

    if existing_entry:
        # Update the timestamp to the current time
        db.session.execute(
            searched_email_user.update().
            where(searched_email_user.c.user_id == user_id).
            where(searched_email_user.c.email_id == searched_email_entry.email_id).
            values(timestamp=datetime.utcnow())
        )
    else:
        # Create a new entry if it does not exist
        new_entry = searched_email_user.insert().values(user_id=user_id, email_id=searched_email_entry.email_id, timestamp=datetime.utcnow())
        db.session.execute(new_entry)
    
    db.session.commit()

    return {
        'result': result,
        'provider': provider,
        'role_based': 'Yes' if username in roles else 'No',
        'accept_all': 'Yes' if accept_all else 'No',
        'full_inbox': 'Yes' if full_inbox else 'No'
    }


def load_file(filename, separator=None):
    data = {}
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if separator:
                try:
                    key, value = line.split(separator, 1)
                    data[key.strip()] = value.strip()
                except ValueError:
                    logger.warning(f"Skipping invalid line (missing separator): {line}")
            else:
                data[line] = None
    return data

# Load providers, roles, and emails from text files
providers = load_file('providers.txt', separator=':')
roles = load_file('roles.txt')


@app.route('/')
def indexview():
    # Check if the user is in session
    if 'user' in session:  # Replace 'user_id' with the appropriate key used for session management
        return redirect(url_for('homeview'))  # Redirect to the home view if the user is logged in
    else:
        return render_template('index.html')

@app.route('/home')
def homeview():
    if 'user' in session:
        return render_template('home.html')
    return redirect('/')

@app.route('/verify')
def verifyview():
    if 'user' in session:
        user_id = session['user']
        
        # Alias for the association table to use in the query
        searched_email_user_alias = aliased(searched_email_user)

        # Get the last 10 emails checked by the user, ordered by the timestamp in the association table
        last_checked_emails = db.session.query(SearchedEMail) \
            .join(searched_email_user_alias, SearchedEMail.email_id == searched_email_user_alias.c.email_id) \
            .filter(searched_email_user_alias.c.user_id == user_id) \
            .order_by(searched_email_user_alias.c.timestamp.desc()) \
            .limit(10).all()
        
        return render_template('verify.html', last_checked_emails=last_checked_emails)

    return redirect('/')


@app.route('/list')
def listview():
    if 'user' in session:
        user = User.query.get(session['user'])
        if user.is_paid:
            return render_template('list.html')
        else:
            return jsonify({'error': 'This feature is available for paid users only.'}), 403
    return redirect('/')


@app.route('/verify', methods=['POST'])
def verify_email_address():
    if 'user' not in session:
        return redirect('/')

    user = User.query.get(session['user'])
    
    reset_verification_attempts(user)

    if not user.is_paid and user.verification_attempts >= 50:
        return jsonify({'error': 'Free plan users can only perform 50 verifications per month.'}), 403

    data = request.get_json()
    email = data.get('email')

    # Perform email verification
    verification_details = perform_email_verification(email, providers, roles)
    
    # Get or create the SearchedEMail entry
    searched_email_entry = SearchedEMail.query.filter_by(email=email).first()
    if not searched_email_entry:
        # Create a new entry if it does not exist
        searched_email_entry = SearchedEMail(email=email, result=verification_details['result'])
        db.session.add(searched_email_entry)
        db.session.commit()

    # Now store the user_id and email_id in the association table
    add_verified_email_for_user(user.user_id, searched_email_entry.email_id)

    if not user.is_paid:
        user.verification_attempts += 1
        db.session.commit()

    return jsonify(verification_details), 200

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


@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if 'csvFile' key is in request.files and if a file is selected
    if 'csvFile' not in request.files or not request.files['csvFile'].filename:
        logger.error('No selected file')
        return jsonify({'error': 'No selected file'}), 400

    file = request.files['csvFile']

    # Validate file extension
    if not file.filename.lower().endswith('.csv'):
        logger.error('Invalid file format. Please upload a CSV file.')
        return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    logger.info(f'File uploaded: {filename}')

    # Detect file properties
    encoding, delimiter = detect_file_properties(filepath)
    logger.info(f'Detected file properties: encoding={encoding}, delimiter={delimiter}')

    try:
        # Read CSV with detected properties
        df = pd.read_csv(filepath, encoding=encoding, delimiter=delimiter)
        logger.info('CSV file read successfully')
    except Exception as e:
        logger.error(f'Failed to read CSV: {str(e)}')
        return jsonify({'error': f'Failed to read CSV: {str(e)}'}), 400

    # Detect the email column
    email_column = detect_email_column(df)
    if not email_column:
        logger.error('No email column found')
        return jsonify({'error': "No email column found"}), 400

    logger.info(f'Email column detected: {email_column}')

    # Sanitize email addresses
    df[email_column] = df[email_column].apply(sanitize_email)
    logger.info('Email addresses sanitized')

    def process_emails():
        results = []
        for email in df[email_column]:
            logger.info(f'Processing email: {email}')
            verification_details = perform_email_verification(email, providers, roles)
            logger.info(f'Email: {email}, Verification Details: {verification_details}')
            results.append(verification_details)
        return pd.DataFrame(results)

    result_df = process_emails()
    df[['Result', 'Provider', 'RoleBased', 'AcceptAll', 'Full Inbox']] = result_df[['result', 'provider', 'role_based', 'accept_all', 'full_inbox']]
    df.to_csv(filepath, index=False)
    logger.info(f'Updated CSV file saved: {filename}')

    return jsonify({'filename': filename}), 200

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

def generate_nonce(length=32):
    """Generate a secure random nonce."""
    return secrets.token_urlsafe(length)

@app.route('/manual_signin', methods=['POST'])
def manual_signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        if user.is_google:
            return jsonify({'success': False, 'message': 'This email is registered via Google sign-in.'}), 401

        session['user'] = user.user_id
        session['user_email'] = user.email
        return jsonify({'success': True}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401

@app.route('/signup', methods=['GET', 'POST'])
def manual_signup():
    if request.method == 'POST':
        # Get data from form submission
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')  # In production, hash the password

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        # If the user exists, show a message instead of redirecting
        if existing_user:
            return jsonify({'message': 'Email is already registered. Please log in.'}), 400
                
        # Create new user
        hashed_password = generate_password_hash(password)  # Hash the password for security
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            is_google=False,
            is_paid=True
        )
        db.session.add(new_user)
        db.session.commit()

        # Log the user in by setting session
        session['user'] = new_user.user_id
        session['user_email'] = email
        return redirect('/index.html')

    return render_template('signup.html')


@app.route('/google/')
def google_login():
    nonce = generate_nonce()
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/auth/')
def google_auth():
    try:
        token = oauth.google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user = oauth.google.parse_id_token(token, nonce=nonce)  # Pass nonce here
        
        # Extract email and name from Google user info
        email = user.get('email')
        first_name = user.get('given_name')
        last_name = user.get('family_name')

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            if existing_user.is_google:
                # User has already signed in with Google
                session['user'] = existing_user.user_id
                session['user_email'] = email
                return redirect('/home')
            else:
                # User has signed in manually before and cannot use Google sign-in
                flash("This email is already registered with manual sign-in.")
                return redirect('/index')
        else:
            # Create a new user if it doesn't exist
            new_user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password='',  # Password is not set for Google sign-in users
                is_google=True,
                is_paid=True
            )
            db.session.add(new_user)
            db.session.commit()
            
            session['user'] = new_user.user_id
            session['user_email'] = email
            return redirect('/home')
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        flash("An authentication error occurred.")
        return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_email', None)
    flash('You have been logged out.')
    return redirect(url_for('indexview'))

if __name__ == '__main__':
    app.run(debug=True)
    with app.app_context():
        db.create_all()

