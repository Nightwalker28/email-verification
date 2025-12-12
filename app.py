import smtplib
import pandas as pd
import re
import dns.resolver
import numpy as np
from flask import Flask, render_template, request, send_from_directory, jsonify, session, redirect, url_for, flash
from authlib.integrations.flask_client import OAuth
from flask_session import Session
import os
import logging
from dotenv import load_dotenv
import socket
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from logging.handlers import RotatingFileHandler
import chardet
from werkzeug.security import check_password_hash, generate_password_hash

# Load environment variables
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/emailtool'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_google = db.Column(db.Boolean, default=False)

    
    def __repr__(self):
        return f'<User {self.email}>'
    


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
logger = logging.getLogger(__name__)
logger.addHandler(handler)

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
    for column in df.columns:
        # Check if the column name is related to email
        if re.search(r'email|e-mail|email address', column, re.IGNORECASE):
            return column
    return None

def sanitize_email(email):
    """Sanitize and validate email addresses."""
    if not isinstance(email, str):
        return None
    return email.strip().lower()

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
    if not is_valid_email(email):
        return {
            'result': "Invalid email format",
            'provider': 'Unknown Provider',
            'role_based': 'No',
            'accept_all': 'No',
            'full_inbox': 'No'
        }

    domain = email.split('@')[-1]
    username = email.split('@')[0]
    mx_records = get_mx_records(domain)

    if not mx_records:
        return {
            'result': "No MX records found",
            'provider': 'Unknown Provider',
            'role_based': 'Yes' if username in roles else 'No',
            'accept_all': 'No',
            'full_inbox': 'No'
        }

    provider = next((extract_provider_from_mx(mx, providers) for mx in mx_records if extract_provider_from_mx(mx, providers) != 'Unknown Provider'), 'Unknown Provider')

    # Get both email existence and full inbox status
    email_exists, full_inbox = verify_email(mx_records, email)
    
    # Check if the domain accepts all emails (catch-all)
    fake_email = f"blablabla@{domain}"
    accept_all, _ = verify_email(mx_records, fake_email)  # full_inbox check is not needed here for fake email

    # Set the initial result
    result = "Email exists" if email_exists else "Email does not exist"

    # Customize the result if both email exists and accept_all is 'Yes'
    if email_exists and accept_all:
        result = "Risky"

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
    return render_template('index.html')

@app.route('/home')
def homeview():
    if 'user' in session:
        return render_template('home.html')
    return redirect('/')

@app.route('/verify')
def verifyview():
    if 'user' in session:
        return render_template('verify.html')
    return redirect('/')

@app.route('/list')
def listview():
    if 'user' in session:
        return render_template('list.html')
    return redirect('/')

@app.route('/verify', methods=['POST'])
def verify_email_address():
    data = request.get_json()
    email = data.get('email')
    
    verification_details = perform_email_verification(email, providers, roles)

    return jsonify(verification_details), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if 'csvFile' key is in request.files and if a file is selected
    if 'csvFile' not in request.files or not request.files['csvFile'].filename:
        return jsonify({'error': 'No selected file'}), 400

    file = request.files['csvFile']

    # Validate file extension
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Detect file properties
    encoding, delimiter = detect_file_properties(filepath)

    try:
        # Read CSV with detected properties
        df = pd.read_csv(filepath, encoding=encoding, delimiter=delimiter)
    except Exception as e:
        return jsonify({'error': f'Failed to read CSV: {str(e)}'}), 400

    # Detect the email column
    email_column = detect_email_column(df)
    if not email_column:
        return jsonify({'error': "No email column found"}), 400

    # Sanitize email addresses
    df[email_column] = df[email_column].apply(sanitize_email)

    def process_emails():
        results = []
        for email in df[email_column]:
            verification_details = perform_email_verification(email, providers, roles)
            results.append(verification_details)
        return pd.DataFrame(results)

    result_df = process_emails()
    df[['Result', 'Provider', 'RoleBased', 'AcceptAll', 'Full Inbox']] = result_df[['result', 'provider', 'role_based', 'accept_all','full_inbox']]
    df.to_csv(filepath, index=False)

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
        if existing_user:
            flash('Email is already registered. Please log in.')
            return redirect(url_for('indexview'))
        
        # Create new user
        hashed_password = generate_password_hash(password)  # Hash the password for security
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            is_google=False
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
                is_google=True
            )
            db.session.add(new_user)
            db.session.commit()
            
            session['user'] = new_user.user_id
            session['user_email'] = email
            return redirect('/home')
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        flash("An authentication error occurred.")
        return redirect('/index')


if __name__ == '__main__':
    app.run(debug=True)
