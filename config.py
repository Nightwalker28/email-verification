import os
import logging
import datetime
import smtplib
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from email.mime.text import MIMEText
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
from flask import jsonify

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('Mail_Username')
    MAIL_PASSWORD = os.environ.get('Mail_PW')
    SMTP_HELO = os.environ.get('SMTP_HELO')
    SMTP_MAIL = os.environ.get('SMTP_MAIL')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'False').lower() in ['true', '1', 'yes']
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=1)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
    broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
    # SQLAlchemy engine options for connection pooling.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20)),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 280))
    }

# Initialize extensions (they are tied to the app later)
db = SQLAlchemy()
migrate = Migrate()
oauth = OAuth()

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {'csv', 'xlsx'}

# Create uploads folder
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create session folder
session_folder = os.path.join(BASE_DIR, 'flask_session')
os.makedirs(session_folder, exist_ok=True)

# Setup logging with rotation (app.log will log INFO level messages)
handler = RotatingFileHandler('app.log', maxBytes=10000000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def success_response(message: str = '', data: dict = None, status_code: int = 200):
    """Creates a standardized success JSON response."""
    response_dict = {'status': 'success', 'message': message}
    if data is not None:
        response_dict['data'] = data  # Add data under a 'data' key
    response = jsonify(response_dict)
    response.status_code = status_code
    return response

def error_response(message='', status_code=400):
    response = jsonify({'error': message})
    response.status_code = status_code
    return response

# Single definition of load_file (duplicate removed)
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

def mail_server_func(recipient_email, subject, html_body):
    sender_email = Config.MAIL_USERNAME
    msg = MIMEText(html_body, "html")
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    try:
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            server.starttls()
            server.login(sender_email, Config.MAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# Expose the mail_server function
mail_server = mail_server_func

# Load providers, roles, and disposable emails from text files.
providers = load_file('providers.txt', separator=':')
roles = load_file('roles.txt')
disposable = load_file('index.txt')
FREE_EMAIL_PROVIDERS = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'}
