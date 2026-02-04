import os
import logging
import datetime
import smtplib
from dotenv import load_dotenv
from email.mime.text import MIMEText
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
from flask import jsonify
from redis import Redis
from urllib.parse import urlparse
import sys
import ssl

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('Mail_Username')
    MAIL_PASSWORD = os.environ.get('Mail_PW')
    SMTP_HELO = os.environ.get('SMTP_HELO')
    SMTP_MAIL = os.environ.get('SMTP_MAIL')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'False').lower() in ['true', '1', 'yes']
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = os.environ.get("SESSION_TYPE", "redis")

    if SESSION_TYPE == "redis":
        redis_url = os.environ.get("SESSION_REDIS", "redis://redis:6379/0")
        parsed_url = urlparse(redis_url)
        SESSION_REDIS = Redis(
            host=parsed_url.hostname,
            port=parsed_url.port,
            db=int(parsed_url.path.replace("/", "") or 0)
        )
    else:
        SESSION_FILE_DIR = os.environ.get("SESSION_FILE_DIR", os.path.join(os.path.abspath(os.path.dirname(__file__)), 'flask_session'))

    PERMANENT_SESSION_LIFETIME = datetime.timedelta(hours=1)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
    broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/1')
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 10)),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 20)),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', 280))
    }

db = SQLAlchemy()
migrate = Migrate()
oauth = OAuth()

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {'csv', 'xlsx'}

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

handler = logging.StreamHandler(sys.stdout)
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
        response_dict['data'] = data
    response = jsonify(response_dict)
    response.status_code = status_code
    return response

def error_response(message='', status_code=400):
    response = jsonify({'error': message})
    response.status_code = status_code
    return response


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
    sender = Config.MAIL_USERNAME
    msg = MIMEText(html_body, "html")
    msg['From'] = sender
    msg['To']   = recipient_email
    msg['Subject'] = subject

    context = ssl.create_default_context()
    try:
        
        if Config.MAIL_PORT == 465:
            server = smtplib.SMTP_SSL(
                Config.MAIL_SERVER,
                Config.MAIL_PORT,
                context=context,
                timeout=10
            )
        else:
            server = smtplib.SMTP(
                Config.MAIL_SERVER,
                Config.MAIL_PORT,
                timeout=10
            )
            server.ehlo()
            server.starttls(context=context)
        server.login(sender, Config.MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True

    except Exception as e:
        print("Email send failed:", e)
        return False


mail_server = mail_server_func

providers = load_file('providers.txt', separator=':')
roles = load_file('roles.txt')
disposable = load_file('index.txt')
FREE_EMAIL_PROVIDERS = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'}
