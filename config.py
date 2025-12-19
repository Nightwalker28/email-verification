import os,logging,datetime,smtplib
from flask import Flask,jsonify,make_response
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from email.mime.text import MIMEText

load_dotenv()

# Configure session
app = Flask(__name__)
session_folder = 'flask_session'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('Mail_Username')
app.config['MAIL_PASSWORD'] = os.environ.get('Mail_PW')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['SESSION_SQLALCHEMY'] = db
app.secret_key = os.environ.get('SECRET_KEY')
Session(app)

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

def success_response(message='', status_code=200):
    response = jsonify({'success': message})  # Use a dictionary to structure the message
    response.status_code = status_code
    return response

def error_response(message='', status_code=400):
    response = jsonify({'error': message})  # Use a dictionary to structure the message
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

# Load providers, roles, and emails from text files
providers = load_file('providers.txt', separator=':')
roles = load_file('roles.txt')
disposable = load_file('index.txt')
FREE_EMAIL_PROVIDERS = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'}

def mail_server(recipient_email, subject, html_body):
    sender_email = app.config['MAIL_USERNAME']
    
    # Create an HTML email message
    msg = MIMEText(html_body, "html")
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    try:
        # Set up the SMTP server and send the email
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()  # Enable TLS
            server.login(sender_email, app.config['MAIL_PASSWORD'])  # Log in to the server
            server.send_message(msg)  # Send the email
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False