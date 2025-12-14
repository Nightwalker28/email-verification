import os,logging,datetime
from flask import Flask
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

load_dotenv()

# Configure session
app = Flask(__name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'no-reply@acumenintelligence.com'
app.config['MAIL_PASSWORD'] = 'xexa kqse gcxs jbcm'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/emailtool'
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