from flask import Flask
from flask_session import Session
from config import Config, db, oauth, migrate
import os
from celery import Celery
from werkzeug.middleware.proxy_fix import ProxyFix

celery = Celery(
    'emailverification',      # Use a consistent application name
    include=['pages.schedule']  # Explicitly include the tasks module
                                # Broker/backend will be set from app.config
)

def create_app():
    app = Flask(__name__)  # Flask will use ./templates and ./static automatically.
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    # Initialize extensions.
    db.init_app(app)
    oauth.init_app(app)
    Session(app)

    # Setup Flask-Migrate.
    migrate.init_app(app, db)

    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
    # Celery will pick up CELERY_BROKER_URL and CELERY_RESULT_BACKEND 
    # and other CELERY_ prefixed settings from app.config
    celery.conf.update(app.config)

    # Register blueprints.
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    from app.files import files_bp as files_blueprint
    app.register_blueprint(files_blueprint)

    return app
