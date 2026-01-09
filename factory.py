from flask import Flask
from flask_session import Session
from config import Config, db, oauth, migrate
import os

def create_app():
    app = Flask(__name__)  # Flask will use ./templates and ./static automatically.
    app.config.from_object(Config)

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

    # Register blueprints.
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    from app.files import files_bp as files_blueprint
    app.register_blueprint(files_blueprint)
    # from app.api import api as api_blueprint
    # app.register_blueprint(api_blueprint)

    return app