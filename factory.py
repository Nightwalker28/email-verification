from flask import Flask
from flask_session import Session
from config import Config, db, oauth, migrate
import os
from celery import Celery
from werkzeug.middleware.proxy_fix import ProxyFix

celery = Celery(
    'emailverification',
    include=['pages.schedule']
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    db.init_app(app)
    oauth.init_app(app)
    Session(app)

    migrate.init_app(app, db)

    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
    celery.conf.update(app.config)

    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    from app.files import files_bp as files_blueprint
    app.register_blueprint(files_blueprint)

    return app
