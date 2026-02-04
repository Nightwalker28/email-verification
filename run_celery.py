from factory import create_app, celery
from pages import schedule
flask_application = create_app()
schedule.flask_app = flask_application