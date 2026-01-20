from factory import create_app, celery
from pages import schedule
# Create the Flask app instance
flask_application = create_app()
schedule.flask_app = flask_application