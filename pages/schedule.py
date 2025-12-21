from apscheduler.schedulers.background import BackgroundScheduler
from config import logger,os,db,app,session_folder,UPLOAD_FOLDER
from pages.models import UserUpload,Summary,TempUser
from datetime import datetime,timedelta,timezone
import time

scheduler = BackgroundScheduler()

def schedule_task(task_function, interval_type, interval_value, *args, **kwargs):
    """
    Schedules a task with the given function and interval.
    :param task_function: The function to schedule
    :param interval_type: The type of interval ('days', 'hours', 'minutes', etc.)
    :param interval_value: The interval value (e.g., every '1 day', '5 hours', etc.)
    :param upload_folder: The folder where the task will operate (for file-related tasks)
    :param args: Positional arguments to pass to the task_function
    :param kwargs: Keyword arguments to pass to the task_function
    """
    logger.info(f"Setting up the scheduler for task: {task_function.__name__} to run every {interval_value} {interval_type}.")
    job = scheduler.add_job(task_function, 'interval', **{interval_type: interval_value}, args=args, kwargs=kwargs)
    logger.info(f"Scheduler started successfully for task: {task_function.__name__}")
    # Define UTC or your desired timezone
    tz = timezone(timedelta(hours=5, minutes=30))
    # Get the current time in that timezone
    now = datetime.now(tz)
    next_run_time = job.trigger.get_next_fire_time(None, now)
    logger.info(f"Next run time for job '{task_function.__name__}': {next_run_time}")
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started.")    
    with app.app_context():
        delete_old_files()
        cleanup_expired_sessions()

def delete_old_files():
    """
    Deletes files older than one month from the upload folder and corresponding database entries.
    """
    with app.app_context():  # Ensure the Flask app context is available
        logger.info("Starting the process to delete old files.")
        one_month_ago = datetime.now() - timedelta(days=30)
        old_files = UserUpload.query.filter(UserUpload.upload_date < one_month_ago).all()
        logger.info(f"Found {len(old_files)} files older than one month.")
        for upload in old_files:
            try:
                # Delete the file from the file system
                file_path = os.path.join(UPLOAD_FOLDER, upload.unique_filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted file: {upload.unique_filename}")
                # Delete the corresponding summary record
                summary_entry = Summary.query.filter_by(list_name=upload.unique_filename).first()
                if summary_entry:
                    db.session.delete(summary_entry)
                    logger.info(f"Deleted summary record for {upload.unique_filename}")
                # Delete the file entry from the database
                db.session.delete(upload)
                db.session.commit()
                logger.info(f"Deleted database record for: {upload.unique_filename}")
            except Exception as e:
                logger.error(f"Error deleting file {upload.unique_filename}: {str(e)}")

def cleanup_expired_sessions():
    """
    Deletes expired session files from the session folder.
    """
    with app.app_context():  # Ensure the Flask app context is available
        now = time.time()
        logger.info("Starting session cleanup process.")
        for filename in os.listdir(session_folder):
            file_path = os.path.join(session_folder, filename)
            # Check if the file modification time is older than session lifetime
            if os.path.isfile(file_path):
                last_modified = os.path.getmtime(file_path)
                if now - last_modified > app.permanent_session_lifetime.total_seconds():
                    os.remove(file_path)
                    logger.info(f"Deleted expired session file: {filename}")

def cleanup_expired_temp_users():
    """
    Deletes temporary user records older than 24 hours from the TempUser table.
    """
    with app.app_context():  # Ensure the Flask app context is available
        expiration_time = datetime.utcnow() - timedelta(hours=24)  # Calculate expiration time
        expired_users = TempUser.query.filter(TempUser.created_at < expiration_time).all()  # Query for expired users
        logger.info(f"Starting cleanup process for expired temp users. Found {len(expired_users)} expired records.")
        for user in expired_users:
            db.session.delete(user)  # Delete expired user records
            logger.info(f"Deleted expired temp user: {user.email}")
        db.session.commit()  # Commit the changes to the database
