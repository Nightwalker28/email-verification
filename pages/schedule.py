import os
import time
from datetime import datetime, timedelta
from typing import Any
from factory import create_app
from celery import Celery
from celery.schedules import crontab
from config import Config, logger, db, UPLOAD_FOLDER, session_folder
from pages.models import UserUpload, Summary, TempUser
import logging

# ------------------------------------------------------------------------------ 
# Celery Application Setup
# ------------------------------------------------------------------------------ 
app = create_app()
celery = Celery(
    app.import_name,
    broker=Config.broker_url,
    backend=Config.result_backend
)
celery.conf.update(app.config)

# Disable Celery's default root logger hijacking so that our configuration in config.py is used.
celery.conf.worker_hijack_root_logger = False

# Attach the app logger's handlers to the Celery logger so that Celery logs
# get written to the same file (app.log).
celery_logger = logging.getLogger("celery")
for handler in logger.handlers:
    if handler not in celery_logger.handlers:
        celery_logger.addHandler(handler)
celery_logger.setLevel(logger.level)

class ContextTask(celery.Task):
    """A Celery Task base class that ensures tasks run within a Flask app context."""
    abstract = True
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        with app.app_context():
            return super().__call__(*args, **kwargs)
celery.Task = ContextTask

# ------------------------------------------------------------------------------ 
# Celery Tasks 
# ------------------------------------------------------------------------------ 
@celery.task
def delete_old_files_task() -> None:
    logger.info("Starting the process to delete old files.")
    one_month_ago = datetime.utcnow() - timedelta(days=30)
    old_files = UserUpload.query.filter(UserUpload.upload_date < one_month_ago).all()
    logger.info(f"Found {len(old_files)} files older than one month.")
    for upload in old_files:
        try:
            file_path = os.path.join(UPLOAD_FOLDER, upload.unique_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted file: {upload.unique_filename}")
            summary_entry = Summary.query.filter_by(list_name=upload.unique_filename).first()
            if summary_entry:
                db.session.delete(summary_entry)
                logger.info(f"Deleted summary record for {upload.unique_filename}")
            db.session.delete(upload)
            db.session.commit()
            logger.info(f"Deleted database record for: {upload.unique_filename}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting file {upload.unique_filename}: {e}", exc_info=True)

@celery.task
def cleanup_expired_sessions_task() -> None:
    now = time.time()
    logger.info("Starting session cleanup process.")
    for filename in os.listdir(session_folder):
        file_path = os.path.join(session_folder, filename)
        if os.path.isfile(file_path):
            last_modified = os.path.getmtime(file_path)
            if now - last_modified > app.permanent_session_lifetime.total_seconds():
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted expired session file: {filename}")
                except Exception as e:
                    logger.error(f"Error deleting session file {filename}: {e}", exc_info=True)

@celery.task
def cleanup_expired_temp_users_task() -> None:
    expiration_time = datetime.utcnow() - timedelta(hours=24)
    expired_users = TempUser.query.filter(TempUser.created_at < expiration_time).all()
    logger.info(f"Starting cleanup for expired temp users. Found {len(expired_users)} expired records.")
    for user in expired_users:
        try:
            db.session.delete(user)
            logger.info(f"Deleted expired temp user: {user.email}")
        except Exception as e:
            logger.error(f"Error deleting temp user {user.email}: {e}", exc_info=True)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error committing cleanup of temp users: {e}", exc_info=True)

@celery.task
def process_uploaded_file_task(unique_filename: str, user_id: int, force: bool = False) -> str:
    import os
    from flask import current_app
    from pages.fileupload import (
        detect_file_properties,
        read_csv_file,
        detect_email_column,
        sanitize_email,
        process_csv_in_chunks,
        process_emails,
        generate_summary,
        update_csv_with_verification
    )
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    logger.info(f"Starting processing of file: {unique_filename}")
    try:
        encoding, delimiter = detect_file_properties(filepath)
        file_size = os.path.getsize(filepath)
        app_instance = current_app._get_current_object()
        if file_size > (5 * 1024 * 1024):  # If file is larger than 5MB, process in chunks.
            result_df = process_csv_in_chunks(filepath, encoding, delimiter, user=user_id, force=force, app_instance=app_instance, chunksize=1000)
        else:
            df = read_csv_file(filepath, encoding, delimiter)
            if isinstance(df, dict):
                logger.error(f"File read error for {unique_filename}")
                return "File read error"
            email_column = detect_email_column(df)
            if not email_column:
                logger.error(f"No email column found in file {unique_filename}")
                return "No email column found"
            df[email_column] = df[email_column].apply(sanitize_email)
            result_df = process_emails(df[email_column], user=user_id, force=force, app_instance=app_instance)
        generate_summary(result_df, unique_filename, user_id)
        update_csv_with_verification(df if file_size <= (5 * 1024 * 1024) else result_df, result_df, filepath, unique_filename)
        db.session.commit()
        logger.info(f"Completed processing of file: {unique_filename}")
        return "Processing complete"
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing file {unique_filename}: {e}", exc_info=True)
        return "Error processing file"

# ------------------------------------------------------------------------------ 
# Celery Beat Schedule 
# ------------------------------------------------------------------------------ 
celery.conf.beat_schedule = {
    "delete-old-files-every-day": {
        "task": "pages.schedule.delete_old_files_task",
        "schedule": crontab(hour=0, minute=0),
    },
    "cleanup-expired-sessions-every-2-hours": {
        "task": "pages.schedule.cleanup_expired_sessions_task",
        "schedule": 7200.0,
    },
    "cleanup-expired-temp-users-every-day": {
        "task": "pages.schedule.cleanup_expired_temp_users_task",
        "schedule": 86400.0,
    },
}
