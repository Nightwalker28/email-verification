# pages/schedule.py
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict
import pandas as pd # Import pandas
from factory import create_app # Assuming factory.py creates your Flask app
from celery import Celery, Task # Import Task base class
from celery.schedules import crontab
import logging
from flask import Flask # Import Flask for type hinting

from config import Config, logger, db, UPLOAD_FOLDER, session_folder
from pages.models import UserUpload, Summary, TempUser, User # Import User model

# --- Import the CORRECT functions from fileupload ---
from pages.fileupload import (
    process_file,       # Main processing function
    generate_summary,   # Summary generation function
    save_verified_file, # Function to save results file
    read_excel_file,    # Helper to read excel
    detect_csv_properties # Helper to read csv
)
# --- End Import Correction ---

# ------------------------------------------------------------------------------
# Flask App Instance (Create first)
# ------------------------------------------------------------------------------
flask_app = create_app()

# ------------------------------------------------------------------------------
# Celery Context Task (Define before Celery app creation)
# ------------------------------------------------------------------------------
class ContextTask(Task):
    """A Celery Task base class that ensures tasks run within a Flask app context."""
    abstract = True
    # No need to store app here, will use module-level flask_app

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Directly use the flask_app instance defined at the module level
        with flask_app.app_context():
            return super().__call__(*args, **kwargs)

# ------------------------------------------------------------------------------
# Celery Application Setup
# ------------------------------------------------------------------------------

# --- Celery Initialization Function ---
def make_celery(app: Flask) -> Celery:
    """Configures and returns a Celery application instance."""
    celery_instance = Celery(
        app.import_name,
        broker=app.config.get('CELERY_BROKER_URL', Config.broker_url), # Get from app config
        backend=app.config.get('CELERY_RESULT_BACKEND', Config.result_backend), # Get from app config
        # include=['pages.schedule'] # Explicitly include task modules if needed
    )
    celery_instance.conf.update(app.config)
    celery_instance.conf.worker_hijack_root_logger = False

    # Attach app logger handlers
    celery_logger = logging.getLogger("celery")
    if not celery_logger.handlers:
        for handler in logger.handlers:
            celery_logger.addHandler(handler)
    celery_logger.setLevel(logger.level)

    # Set the base task class using the module-level ContextTask
    celery_instance.Task = ContextTask
    return celery_instance

# --- Create Celery Instance ---
# Create Celery instance using the function and the Flask app
celery = make_celery(flask_app)

# ------------------------------------------------------------------------------
# Celery Tasks (Decorated with the 'celery' instance created above)
# ------------------------------------------------------------------------------
@celery.task(bind=True)
def delete_old_files_task(self: ContextTask) -> None: # Type hint should work now
    """Deletes UserUploads, Summaries, and files older than 30 days."""
    logger.info("Starting the process to delete old files.")
    one_month_ago = datetime.utcnow() - timedelta(days=30)
    # Context is handled by the base class __call__ method now
    old_files = UserUpload.query.filter(UserUpload.upload_date < one_month_ago).all()
    logger.info(f"Found {len(old_files)} files older than one month.")
    deleted_count = 0
    error_count = 0
    for upload in old_files:
        try:
            # Attempt to delete associated summary first
            # Use list_name for lookup if upload_id isn't reliable or consistent yet
            summary_entry = Summary.query.filter_by(list_name=upload.unique_filename, user_id=upload.user_id).first()
            if summary_entry:
                db.session.delete(summary_entry)
                logger.debug(f"Marked summary record for deletion: {upload.unique_filename}")

            # Delete the UserUpload record
            db.session.delete(upload)
            logger.debug(f"Marked database record for deletion: {upload.unique_filename}")

            # Delete the physical files (original and verified)
            original_filepath = upload.filepath
            verified_filepath = upload.verified_filepath

            if original_filepath and os.path.exists(original_filepath):
                os.remove(original_filepath)
                logger.info(f"Deleted original physical file: {original_filepath}")
            elif original_filepath:
                 logger.warning(f"Original file path recorded but not found on disk: {original_filepath}")

            if verified_filepath and os.path.exists(verified_filepath):
                os.remove(verified_filepath)
                logger.info(f"Deleted verified physical file: {verified_filepath}")
            elif verified_filepath:
                 logger.warning(f"Verified file path recorded but not found on disk: {verified_filepath}")

            # Commit deletions for this upload record
            db.session.commit()
            logger.info(f"Successfully deleted records and file(s) for: {upload.unique_filename}")
            deleted_count += 1
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting file {upload.unique_filename}: {e}", exc_info=True)
            error_count += 1
    logger.info(f"Finished deleting old files. Deleted: {deleted_count}, Errors: {error_count}")


@celery.task(bind=True)
def cleanup_expired_sessions_task(self: ContextTask) -> None: # Type hint should work now
    """Deletes expired session files from the filesystem session storage."""
    now = time.time()
    logger.info("Starting session cleanup process.")
    # Access app config via the flask_app instance (available in module scope)
    session_lifetime_seconds = flask_app.permanent_session_lifetime.total_seconds()
    deleted_count = 0
    error_count = 0
    if not os.path.isdir(session_folder):
        logger.warning(f"Session folder '{session_folder}' not found. Skipping cleanup.")
        return
    try:
        for filename in os.listdir(session_folder):
            file_path = os.path.join(session_folder, filename)
            if os.path.isfile(file_path):
                try:
                    last_modified = os.path.getmtime(file_path)
                    if now - last_modified > session_lifetime_seconds:
                        os.remove(file_path)
                        logger.info(f"Deleted expired session file: {filename}")
                        deleted_count += 1
                except Exception as e:
                    logger.error(f"Error processing session file {filename}: {e}", exc_info=True)
                    error_count += 1
        logger.info(f"Finished session cleanup. Deleted: {deleted_count}, Errors: {error_count}")
    except Exception as e:
         logger.error(f"Error listing session directory '{session_folder}': {e}", exc_info=True)


@celery.task(bind=True)
def cleanup_expired_temp_users_task(self: ContextTask) -> None: # Type hint should work now
    """Deletes temporary user registration records older than 24 hours."""
    expiration_time = datetime.utcnow() - timedelta(hours=24)
    logger.info("Starting cleanup for expired temp users.")
    deleted_count = 0
    error_count = 0
    # Context is handled by the base class __call__ method now
    try:
        expired_users = TempUser.query.filter(TempUser.created_at < expiration_time).all()
        logger.info(f"Found {len(expired_users)} expired temp user records.")
        for user in expired_users:
            try:
                db.session.delete(user)
                logger.info(f"Marked expired temp user for deletion: {user.email}")
            except Exception as e:
                # Log error for this specific user but continue with others
                logger.error(f"Error marking temp user {user.email} for deletion: {e}", exc_info=True)
                error_count += 1
        # Commit all deletions at once
        db.session.commit()
        deleted_count = len(expired_users) - error_count
        logger.info(f"Finished temp user cleanup. Deleted: {deleted_count}, Errors: {error_count}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during bulk cleanup of temp users: {e}", exc_info=True)


@celery.task(bind=True)
def process_uploaded_file_task(self: ContextTask, unique_name: str, user_id: int, force: bool = False) -> Dict[str, Any]: # Type hint should work now
    """
    Background task to process an uploaded file, verify emails, generate summary,
    and save the results to a new file, then delete the original.
    """
    logger.info(f"Task started: Processing file {unique_name} for user {user_id} (Force: {force})")

    # Context is handled by the base class __call__ method now
    original_filepath = None # Keep track for potential deletion
    verified_file_saved = False
    verified_path = None
    summary_saved = False
    final_status = "error" # Default status
    final_message = "Task initialization failed."
    summary_id = None

    try:
        # 1. Fetch necessary records
        user = User.query.get(user_id)
        upload = UserUpload.query.filter_by(unique_filename=unique_name, user_id=user_id).first()

        if not user:
            logger.error(f"Task failed: User {user_id} not found.")
            return {"status": "error", "message": "User not found"}
        if not upload:
            logger.error(f"Task failed: Upload {unique_name} for user {user_id} not found.")
            return {"status": "error", "message": "Upload record not found"}

        original_filepath = upload.filepath # Store original path
        upload_id = upload.id

        if not original_filepath or not os.path.exists(original_filepath):
             logger.error(f"Task failed: Original file path '{original_filepath}' for upload {unique_name} not found on disk.")
             return {"status": "error", "message": "Uploaded file not found on server."}

        # 2. Call the main processing function from fileupload
        logger.info(f"Starting email verification process for {unique_name}...")
        # Pass the module-level flask_app instance
        results_df = process_file(original_filepath, user, force, app_instance=flask_app)

        if results_df is None:
             logger.error(f"Processing for {unique_name} failed and returned None.")
             return {"status": "error", "message": "File processing failed unexpectedly."}

        # 3. Save Verified File (if results exist)
        if not results_df.empty:
            try:
                logger.info(f"Reading original file data from {original_filepath} to merge results.")
                original_df = None
                _, ext = os.path.splitext(original_filepath)
                if ext.lower() == '.csv':
                    encoding, delimiter = detect_csv_properties(original_filepath)
                    # Read without chunking for merging
                    original_df = pd.read_csv(original_filepath, encoding=encoding, delimiter=delimiter, on_bad_lines='warn', low_memory=False)
                elif ext.lower() in ['.xlsx', '.xls']:
                    original_df = read_excel_file(original_filepath)

                if original_df is not None and not original_df.empty:
                    logger.info(f"Attempting to save verified file for {unique_name}...")
                    verified_path = save_verified_file(original_df, results_df, original_filepath)
                    if verified_path:
                        # Update the UserUpload record with the new path
                        upload.verified_filepath = verified_path
                        db.session.add(upload) # Add to session to mark for commit
                        verified_file_saved = True
                        logger.info(f"Verified file saved: {verified_path}. Marked upload record {upload_id} for update.")
                    else:
                        logger.error(f"Failed to save verified file for {unique_name} (save_verified_file returned None).")
                else:
                     logger.warning(f"Could not read or original file was empty: {original_filepath}. Cannot save verified file.")

            except Exception as save_err:
                logger.exception(f"Error occurred while trying to save verified file for {unique_name}: {save_err}")
                # Continue to summary generation, but verified_file_saved remains False
        else:
             logger.warning(f"Processing for {unique_name} yielded no results. Skipping verified file save.")

        # 4. Generate and save the summary
        logger.info(f"Generating summary for {unique_name}...")
        summary = generate_summary(results_df, unique_name, user_id, upload_id)
        if summary:
            summary_saved = True
            summary_id = summary.id
            logger.info(f"Summary generated/updated successfully for {unique_name} (Summary ID: {summary_id}).")
        else:
            logger.error(f"Failed to generate/save summary for {unique_name}.")

        # 5. Final Commit (includes potential update to upload.verified_filepath)
        try:
            db.session.commit()
            logger.info(f"Committed final DB changes for task {unique_name}.")
            # If commit is successful AND verified file was saved, delete original
            if verified_file_saved and original_filepath and os.path.exists(original_filepath):
                 try:
                     os.remove(original_filepath)
                     logger.info(f"Successfully deleted original file: {original_filepath}")
                     # Optionally update upload.filepath to None in DB? Maybe not necessary.
                     # upload.filepath = None
                     # db.session.commit() # Requires another commit
                 except OSError as del_err:
                     logger.error(f"Failed to delete original file {original_filepath} after saving verified version: {del_err}")
        except Exception as commit_err:
             db.session.rollback()
             logger.error(f"Failed final commit for task {unique_name}: {commit_err}", exc_info=True)
             # Update status to reflect commit failure - summary/verified path might not be saved
             summary_saved = False
             verified_file_saved = False # Rollback means verified_filepath wasn't saved in DB
             final_status = "error"
             final_message = f"Processing finished, but failed final DB commit: {commit_err}"
             return {"status": final_status, "message": final_message} # Exit early on commit fail


        # 6. Determine final status message
        if summary_saved:
            final_status = "success"
            final_message = "Processing complete."
            if verified_file_saved:
                 final_message += " Results file saved."
            elif not results_df.empty:
                 final_message += " Warning: Failed to save results file."
        else:
            final_status = "error"
            final_message = "Processing finished, but failed to save summary."
            if verified_file_saved: # This case is unlikely if commit failed, but possible if only summary save failed
                 final_message += " Results file may have been saved but not recorded correctly."

        logger.info(f"Task finished for {unique_name}. Status: {final_status}, Message: {final_message}")
        return {"status": final_status, "summary_id": summary_id, "message": final_message}

    except Exception as e:
        # Catch any unexpected errors during the task execution
        db.session.rollback() # Ensure rollback on unexpected error
        logger.exception(f"Task failed unexpectedly for file {unique_name}, user {user_id}: {e}")
        return {"status": "error", "message": f"An unexpected error occurred: {e}"}
# --- End Task Logic Update ---

# ------------------------------------------------------------------------------
# Celery Beat Schedule (Use the 'celery' instance defined above)
# ------------------------------------------------------------------------------
celery.conf.beat_schedule = {
    "delete-old-files-every-day": {
        "task": "pages.schedule.delete_old_files_task",
        "schedule": crontab(hour=0, minute=0), # Run daily at midnight
    },
    "cleanup-expired-sessions-every-hour": { # Changed to hourly, adjust as needed
        "task": "pages.schedule.cleanup_expired_sessions_task",
        "schedule": crontab(minute=0), # Run at the start of every hour
        # "schedule": 3600.0, # Alternative: run every 3600 seconds
    },
    "cleanup-expired-temp-users-every-day": {
        "task": "pages.schedule.cleanup_expired_temp_users_task",
        "schedule": crontab(hour=1, minute=0), # Run daily at 1 AM
        # "schedule": 86400.0, # Alternative: run every 24 hours
    },
}

# Optional: Set timezone for Celery Beat if needed
# celery.conf.timezone = 'UTC' # Or your desired timezone
