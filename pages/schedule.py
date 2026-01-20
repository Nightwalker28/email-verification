# pages/schedule.py
import os, time, json, redis, logging
from datetime import datetime, timedelta
from typing import Any, Dict
import pandas as pd # Import pandas
from celery import Celery, Task, shared_task, current_task, states
from celery.schedules import crontab
from flask import Flask # Import Flask for type hinting
from pages.users import get_user_id
from pages.emailverification import perform_email_verification
from config import Config, logger, db, providers, roles
from pages.models import UserUpload, Summary, TempUser, User # Import User model
from factory import celery
# --- Import the CORRECT functions from fileupload ---
from pages.fileupload import (
    process_file,       # Main processing function
    generate_summary,   # Summary generation function
    save_verified_file, # Function to save results file
    read_excel_file,    # Helper to read excel
    detect_csv_properties # Helper to read csv
)
from celery.exceptions import Ignore # Import Ignore for specific error handling
# --- End Import Correction ---

# Define flask_app at the module level.
# This instance will be set by the Celery worker's startup script.
flask_app: Flask = None
# ------------------------------------------------------------------------------
# Celery Context Task (Define before Celery app creation)
# ------------------------------------------------------------------------------
class ContextTask(Task):
    """A Celery Task base class that ensures tasks run within a Flask app context."""
    abstract = True

    def __call__(self, *args: Any, **kwargs: Any) -> Any: # This method wraps the task's run method
        if flask_app:
            with flask_app.app_context():
                return super().__call__(*args, **kwargs)
        else:
            logger.error(f"Task {self.name}: Flask app context (flask_app) not available.")
            # For tasks interacting with DB, context is crucial.
            raise RuntimeError(f"Task {self.name} cannot run without Flask app context.")

# ------------------------------------------------------------------------------
# Celery Tasks (Decorated with the 'celery' instance created above)
# ------------------------------------------------------------------------------
@celery.task(bind=True, base=ContextTask)
def delete_old_files_task(self: Task) -> None:
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

@celery.task(bind=True, base=ContextTask)
def cleanup_expired_temp_users_task(self: Task) -> None:
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


@celery.task(bind=True, base=ContextTask)
def process_uploaded_file_task(self: Task, unique_name: str, user_id: int, force: bool = False) -> Dict[str, Any]:
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
    
# Add base=ContextTask here so this task runs within the Flask app context
@celery.task(bind=True, base=ContextTask, soft_time_limit=90, time_limit=120)
def email_verify_task(self, email: str, user_id: int, force_live: bool):
    """
    Runs the heavy perform_email_verification in the background.
    """
    task_id = self.request.id
    logger.info(f"Task {task_id}: Starting email_verify_task for email: {email}, user_id: {user_id}, force_live: {force_live}")
    redis_client_instance = None # Initialize client to None

    try:
        # The ContextTask base class handles the app context now
        # verification_details is the dict from perform_email_verification
        verification_details = perform_email_verification(
            email, providers, roles, user=user_id, force_live_check=force_live, commit_immediately=True
        )
        logger.info(f"Task {task_id}: perform_email_verification completed for {email}. Result: {verification_details}")

        # Data to be published to Redis (this structure is good for the client)
        sse_data_for_redis_publish = {
            "status": "completed",
            "email": email, # Original email
            "details": verification_details # The result from perform_email_verification
        }
        
        try:
            redis_client_instance = redis.Redis.from_url(Config.REDIS_URL)
            redis_client_instance.ping() # Test connection before publishing
            logger.info(f"Task {task_id}: Redis client connected for publishing to channel {task_id}.")
            
            json_payload = json.dumps(sse_data_for_redis_publish)
            logger.debug(f"Task {task_id}: Publishing to Redis channel {task_id}: {json_payload}")
            
            publish_success_count = redis_client_instance.publish(task_id, json_payload)
            logger.info(f"Task {task_id}: Redis publish command executed for {email}. Subscribers received by publish: {publish_success_count}")
            if publish_success_count == 0:
                logger.warning(f"Task {task_id}: Redis publish for {email} returned 0, meaning no clients were subscribed to {task_id} at the time of publishing.")
        except redis.exceptions.RedisError as redis_err:
            logger.error(f"Task {task_id}: Redis error during SSE publish for {email}: {redis_err}", exc_info=True)
        except json.JSONDecodeError as json_err: # Corrected from JSONDecodeError to json.JSONDecodeError
            logger.error(f"Task {task_id}: JSON encoding error for SSE data for {email}: {json_err}", exc_info=True)
        except Exception as e:
            logger.error(f"Task {task_id}: Unexpected error during SSE publish phase for {email}: {e}", exc_info=True)

        # Data to be returned by the Celery task (becomes task.result)
        # This should also contain the email so the SSE endpoint can use it if it fetches the result directly.
        celery_task_result = {
            "email": email,
            "details": verification_details
        }
        return celery_task_result

    except Exception as e:
        logger.error(f"Task {task_id}: Unhandled exception in email_verify_task for {email}: {e}", exc_info=True)
        error_sse_data_for_redis_publish = {
            "status": "error",
            "email": email,
            "message": f"Verification task failed for {email}. Please check server logs." # Generic message for client
        }
        try:
            if not redis_client_instance:
                redis_client_instance = redis.Redis.from_url(Config.REDIS_URL)
            redis_client_instance.publish(task_id, json.dumps(error_sse_data_for_redis_publish))
            logger.info(f"Task {task_id}: Published error status to SSE for {email} due to task failure.")
        except Exception as pub_err:
            logger.error(f"Task {task_id}: Failed to publish error status to SSE for {email}: {pub_err}", exc_info=True)
        
        # Update Celery task state with metadata including the email
        self.update_state(state=states.FAILURE, meta={'exc_type': type(e).__name__, 'exc_message': str(e), 'email': email})
        raise Ignore() # Mark as failed but prevent Celery from retrying automatically
    finally:
        if redis_client_instance:
            try:
                redis_client_instance.close()
                logger.debug(f"Task {task_id}: Redis client closed for {email}.")
            except Exception as e:
                logger.error(f"Task {task_id}: Error closing Redis client for {email}: {e}", exc_info=True)
# --- End Task Logic Update ---

# ------------------------------------------------------------------------------
# Celery Beat Schedule (Use the 'celery' instance defined above)
# ------------------------------------------------------------------------------
celery.conf.beat_schedule = {
    "delete-old-files-every-day": {
        "task": "pages.schedule.delete_old_files_task",
        "schedule": crontab(hour=0, minute=0), # Run daily at midnight
    },
    "cleanup-expired-temp-users-every-day": {
        "task": "pages.schedule.cleanup_expired_temp_users_task",
        "schedule": crontab(hour=1, minute=0), # Run daily at 1 AM
        # "schedule": 86400.0, # Alternative: run every 24 hours
    },
}

# Optional: Set timezone for Celery Beat if needed
# celery.conf.timezone = 'UTC' # Or your desired timezone
