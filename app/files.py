import os
from flask import (
    Blueprint, request, render_template, redirect, url_for, session, abort,
    send_from_directory, current_app
)
from werkzeug.datastructures import FileStorage
from sqlalchemy.exc import SQLAlchemyError
from .auth import login_required 
from pages.fileupload import (
    validate_uploaded_file,
    save_uploaded_file,
    delete_upload,
    read_file_as_html,
)
from pages.models import db, UserUpload, Summary, User
from config import UPLOAD_FOLDER, success_response, error_response, logger
from pages.users import check_user_access

files_bp = Blueprint('files', __name__)

@files_bp.route('/list')
@login_required
def list_view():
    """Displays the list of uploaded files and their summaries for the logged-in user."""
    user_id = session['user']
    user = User.query.get(user_id) 
    if not user:
        current_app.logger.warning(f"Invalid user ID in session for list view: {user_id}. Clearing session.")
        session.clear()
        return redirect(url_for('auth.manual_signin'))
    
    access_check = check_user_access(user, "list_view")
    if access_check:
        return access_check

    # Fetch uploads for the current user, ordered by date
    # Consider adding .options(joinedload(UserUpload.summary)) if you frequently access summary data
    # from sqlalchemy.orm import joinedload 
    uploads = UserUpload.query.filter_by(user_id=user_id)\
        .order_by(UserUpload.upload_date.desc()).all()

    # Fetch summaries efficiently using the list of unique filenames
    # This is good if summaries are separate, but if 1-to-1, a join might be better.
    upload_filenames = [u.unique_filename for u in uploads]
    summaries = {}
    if upload_filenames:
        summaries_query = Summary.query.filter(
            Summary.list_name.in_(upload_filenames),
            Summary.user_id == user_id
        ).all()
        summaries = {s.list_name: s for s in summaries_query}

    # Prepare data for the template
    uploads_list = []
    for u in uploads:
        s = summaries.get(u.unique_filename)
        uploads_list.append({
            'id': u.id,
            'original_filename': u.original_filename,
            'upload_date': u.upload_date.strftime('%Y-%m-%d %H:%M:%S') if u.upload_date else 'N/A',
            'unique_filename': u.unique_filename,
            'total_emails': getattr(s, 'total_emails', 0),
            'valid_emails': getattr(s, 'valid_emails', 0),
            'risky_emails': getattr(s, 'risky_emails', 0),
            'invalid_emails': getattr(s, 'invalid_emails', 0),
            'unknown_emails': getattr(s, 'unknown_emails', 0),
            'is_processed': bool(s)
        })

    return render_template('list.html', uploads=uploads_list, user=user) 

def _handle_upload(user_id: str, force_flag: bool):
    """Helper function to handle file upload, validation, saving, and task queuing."""
    
    file = request.files.get('file')

    if not file:
         return error_response("No file selected.", 400)
    validated_file_or_response = validate_uploaded_file(file)
    if not isinstance(validated_file_or_response, FileStorage):
        return validated_file_or_response

    try:
        unique_name, file_path, upload_id = save_uploaded_file(validated_file_or_response, user_id)
        logger.info(f"File saved: {file_path} (Upload ID: {upload_id}) for user {user_id}")
    except (ValueError, OSError) as e:
        logger.error(f"Error saving file for user {user_id}: {e}", exc_info=True)
        return error_response(f"Failed to save uploaded file: {e}", 500)
    except SQLAlchemyError as e:
        db.session.rollback() # Ensure rollback on DB error during save
        logger.exception(f"Database error saving file record for user {user_id}: {e}")
        return error_response("A database error occurred while saving the file record.", 500)
    except Exception as e:
        logger.exception(f"Unexpected error saving file or DB record for user {user_id}: {e}")
        return error_response("An unexpected error occurred while saving the file.", 500)

    try:
        from pages.schedule import process_uploaded_file_task 
        process_uploaded_file_task.delay(unique_name, user_id, force=force_flag)
        message = 'Force upload initiated and processing started.' if force_flag else 'File uploaded and processing started.'
        return success_response(message, 202) 
    except ImportError:
         logger.error("Could not import background task 'process_uploaded_file_task'. Processing cannot start.")
         return error_response("File uploaded, but failed to start background processing task.", 500)
    except Exception as e:
        logger.error(f"Error enqueuing background task for {unique_name}: {e}", exc_info=True)
        return error_response("File uploaded, but failed to queue the processing task.", 500)

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Route to handle standard file uploads."""
    user_id = session['user']
    return _handle_upload(user_id=user_id, force_flag=False)

@files_bp.route('/force-upload', methods=['POST'])
@login_required
def force_upload():
    """Route to handle file uploads with forced live verification."""
    user_id = session['user']
    return _handle_upload(user_id=user_id, force_flag=True)


@files_bp.route('/download/<unique_filename>', methods=['GET'])
@login_required
def download_file(unique_filename):
    """Provides the processed file (verified if available, else original) for download, checking user ownership."""
    user_id = session['user']

    upload = UserUpload.query.filter_by(unique_filename=unique_filename, user_id=user_id).first()
    if not upload:
        logger.warning(f"User {user_id} attempted to download non-existent or unauthorized file: {unique_filename}")
        abort(404, description="File not found or access denied.")

    filepath_to_send = None
    download_name_to_use = upload.original_filename
    is_verified_download = False

    if upload.verified_filepath and os.path.exists(upload.verified_filepath):
        filepath_to_send = upload.verified_filepath
        download_name_to_use = upload.original_filename
        is_verified_download = True
        logger.info(f"Preparing verified file for download: {filepath_to_send}")
    elif upload.filepath and os.path.exists(upload.filepath):
        filepath_to_send = upload.filepath
        logger.info(f"Verified file not ready/found for {unique_filename}. Preparing original file for download: {filepath_to_send}")
    else:
        logger.error(f"File data missing on disk for upload '{unique_filename}' (User: {user_id}). Paths checked: Original='{upload.filepath}', Verified='{upload.verified_filepath}'.")
        abort(404, description="File data is missing on the server.")

    try:
        directory_to_use = os.path.dirname(filepath_to_send)
        filename_to_send = os.path.basename(filepath_to_send)
    except Exception as e:
         logger.error(f"Error processing file path '{filepath_to_send}' for download: {e}")
         abort(500, description="Server error processing file path.")

    if not directory_to_use or not os.path.isdir(directory_to_use):
         logger.error(f"Download directory '{directory_to_use}' derived from '{filepath_to_send}' is not valid.")
         abort(500, description="Server configuration error prevents file download.")

    try:
        logger.info(f"User {user_id} downloading file: '{filename_to_send}' as '{download_name_to_use}' (Verified: {is_verified_download}) from dir '{directory_to_use}'")
        return send_from_directory(
            directory=directory_to_use,
            path=filename_to_send,
            as_attachment=True,
            download_name=download_name_to_use
        )
    except FileNotFoundError:
         logger.error(f"File disappeared before sending: {filepath_to_send}")
         abort(404, description="File data is missing on the server.")
    except Exception as e:
        logger.exception(f"Error sending file {filename_to_send} for user {user_id}: {e}")
        abort(500, description="An error occurred while downloading the file.")


@files_bp.route('/delete/<unique_filename>', methods=['POST'])
@login_required
def delete_file(unique_filename):
    """Deletes an uploaded file and its associated records for the logged-in user."""
    user_id = session['user']
    logger.info(f"User {user_id} attempting to delete file: {unique_filename}")

    try:
        success = delete_upload(unique_filename, user_id)

        if success:
            logger.info(f"Successfully deleted file {unique_filename} and associated data for user {user_id}")
            return success_response('File deleted successfully.', 200) 
        else:
            upload_exists = UserUpload.query.filter_by(unique_filename=unique_filename, user_id=user_id).count() > 0
            if not upload_exists:
                 logger.warning(f"Delete failed because file {unique_filename} not found or not owned by user {user_id}.")
                 return error_response('File not found or access denied.', 404)
            else:
                 logger.error(f"delete_upload function returned False for existing file {unique_filename}, user {user_id}.")
                 return error_response('Deletion failed due to an internal error. Check logs.', 500)
    except Exception as e:
        logger.exception(f"Unexpected error during delete operation for file {unique_filename}, user {user_id}: {e}")
        db.session.rollback() 
        return error_response('An unexpected error occurred during deletion.', 500)


@files_bp.route('/view/<unique_filename>', methods=['GET'])
@login_required
def view_file(unique_filename):
    """Displays the content of an uploaded file (verified if available) as an HTML table."""
    user_id = session['user']
    logger.info(f"User {user_id} attempting to view file: {unique_filename}")

    html_content = read_file_as_html(unique_filename, user_id)

    if html_content is None:
         logger.warning(f"View access denied or file not found/readable for {unique_filename}, user {user_id}.")
         abort(404, description="File not found, access denied, or error reading file content.")

    upload = UserUpload.query.filter_by(unique_filename=unique_filename, user_id=user_id).first()
    if not upload:
        logger.error(f"File content read successfully for {unique_filename}, but DB record missing for user {user_id}.")
        abort(404)

    return render_template('view_file.html', content=html_content, upload=upload)

@files_bp.route('/delete-old', methods=['POST'])
def delete_old_files():
    """Triggers a background task to clean up old files."""
    try:
        from pages.schedule import delete_old_files_task
        delete_old_files_task.delay()
        logger.info("Old files cleanup task queued.")
        return success_response('Old files cleanup task queued.', 202)
    except ImportError:
         logger.error("Could not import background task 'delete_old_files_task'.")
         return error_response("Failed to start cleanup task due to import error.", 500)
    except Exception as e:
        logger.error(f"Error enqueuing old files cleanup task: {e}", exc_info=True)
        return error_response("Failed to queue cleanup task.", 500)

