import json
import secrets
from collections import OrderedDict
from functools import wraps
from typing import Any, Callable

from flask import jsonify, request
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash

from pages.emailverification import perform_email_verification
from pages.fileupload import (
    validate_uploaded_file,
    save_uploaded_file,
    detect_file_properties,
    read_csv_file,
    delete_file_by_unique_filename,
    detect_email_column,
    sanitize_email,
    process_emails,
    generate_summary,
)
from pages.models import ApiKey, get_or_create_searched_email, add_verified_email_for_user
from config import logger, providers, roles, db, error_response, success_response, UPLOAD_FOLDER


def create_api_key(api_key_name: str, user_id: Any) -> Any:
    """
    Creates and saves an API key for the given user.
    Returns a success response with the plaintext API key or an error response.
    """
    if not user_id:
        return error_response("You must be logged in to create an API key.", 403)
    if not api_key_name:
        return error_response("API key name is required.", 400)

    # Generate a secure plaintext API key.
    plaintext_key = secrets.token_urlsafe(32)
    final_plaintext_key = f"{user_id}:{plaintext_key}"
    hashed_key = generate_password_hash(plaintext_key)
    
    api_key = ApiKey(
        user_id=user_id,
        api_key=f"{user_id}:{hashed_key}",
        name=api_key_name,
    )
    try:
        db.session.add(api_key)
        db.session.commit()
        return success_response(f"API key created successfully! Your API key is: {final_plaintext_key}", 201)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create API key: {e}", exc_info=True)
        return error_response(f"Failed to create API key: {str(e)}", 500)


def edit_api_key(api_key_id: int, new_name: str, user_id: Any) -> Any:
    """
    Edits the name of an existing API key for the given user.
    """
    if not user_id:
        return error_response("You must be logged in to edit your keys", 403)
    
    api_key = ApiKey.query.filter_by(id=api_key_id, user_id=user_id).first()
    if api_key:
        api_key.name = new_name
        try:
            db.session.commit()
            return success_response("Updated Successfully", 201)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating API key: {e}", exc_info=True)
            return error_response("Failed to update API key.", 500)
    return error_response("API Key not found", 404)


def delete_api_key(api_key_id: int, user_id: Any) -> Any:
    """
    Deletes an API key for the given user.
    """
    if not user_id:
        return error_response("You must be logged in to delete your keys", 403)
    
    api_key = ApiKey.query.filter_by(id=api_key_id, user_id=user_id).first()
    if api_key:
        try:
            db.session.delete(api_key)
            db.session.commit()
            return success_response("Deleted Successfully", 201)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting API key: {e}", exc_info=True)
            return error_response("Failed to delete API key", 500)
    return error_response("API Key not found", 404)


def require_api_key(func: Callable) -> Callable:
    """
    Decorator to require a valid API key for protected endpoints.
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "API key is missing"}), 401
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid authorization format"}), 400
        try:
            user_id, token = parts[1].split(":", 1)
        except ValueError:
            return jsonify({"error": "Invalid API key format"}), 400
        
        api_key_records = ApiKey.query.filter_by(user_id=user_id).all()
        if not api_key_records:
            return jsonify({"error": "No API keys found for the user"}), 403
        
        for record in api_key_records:
            stored_user_id, stored_hashed_token = record.api_key.split(":", 1)
            if stored_user_id == user_id and check_password_hash(stored_hashed_token, token):
                request.user = record.user
                return func(*args, **kwargs)
        return jsonify({"error": "Invalid API key"}), 403
    return wrapper


def api_verify() -> Any:
    """
    API endpoint to verify an email address.
    """
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"error": "Email is required"}), 400
        user = request.user
        verification_details = perform_email_verification(email, providers, roles, user=user, increment_count=False)
        searched_email_entry = get_or_create_searched_email(email, verification_details["result"])
        add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
        return jsonify(verification_details), 200
    except Exception as e:
        logger.error(f"Error in api_verify: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def api_forceverify() -> Any:
    """
    API endpoint to force live email verification.
    """
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"error": "Email is required"}), 400
        user = request.user
        verification_details = perform_email_verification(email, providers, roles, user=user, force_live_check=True, increment_count=False)
        searched_email_entry = get_or_create_searched_email(email, verification_details["result"])
        add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
        return jsonify(verification_details), 200
    except Exception as e:
        logger.error(f"Error in api_forceverify: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def api_upload() -> Any:
    """
    API endpoint to process file uploads and perform email verifications.
    """
    try:
        user = request.user
        user_id = user.user_id
        logger.info(f"User ID for file upload: {user_id}")
        file = validate_uploaded_file(request.files)
        if not isinstance(file, FileStorage):
            return file
        filename, filepath = save_uploaded_file(file, user_id)
        encoding, delimiter = detect_file_properties(filepath)
        df = read_csv_file(filepath, encoding, delimiter)
        if isinstance(df, dict):
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response(df.get("File read error", "Error reading file"), 400)
        email_column = detect_email_column(df)
        if not email_column:
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response("No email column found", 400)
        df[email_column] = df[email_column].apply(sanitize_email)
        result_df = process_emails(df[email_column], user=user)
        summary = generate_summary(result_df, filename, user_id)
        
        response_data = OrderedDict([
            ("view_url", f"http://127.0.0.1/view_csv/{filename}"),
            ("download_url", f"http://127.0.0.1/download/{filename}"),
            ("summary", OrderedDict([
                ("total_emails", summary.total_emails),
                ("valid_emails", summary.valid_emails),
                ("risky_emails", summary.risky_emails),
                ("invalid_emails", summary.invalid_emails),
                ("unknown_emails", summary.unknown_emails)
            ]))
        ])
        response_json = json.dumps(response_data)
        return response_json, 200, {"Content-Type": "application/json"}
    except Exception as e:
        logger.error(f"Unexpected error in api_upload: {e}", exc_info=True)
        return error_response("An unexpected error occurred", 500)


def api_forceupload() -> Any:
    """
    API endpoint to force file upload processing with live email verification.
    """
    try:
        user = request.user
        user_id = user.user_id
        logger.info(f"User ID for file upload (force): {user_id}")
        file = validate_uploaded_file(request.files)
        if not isinstance(file, FileStorage):
            return file
        filename, filepath = save_uploaded_file(file, user_id)
        encoding, delimiter = detect_file_properties(filepath)
        df = read_csv_file(filepath, encoding, delimiter)
        if isinstance(df, dict):
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response(df.get("File read error", "Error reading file"), 400)
        email_column = detect_email_column(df)
        if not email_column:
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response("No email column found", 400)
        df[email_column] = df[email_column].apply(sanitize_email)
        result_df = process_emails(df[email_column], user=user, force=True)
        summary = generate_summary(result_df, filename, user_id)
        
        response_data = OrderedDict([
            ("view_url", f"http://127.0.0.1/view_csv/{filename}"),
            ("download_url", f"http://127.0.0.1/download/{filename}"),
            ("summary", OrderedDict([
                ("total_emails", summary.total_emails),
                ("valid_emails", summary.valid_emails),
                ("risky_emails", summary.risky_emails),
                ("invalid_emails", summary.invalid_emails),
                ("unknown_emails", summary.unknown_emails)
            ]))
        ])
        response_json = json.dumps(response_data)
        return response_json, 200, {"Content-Type": "application/json"}
    except Exception as e:
        logger.error(f"Unexpected error in api_forceupload: {e}", exc_info=True)
        return error_response("An unexpected error occurred", 500)
