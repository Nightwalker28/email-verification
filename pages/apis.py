import secrets
from flask import jsonify, request
from pages.emailverification import perform_email_verification
from pages.fileupload import validate_uploaded_file,save_uploaded_file,detect_file_properties,read_csv_file,delete_file_by_unique_filename,detect_email_column,sanitize_email,process_emails,update_csv_with_verification,generate_summary
from config import logger,providers,roles,db,error_response,success_response,UPLOAD_FOLDER
from pages.models import ApiKey,get_or_create_searched_email,add_verified_email_for_user
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from werkzeug.datastructures import FileStorage
from collections import OrderedDict
import json

def create_api_key(api_key_name, user_id):
    if not user_id:
        return error_response('You must be logged in to create an API key.', 403)
    if not api_key_name:
        return error_response('API key name is required.', 400)
    # Generate the plaintext API key
    plaintext_key = secrets.token_urlsafe(32)  # Secure random string
    final_plaintext_key = f"{user_id}:{plaintext_key}"  # user_id and plaintext key
    # Hash only the token portion of the key
    hashed_key = generate_password_hash(plaintext_key)  # Secure hashing
    # Create a new instance of the ApiKey model
    api_key = ApiKey(
        user_id=user_id,
        api_key=f"{user_id}:{hashed_key}",  # Store user_id and hashed token
        name=api_key_name
    )
    try:
        # Save to the database
        db.session.add(api_key)
        db.session.commit()
        # Return the success response with the plaintext API key for the user
        return success_response(
            f"API key created successfully! Your API key is: {final_plaintext_key}",
            201
        )
    except Exception as e:
        db.session.rollback()  # Rollback in case of errors
        return error_response(f'Failed to create API key: {str(e)}', 500)

def edit_api_key(api_key_id, new_name, user_id):
    if user_id:
        # Find the API key by its ID
        api_key = ApiKey.query.filter_by(id=api_key_id, user_id=user_id).first()
        if api_key:
            # Update the name of the API key
            api_key.name = new_name           
            # Commit the changes to the database
            db.session.commit()
            return success_response(f'Updated Succesfully', 201)
        return error_response(f'Api Key Not Found', 500)
    return error_response(f'You must be logged in to Edit your keys', 403)

def delete_api_key(api_key_id, user_id):
    if user_id:
        # Find the API key by its ID
        api_key = ApiKey.query.filter_by(id=api_key_id, user_id=user_id).first()
        if api_key:
            # Delete the API key from the database
            db.session.delete(api_key)
            db.session.commit()
            return success_response(f'Deleted Succesfully', 201)
        return error_response(f'Api Key Not Found', 500)
    return error_response(f'You must be logged in to Edit your keys', 403)

def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Get the Authorization header (Bearer scheme)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'API key is missing'}), 401
        # Split the header value to extract the API key
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'error': 'Invalid authorization format'}), 400  # Bad format
        api_key = parts[1]  # The actual plain API key sent by the user
        # Extract user ID and token from the provided key
        try:
            user_id, token = api_key.split(':', 1)
        except ValueError:
            return jsonify({'error': 'Invalid API key format'}), 400  # Bad format
        # Retrieve all API key records for the user
        api_key_records = ApiKey.query.filter_by(user_id=user_id).all()
        if not api_key_records:
            return jsonify({'error': 'No API keys found for the user'}), 403  # Forbidden
        # Validate the token against the hashed keys in the database
        for api_key_record in api_key_records:
            stored_user_id, stored_hashed_token = api_key_record.api_key.split(':', 1)
            if stored_user_id == user_id and check_password_hash(stored_hashed_token, token):
                # Key is valid, attach the associated user to the request context
                request.user = api_key_record.user  # Set the user based on the API key
                return func(*args, **kwargs)
        # If no valid key is found, return an error
        return jsonify({'error': 'Invalid API key'}), 403  # Forbidden
    return wrapper

def api_verify():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400  # Bad request if email is missing
        user = request.user
        # Perform email verification
        verification_details = perform_email_verification(email, providers, roles, user=user, increment_count=False)
        searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
        add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
        # Ensure verification_details is a JSON-serializable object
        return jsonify(verification_details), 200  # Return the verification details with a success status
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # Internal server error if something goes wrong
    
def api_forceverify():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'error': 'Email is required'}), 400  # Bad request if email is missing
        user = request.user
        # Perform email verification
        verification_details = perform_email_verification(email, providers, roles, user=user, force_live_check=True, increment_count=False)
        searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
        add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
        # Ensure verification_details is a JSON-serializable object
        return jsonify(verification_details), 200  # Return the verification details with a success status
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # Internal server error if something goes wrong

def api_upload():
    try:
        user = request.user
        user_id = user.user_id
        logger.info(f'The user ID for uploading file: {user_id}')
        # Validate and save file
        file = validate_uploaded_file(request.files)
        if not isinstance(file, FileStorage):
            return file  # Return error response from validation
        filename, filepath = save_uploaded_file(file, user_id)
        encoding, delimiter = detect_file_properties(filepath)
        df = read_csv_file(filepath, encoding, delimiter)
        if isinstance(df, dict):  # Handle read errors
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response(df.get('File read error', 'Error reading file'), 400)
        email_column = detect_email_column(df)
        if not email_column:
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response('No email column found', 400)
        df[email_column] = df[email_column].apply(sanitize_email)
        result_df = process_emails(df[email_column], user=user)
        # Generate summary
        summary = generate_summary(result_df, filename, user_id)
        total_emails = summary.total_emails
        valid_emails = summary.valid_emails
        risky_emails = summary.risky_emails
        invalid_emails = summary.invalid_emails
        unknown_emails = summary.unknown_emails
        # Update the CSV file with verification results
        update_csv_with_verification(df, result_df, filepath, filename)
        # Build response using OrderedDict
        response_data = OrderedDict([
            ("view_url", f"http://127.0.0.1/view_csv/{filename}"),
            ("download_url", f"http://127.0.0.1/download/{filename}"),
            ("summary", OrderedDict([
                ("total_emails", total_emails),
                ("valid_emails", valid_emails),
                ("risky_emails", risky_emails),
                ("invalid_emails", invalid_emails),
                ("unknown_emails", unknown_emails)
            ]))
        ])
        # Serialize with json.dumps to preserve order
        response_json = json.dumps(response_data)
        return response_json, 200, {'Content-Type': 'application/json'}
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}", exc_info=True)
        return error_response('An unexpected error occurred', 500)

def api_forceupload():
    try:
        user = request.user
        user_id = user.user_id
        logger.info(f'The user ID for uploading file: {user_id}')
        # Validate and save file
        file = validate_uploaded_file(request.files)
        if not isinstance(file, FileStorage):
            return file  # Return error response from validation
        filename, filepath = save_uploaded_file(file, user_id)
        encoding, delimiter = detect_file_properties(filepath)
        df = read_csv_file(filepath, encoding, delimiter)
        if isinstance(df, dict):  # Handle read errors
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response(df.get('File read error', 'Error reading file'), 400)
        email_column = detect_email_column(df)
        if not email_column:
            delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
            return error_response('No email column found', 400)
        df[email_column] = df[email_column].apply(sanitize_email)
        result_df = process_emails(df[email_column], user=user,force=True)
        # Generate summary
        summary = generate_summary(result_df, filename, user_id)
        total_emails = summary.total_emails
        valid_emails = summary.valid_emails
        risky_emails = summary.risky_emails
        invalid_emails = summary.invalid_emails
        unknown_emails = summary.unknown_emails
        # Update the CSV file with verification results
        update_csv_with_verification(df, result_df, filepath, filename)
        # Build response using OrderedDict
        response_data = OrderedDict([
            ("view_url", f"http://127.0.0.1/view_csv/{filename}"),
            ("download_url", f"http://127.0.0.1/download/{filename}"),
            ("summary", OrderedDict([
                ("total_emails", total_emails),
                ("valid_emails", valid_emails),
                ("risky_emails", risky_emails),
                ("invalid_emails", invalid_emails),
                ("unknown_emails", unknown_emails)
            ]))
        ])
        # Serialize with json.dumps to preserve order
        response_json = json.dumps(response_data)
        return response_json, 200, {'Content-Type': 'application/json'}
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}", exc_info=True)
        return error_response('An unexpected error occurred', 500)

