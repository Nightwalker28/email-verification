import chardet,re,os,pandas as pd
from werkzeug.utils import secure_filename
from config import logger,UPLOAD_FOLDER,providers,roles
from pages.emailverification import perform_email_verification
from pages.models import db,UserUpload,Summary
from datetime import datetime
from flask import jsonify

def detect_file_properties(filepath):
    """Detect the encoding and delimiter of the CSV file."""
    with open(filepath, 'rb') as file:
        raw_data = file.read(10000)
        encoding = chardet.detect(raw_data)['encoding']
    with open(filepath, 'r', encoding=encoding) as file:
        sample = file.read(1024)
        delimiter = next((d for d in [',', ';', '\t', '|'] if d in sample), ',')
    return encoding, delimiter

def detect_email_column(df):
    """Detects the column containing email addresses."""
    logger.info('Detecting email column...')
    for column in df.columns:
        # Check if the column name is related to email
        if re.search(r'email|e-mail|email address', column, re.IGNORECASE):
            logger.info(f'Email column detected: {column}')
            return column
    logger.warning('No email column found')
    return None

def sanitize_email(email):
    """Sanitize and validate email addresses."""
    if not isinstance(email, str):
        logger.warning(f'Invalid email format: {email}')
        return None
    sanitized_email = email.strip().lower()
    # Simple email validation check (you may need a more comprehensive check)
    if '@' not in sanitized_email or '.' not in sanitized_email:
        logger.warning(f'Invalid email address after sanitization: {sanitized_email}')
        return None
    return sanitized_email

def validate_uploaded_file(files):
    """Validate the uploaded file."""
    if 'csvFile' not in files or not files['csvFile'].filename:
        logger.error('No selected file')
        return {'error': 'No selected file'}
    file = files['csvFile']
    if not file.filename.lower().endswith('.csv'):
        logger.error('Invalid file format. Please upload a CSV file.')
        return {'error': 'Invalid file format. Please upload a CSV file.'}
    return file

def save_uploaded_file(file, user_id):
    """Save the uploaded file to the server with a unique filename."""
    original_filename = secure_filename(file.filename)
    base, ext = os.path.splitext(original_filename)
    # Create a unique filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    unique_filename = f"{base}_{timestamp}{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    # Check if the file already exists and rename if necessary
    while os.path.exists(filepath):
        unique_filename = f"{base}_{timestamp}_{len(os.listdir(UPLOAD_FOLDER)) + 1}{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)
    # Insert file information into the database using SQLAlchemy
    new_upload = UserUpload(user_id=user_id, original_filename=original_filename, unique_filename=unique_filename, filepath=filepath)
    db.session.add(new_upload)
    db.session.commit() 
    return unique_filename, filepath

def read_csv_file(filepath, encoding, delimiter):
    """Reads the CSV file based on detected properties."""
    try:
        df = pd.read_csv(filepath, encoding=encoding, delimiter=delimiter)
        logger.info('CSV file read successfully')
        return df
    except Exception as e:
        logger.error(f'Failed to read CSV: {str(e)}')
        return {'error': f'Failed to read CSV: {str(e)}'}

def process_emails(emails, force=False):
    """Processes the list of emails by performing verification."""
    results = []
    for email in emails:
        logger.info(f'Processing email: {email}')
        verification_details = perform_email_verification(email, providers, roles, force_live_check=force)
        logger.info(f'Email: {email}, Verification Details: {verification_details}')
        results.append(verification_details)
    return pd.DataFrame(results)

def update_csv_with_verification(df, result_df, filepath, filename):
    """Updates the CSV file with the verification results and saves it."""
    df[['Result', 'Provider', 'RoleBased', 'AcceptAll', 'Full Inbox', 'Temporary Mail']] = \
        result_df[['result', 'provider', 'role_based', 'accept_all', 'full_inbox', 'temporary_mail']]
    df.to_csv(filepath, index=False)
    logger.info(f'Updated CSV file saved: {filename}')

def delete_file_by_unique_filename(unique_filename, upload_folder):
    # Fetch the file entry from the database
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if not upload_entry:
        jsonify('File not found', 'danger')
        return False
    try:
        # Delete the file from the file system
        file_path = os.path.join(upload_folder, upload_entry.unique_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        # Delete the associated summary record
        summary_entry = Summary.query.filter_by(list_name=unique_filename).first()
        if summary_entry:
            db.session.delete(summary_entry)
            logger.info(f"Deleted summary record for {unique_filename}")
        # Delete the file entry from the database
        db.session.delete(upload_entry)
        db.session.commit()
        jsonify('File and summary record deleted successfully', 'success')
        return True
    except Exception as e:
        jsonify(f'Error deleting file or summary record: {str(e)}', 'danger')
        return False
   
def read_csv_as_html(unique_filename):
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    try:
        df = pd.read_csv(file_path)
        # Replace NaN values with empty strings
        df = df.fillna('')
        return df.to_html(classes='table table-striped', index=False)
    except Exception as e:
        logger.error(f"Error reading CSV file {unique_filename}: {str(e)}")
        return None

def generate_summary(result_df, list_name, user_id):
    total_emails = len(result_df)
    valid_emails = len(result_df[result_df['result'] == 'Email exists'])
    risky_emails = len(result_df[result_df['result'] == 'Risky'])
    invalid_emails = len(result_df[result_df['result'] == 'Email doesnt exists'])
    unknown_emails = len(result_df[result_df['result'].isnull()])

    summary = Summary(
        list_name=list_name,
        total_emails=total_emails,
        valid_emails=valid_emails,
        risky_emails=risky_emails,
        invalid_emails=invalid_emails,
        unknown_emails=unknown_emails,
        user_id=user_id
    )
    db.session.add(summary)
    db.session.commit()