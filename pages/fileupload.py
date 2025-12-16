import chardet,re,os,pandas as pd
from werkzeug.utils import secure_filename
from config import logger,UPLOAD_FOLDER,providers,roles
from pages.emailverification import perform_email_verification

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

def save_uploaded_file(file):
    """Save the uploaded file to the server."""
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    return filename, filepath

def read_csv_file(filepath, encoding, delimiter):
    """Reads the CSV file based on detected properties."""
    try:
        df = pd.read_csv(filepath, encoding=encoding, delimiter=delimiter)
        logger.info('CSV file read successfully')
        return df
    except Exception as e:
        logger.error(f'Failed to read CSV: {str(e)}')
        return {'error': f'Failed to read CSV: {str(e)}'}

def process_emails(emails):
    """Processes the list of emails by performing verification."""
    results = []
    for email in emails:
        logger.info(f'Processing email: {email}')
        verification_details = perform_email_verification(email, providers, roles)
        logger.info(f'Email: {email}, Verification Details: {verification_details}')
        results.append(verification_details)
    return pd.DataFrame(results)

def update_csv_with_verification(df, result_df, filepath, filename):
    """Updates the CSV file with the verification results and saves it."""
    df[['Result', 'Provider', 'RoleBased', 'AcceptAll', 'Full Inbox', 'Temporary Mail']] = \
        result_df[['result', 'provider', 'role_based', 'accept_all', 'full_inbox', 'temporary_mail']]
    df.to_csv(filepath, index=False)
    logger.info(f'Updated CSV file saved: {filename}')