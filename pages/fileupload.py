import os
import re
import uuid
from typing import Tuple, Union, Any
import concurrent.futures
import pandas as pd
import chardet

from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask import current_app

from config import logger, UPLOAD_FOLDER, providers, roles, error_response
from pages.emailverification import perform_email_verification
from pages.models import db, UserUpload, Summary

def detect_file_properties(filepath: str, delimiters: list = [',', ';', '\t', '|']) -> Tuple[str, Union[str, None]]:
    with open(filepath, 'rb') as file:
        result = chardet.detect(file.read())
    encoding = result.get('encoding', 'utf-8')
    delimiter: Union[str, None] = None
    with open(filepath, 'r', encoding=encoding) as file:
        header = file.readline()
        for delim in delimiters:
            if delim in header:
                delimiter = delim
                break
        header = file.readline()
        for delim in delimiters:
            if delim in header:
                delimiter = delim
                break
    return encoding, delimiter

def detect_email_column(df: pd.DataFrame) -> Union[str, None]:
    email_pattern = re.compile(r'\b(email|e-mail|mail)\b', re.IGNORECASE)
    for column in df.columns:
        if email_pattern.search(column):
            return column
    return None

def sanitize_email(email: Union[str, None]) -> Union[str, None]:
    if not isinstance(email, str):
        logger.warning(f"Invalid email format: {email}")
        return None
    sanitized = email.strip().lower()
    if '@' not in sanitized or '.' not in sanitized:
        logger.warning(f"Invalid email after sanitization: {sanitized}")
        return None
    return sanitized

def validate_uploaded_file(files: dict) -> Union[FileStorage, dict]:
    file = files.get('csvFile')
    if not file or not file.filename:
        logger.error("No selected file")
        return error_response("No selected file", 400)
    if not file.filename.lower().endswith('.csv'):
        logger.error("Invalid file format. Please upload a CSV file.")
        return error_response("Invalid file format. Please upload a CSV file.", 400)
    return file

def save_uploaded_file(file: FileStorage, user_id: int) -> Tuple[str, str]:
    original_filename = secure_filename(file.filename)
    _, ext = os.path.splitext(original_filename)
    unique_filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)

    new_upload = UserUpload(
        user_id=user_id,
        original_filename=original_filename,
        unique_filename=unique_filename,
        filepath=filepath
    )
    try:
        db.session.add(new_upload)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save uploaded file: {e}", exc_info=True)
        raise
    return unique_filename, filepath

def read_csv_file(filepath: str, encoding: str, delimiter: str) -> Union[pd.DataFrame, dict]:
    try:
        df = pd.read_csv(filepath, encoding=encoding, delimiter=delimiter)
        logger.info("CSV file read successfully")
        return df
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}", exc_info=True)
        return error_response("Failed to read CSV", 400)

def process_csv_in_chunks(filepath: str, encoding: str, delimiter: str, user: Any = None, force: bool = False, app_instance=None, chunksize: int = 1000) -> pd.DataFrame:
    """
    Processes a CSV file in chunks to save memory.
    """
    results = []
    for chunk in pd.read_csv(filepath, encoding=encoding, delimiter=delimiter, chunksize=chunksize):
        email_column = detect_email_column(chunk)
        if not email_column:
            continue
        chunk[email_column] = chunk[email_column].apply(sanitize_email)
        # Process emails in the chunk using threaded processing.
        chunk_results = process_emails(chunk[email_column], user=user, force=force, app_instance=app_instance)
        results.append(chunk_results)
    if results:
        return pd.concat(results, ignore_index=True)
    return pd.DataFrame()

def process_emails(emails: pd.Series, user: Any = None, force: bool = False, app_instance=None) -> pd.DataFrame:
    """
    Processes a series of email addresses concurrently using threads.
    Each thread uses the provided Flask app_instance to create its own context.
    """
    results = []
    if app_instance is None:
        app_instance = current_app._get_current_object()
    
    def _verify(email):
        with app_instance.app_context():
            return perform_email_verification(email, providers, roles, user=user, force_live_check=force, increment=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_verify, email): email for email in emails if email}
        for future in concurrent.futures.as_completed(futures):
            email = futures[future]
            try:
                res = future.result()
            except Exception as e:
                logger.error(f"Error processing email {email}: {e}", exc_info=True)
                res = {
                    "email": email,
                    "result": "Error",
                    "provider": "",
                    "role_based": "No",
                    "accept_all": "No",
                    "full_inbox": "No",
                    "temporary_mail": "No",
                    "error": str(e)
                }
            results.append(res)
    return pd.DataFrame(results)

def update_csv_with_verification(df: pd.DataFrame, result_df: pd.DataFrame, filepath: str, filename: str) -> None:
    df[["Result", "Provider", "RoleBased", "AcceptAll", "Full Inbox", "Temporary Mail"]] = \
        result_df[["result", "provider", "role_based", "accept_all", "full_inbox", "temporary_mail"]]
    df.to_csv(filepath, index=False)
    logger.info(f"Updated CSV file saved: {filename}")

def delete_file_by_unique_filename(unique_filename: str, upload_folder: str) -> bool:
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if not upload_entry:
        return False
    try:
        file_path = os.path.join(upload_folder, upload_entry.unique_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        summary_entry = Summary.query.filter_by(list_name=unique_filename).first()
        if summary_entry:
            db.session.delete(summary_entry)
            logger.info(f"Deleted summary record for {unique_filename}")
        db.session.delete(upload_entry)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting file {unique_filename}: {e}", exc_info=True)
        return False

def read_csv_as_html(unique_filename: str) -> Union[str, None]:
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    try:
        df = pd.read_csv(file_path)
        df = df.fillna("")
        return df.to_html(classes="table table-striped", index=False)
    except Exception as e:
        logger.error(f"Error reading CSV file {unique_filename}: {e}", exc_info=True)
        return None

def generate_summary(result_df: pd.DataFrame, list_name: str, user_id: int) -> Summary:
    total_emails = len(result_df)
    valid_emails = len(result_df[result_df["result"] == "Email exists"])
    risky_emails = len(result_df[result_df["result"] == "Risky"])
    invalid_emails = len(result_df[result_df["result"] == "Email does not exist"])
    unknown_emails = len(result_df[result_df["result"].isnull()])
    
    summary = Summary(
        list_name=list_name,
        total_emails=total_emails,
        valid_emails=valid_emails,
        risky_emails=risky_emails,
        invalid_emails=invalid_emails,
        unknown_emails=unknown_emails,
        user_id=user_id
    )
    try:
        db.session.add(summary)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating summary for {list_name}: {e}", exc_info=True)
        raise
    return summary
