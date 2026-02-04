import os
import re
import uuid
import concurrent.futures
from typing import Tuple, Any, Union, List, Dict, Optional
import pandas as pd
import chardet
from flask import current_app, Flask
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from config import (
    logger, UPLOAD_FOLDER, ALLOWED_EXTENSIONS, MAX_FILE_SIZE,
    providers, roles, error_response
)
from pages.emailverification import perform_email_verification
from pages.models import db, User, UserUpload, Summary

DEFAULT_ENCODING = 'utf-8'
CHUNK_SIZE_DEFAULT = 1000
MAX_WORKERS_DEFAULT = 10
ENCODING_DETECTION_SAMPLE_SIZE = 1024 * 10
EMAIL_REGEX_PATTERN = re.compile(r'\b(e-?mail|email[_\s]?address)\b', re.IGNORECASE)

RESULT_EXISTS = "Email exists"
RESULT_RISKY = "Risky"
RESULT_DOES_NOT_EXIST = "Invalid"
RESULT_ERROR = "Error"
RESULT_UNKNOWN = "Unknown"
RESULT_DB_ERROR = "Database Error"
RESULT_VERIFICATION_ERROR = "Verification Error"
RESULT_INVALID_FORMAT = "Invalid email format"

def allowed_file(filename: str) -> bool:
    """Checks if the file extension is allowed based on ALLOWED_EXTENSIONS."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_email(email: Any) -> Optional[str]:
    """
    Cleans and performs basic validation on an email string.
    Consider using a more robust library like 'email_validator' if strict validation is needed.

    Args:
        email: The input email (can be any type).

    Returns:
        A sanitized email string in lowercase, or None if invalid/not a string.
    """
    if not isinstance(email, str):
        return None
    sanitized = email.strip().lower()
    if '@' in sanitized and '.' in sanitized and ' ' not in sanitized:
        return sanitized
    return None

def detect_email_column(df_columns: pd.Index) -> Optional[str]:
    """
    Detects the most likely email column in a DataFrame based on common names.

    Args:
        df_columns: The columns of the Pandas DataFrame.

    Returns:
        The name of the detected email column, or None if not found.
    """
    for col in df_columns:
        if isinstance(col, str) and EMAIL_REGEX_PATTERN.search(col):
            logger.debug(f"Detected email column: '{col}'")
            return col
    logger.warning("Could not automatically detect an email column from headers.")
    return None


def validate_uploaded_file(file: Optional[FileStorage]) -> Union[FileStorage, Tuple[Dict[str, str], int]]:
    """
    Validates the uploaded file based on presence, extension, and size.

    Args:
        file: The FileStorage object from the request.

    Returns:
        The validated FileStorage object if valid, otherwise an error response tuple
        suitable for returning from a Flask route (as defined by `error_response`).
    """
    if not file or not file.filename:
        logger.error("File validation failed: No file provided.")
        return error_response("No file selected for upload.", 400)

    if not allowed_file(file.filename):
        logger.error(f"File validation failed: Invalid extension for '{file.filename}'.")
        allowed_ext_str = ", ".join(ALLOWED_EXTENSIONS)
        return error_response(f"Invalid file format. Allowed formats: {allowed_ext_str}", 400)

    size = -1 
    try:
        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(0, os.SEEK_SET)
    except (AttributeError, OSError, ValueError) as e: 
        logger.warning(f"Could not determine file size accurately via stream seek/tell: {e}. Checking request content_length as fallback.")
        try:
            from flask import request
            if request.content_length is not None:
                 size = request.content_length
                 logger.info(f"Using request.content_length for file size: {size} bytes.")
            else:
                 logger.warning("request.content_length is not available.")
        except Exception as req_err:
             logger.warning(f"Error accessing request context for content_length: {req_err}")

    if size > -1 and size > MAX_FILE_SIZE:
        logger.error(f"File validation failed: '{file.filename}' size ({size} bytes) exceeds limit ({MAX_FILE_SIZE} bytes).")
        max_mb = MAX_FILE_SIZE // (1024 * 1024)
        return error_response(f"File is too large. Maximum allowed size is {max_mb}MB.", 413)
    elif size == -1:
         logger.warning(f"Could not determine file size for '{file.filename}'. Proceeding without size validation.")


    logger.info(f"File validation successful for '{file.filename}' (Size: {size if size > -1 else 'unknown'} bytes).")
    return file 

def save_uploaded_file(file: FileStorage, user_id: int) -> Tuple[str, str, int]:
    """
    Saves the uploaded file with a unique name and records it in the database.

    Args:
        file: The validated FileStorage object.
        user_id: The ID of the user uploading the file.

    Returns:
        A tuple containing (unique_filename, full_filepath, upload_id).

    Raises:
        ValueError: If UPLOAD_FOLDER is not configured.
        OSError: If saving the file fails.
        Exception: If recording to the database fails (after attempting cleanup).
    """
    original_filename = secure_filename(file.filename)
    _, ext = os.path.splitext(original_filename)
    unique_filename = f"{uuid.uuid4()}{ext}"

    if not UPLOAD_FOLDER or not os.path.isdir(UPLOAD_FOLDER):
        logger.critical(f"UPLOAD_FOLDER ('{UPLOAD_FOLDER}') is not configured or is not a valid directory!")
        raise ValueError("Upload folder configuration is invalid or missing.")

    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        file.save(filepath)
        logger.info(f"File saved: '{filepath}' (Original: '{original_filename}')")
    except OSError as e:
        logger.exception(f"Failed to save file '{filepath}'. Error: {e}")
        raise 

    upload = UserUpload(
        user_id=user_id,
        original_filename=original_filename,
        unique_filename=unique_filename,
        filepath=filepath
    )
    try:
        db.session.add(upload)
        db.session.commit()
        upload_id = upload.id
        if upload_id is None:
             logger.error(f"Failed to get upload_id for '{unique_filename}' after commit.")
             raise ValueError("Failed to retrieve upload ID after database commit.")
        logger.info(f"Upload record created for '{unique_filename}' with ID {upload_id}.")
        return unique_filename, filepath, upload_id
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Failed to record upload for '{unique_filename}' in database. Rolling back.")
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.warning(f"Cleaned up orphaned file due to DB error: '{filepath}'")
        except OSError as cleanup_err:
            logger.error(f"Failed to clean up orphaned file '{filepath}'. Error: {cleanup_err}")
        raise 


def detect_csv_properties(filepath: str, delimiters: List[str] = [',', ';', '\t', '|']) -> Tuple[str, str]:
    """
    Detects the encoding (using a sample) and delimiter of a CSV file.

    Args:
        filepath: The path to the CSV file.
        delimiters: A list of possible delimiters to check.

    Returns:
        A tuple containing (detected_encoding, detected_delimiter).

    Raises:
        FileNotFoundError: If the filepath does not exist.
    """
    detected_encoding = DEFAULT_ENCODING
    try:
        with open(filepath, 'rb') as f:
            sample = f.read(ENCODING_DETECTION_SAMPLE_SIZE)
        if not sample:
             logger.warning(f"File '{os.path.basename(filepath)}' is empty or could not read sample. Using default encoding.")
             return detected_encoding, ','

        detection = chardet.detect(sample)
        if detection and detection['encoding'] and detection['confidence'] is not None and detection['confidence'] > 0.7:
             detected_encoding = detection['encoding']
             if detected_encoding.lower() == 'ascii':
                 detected_encoding = DEFAULT_ENCODING
        logger.info(f"Detected encoding for '{os.path.basename(filepath)}': {detected_encoding} (Confidence: {detection.get('confidence')})")
    except FileNotFoundError:
        logger.error(f"File not found during encoding detection: '{filepath}'")
        raise
    except Exception as e:
        logger.warning(f"Could not detect encoding for '{os.path.basename(filepath)}', using default '{DEFAULT_ENCODING}'. Error: {e}")
        detected_encoding = DEFAULT_ENCODING

    detected_delimiter = ','
    try:
        with open(filepath, 'r', encoding=detected_encoding, errors='ignore') as f:
            header = ""
            for line in f:
                header = line.strip()
                if header:
                    break
            if header:
                delimiter_counts = {d: header.count(d) for d in delimiters}
                valid_delimiters = {d: c for d, c in delimiter_counts.items() if c > 0}
                if valid_delimiters:
                    detected_delimiter = max(valid_delimiters, key=valid_delimiters.get)
                else:
                    logger.warning(f"No common delimiters {delimiters} found in header of '{os.path.basename(filepath)}'. Using default ','. Header sample: '{header[:100]}'")
            else:
                 logger.warning(f"File '{os.path.basename(filepath)}' seems empty or contains only whitespace. Using default delimiter ','.")

        logger.info(f"Detected delimiter for '{os.path.basename(filepath)}': '{detected_delimiter}'")
    except Exception as e:
        logger.warning(f"Could not detect delimiter for '{os.path.basename(filepath)}', using default ','. Error: {e}")
        detected_delimiter = ','

    return detected_encoding, detected_delimiter


def read_excel_file(filepath: str) -> pd.DataFrame:
    """Reads an Excel file (xls, xlsx) into a pandas DataFrame."""
    try:
        df = pd.read_excel(filepath, engine=None)
        logger.info(f"Excel file '{os.path.basename(filepath)}' read successfully.")
        return df
    except FileNotFoundError:
        logger.error(f"Excel file not found: {filepath}")
        raise
    except ImportError as e:
         logger.error(f"Missing Excel engine for '{filepath}'. Install openpyxl and/or xlrd. Error: {e}")
         raise
    except Exception as e:
        logger.exception(f"Failed to read Excel file: {filepath}. Error: {e}")
        raise


def read_and_sanitize_emails(df: pd.DataFrame) -> pd.Series:
    """
    Detects the email column, sanitizes emails, drops duplicates and NaNs.

    Args:
        df: Input DataFrame.

    Returns:
        A Pandas Series containing unique, sanitized, non-null email addresses.
        Returns an empty Series if no email column is found or no valid emails exist.
    """
    email_col = detect_email_column(df.columns)
    if not email_col:
        logger.warning("No email column detected in the provided DataFrame/chunk.")
        return pd.Series(dtype=str)

    if email_col not in df.columns:
         logger.error(f"Detected email column '{email_col}' not found in DataFrame columns: {list(df.columns)}.")
         return pd.Series(dtype=str)

    if df[email_col].isnull().all():
        logger.debug(f"Email column '{email_col}' contains only null values.")
        return pd.Series(dtype=str)

    sanitized_emails = (
        df[email_col]
        .apply(sanitize_email)
        .dropna()
        .astype(str)
        .drop_duplicates()
        .reset_index(drop=True)
    )

    logger.debug(f"Extracted and sanitized {len(sanitized_emails)} unique emails from column '{email_col}'.")
    return sanitized_emails


def process_emails_concurrently(emails: pd.Series, user: User, force: bool = False,
                                app_instance: Optional[Flask] = None) -> pd.DataFrame:
    """
    Performs email verification concurrently using a ThreadPoolExecutor.
    Relies on the caller (Celery task) to commit the final transaction.
    """
    if emails.empty:
        logger.info("No emails provided for verification.")
        return pd.DataFrame(columns=['email', 'result', 'details', 'error'])

    effective_app = app_instance or current_app._get_current_object()
    if not effective_app:
         logger.error("Cannot process emails: No Flask app context available.")
         results = [{"email": e, "result": RESULT_ERROR, "details": None, "error": "App context unavailable"} for e in emails]
         return pd.DataFrame(results)

    max_workers = effective_app.config.get('MAX_EMAIL_VERIFICATION_WORKERS', MAX_WORKERS_DEFAULT)
    results_list = []
    total_emails = len(emails)
    logger.info(f"Starting concurrent verification for {total_emails} unique emails using up to {max_workers} workers...")

    def _verify_email_with_context(email_to_verify: str):
        """Worker function to verify a single email within its own app context."""
        with effective_app.app_context():
            try:
                verification_result_dict = perform_email_verification(
                    email=email_to_verify,
                    providers=providers,
                    roles=roles,
                    user=user,
                    force_live_check=force,
                    increment=False,
                    commit_immediately=False
                )
                return {
                    "email": email_to_verify,
                    "result": verification_result_dict.get("result", RESULT_ERROR),
                    "provider": verification_result_dict.get("provider"),
                    "role_based": verification_result_dict.get("role_based"),
                    "accept_all": verification_result_dict.get("accept_all"),
                    "full_inbox": verification_result_dict.get("full_inbox"),
                    "disposable": verification_result_dict.get("temporary_mail"),
                    "details": verification_result_dict.get("details"),
                    "error": verification_result_dict.get("error")
                }
            except Exception as ex:
                logger.error(f"Verification task failed unexpectedly for {email_to_verify}: {ex}", exc_info=False)
                return {"email": email_to_verify, "result": RESULT_VERIFICATION_ERROR, "details": None, "error": str(ex)}

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for email in emails:
             if isinstance(email, str) and email:
                 futures.append(executor.submit(_verify_email_with_context, email))

        processed_count = 0
        for future in concurrent.futures.as_completed(futures):
            try:
                result_data = future.result()
                results_list.append(result_data)
            except Exception as exc:
                logger.exception(f"Unhandled exception processing future result: {exc}")

            processed_count += 1
            if processed_count % 100 == 0 or processed_count == total_emails:
                 progress_percent = (processed_count / total_emails) * 100 if total_emails > 0 else 0
                 logger.info(f"Verification progress: {processed_count}/{total_emails} ({progress_percent:.1f}%) emails processed.")

    logger.info(f"Finished concurrent verification processing. Processed {len(results_list)} results. Awaiting final task commit.")
    results_df = pd.DataFrame(results_list)
    logger.debug(f"DataFrame columns created by process_emails_concurrently: {results_df.columns.tolist()}")
    return results_df


def process_file(filepath: str, user: User, force: bool = False,
                 app_instance: Optional[Flask] = None, chunksize: int = CHUNK_SIZE_DEFAULT) -> pd.DataFrame:
    """
    Processes an uploaded file (CSV or Excel) to extract, sanitize, and verify emails.
    This function is intended to be run in a background task.

    Args:
        filepath: Path to the uploaded file.
        user: The User object (models.User) associated with the request.
        force: Force live email verification check.
        app_instance: Flask application instance (needed for background tasks).
        chunksize: Number of rows to process per chunk (for CSV).

    Returns:
        A DataFrame containing the email verification results.
        Returns an empty DataFrame if no emails are found or processing fails.
    """
    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()
    all_sanitized_emails = pd.Series(dtype=str)

    if not isinstance(user, User):
        logger.error(f"Invalid user object provided for processing file '{filename}'. Type: {type(user)}")
        return pd.DataFrame(columns=['email', 'result', 'details', 'error'])

    try:
        if ext == '.csv':
            encoding, delimiter = detect_csv_properties(filepath)
            logger.info(f"Processing CSV '{filename}' with encoding '{encoding}', delimiter '{delimiter}', chunksize {chunksize}.")
            email_series_list = []
            chunk_count = 0
            try:
                for chunk in pd.read_csv(filepath, encoding=encoding, delimiter=delimiter,
                                         chunksize=chunksize, skipinitialspace=True,
                                         on_bad_lines='warn',
                                         low_memory=True):
                    chunk_count += 1
                    logger.debug(f"Processing chunk {chunk_count}...")
                    sanitized_chunk_emails = read_and_sanitize_emails(chunk)
                    if not sanitized_chunk_emails.empty:
                        email_series_list.append(sanitized_chunk_emails)
            except pd.errors.EmptyDataError:
                 logger.warning(f"CSV file '{filename}' is empty or contains no data.")

            if email_series_list:
                all_sanitized_emails = pd.concat(email_series_list, ignore_index=True).drop_duplicates().reset_index(drop=True)
            logger.info(f"Finished reading CSV '{filename}'. Found {len(all_sanitized_emails)} unique emails.")

        elif ext in ['.xlsx', '.xls']:
            logger.info(f"Processing Excel file '{filename}'.")
            df = read_excel_file(filepath)
            if not df.empty:
                all_sanitized_emails = read_and_sanitize_emails(df)
            else:
                 logger.warning(f"Excel file '{filename}' is empty.")
            logger.info(f"Finished reading Excel '{filename}'. Found {len(all_sanitized_emails)} unique emails.")

        else:
            logger.error(f"Unsupported file type: '{ext}' for file '{filename}'")
            return pd.DataFrame(columns=['email', 'result', 'details', 'error'])

        if all_sanitized_emails.empty:
             logger.warning(f"No valid emails found to verify in '{filename}'.")
             return pd.DataFrame(columns=['email', 'result', 'details', 'error'])

        return process_emails_concurrently(all_sanitized_emails, user, force, app_instance)

    except FileNotFoundError:
        logger.error(f"File not found during processing: '{filepath}'")
        return pd.DataFrame(columns=['email', 'result', 'details', 'error'])
    except Exception as e:
        logger.exception(f"An unexpected error occurred while processing file '{filepath}'. Error: {e}")
        return pd.DataFrame(columns=['email', 'result', 'details', 'error'])


def save_verified_file(original_df: pd.DataFrame, results_df: pd.DataFrame, original_filepath: str) -> Optional[str]:
    """
    Merges verification results back into the original DataFrame and saves to a NEW file.
    This avoids overwriting the original upload and is generally safer.

    Args:
        original_df: The original DataFrame read from the file.
        results_df: DataFrame with verification results (must have 'email' column).
        original_filepath: Path of the original uploaded file (used for naming the new file).

    Returns:
        The filepath of the newly created file with results, or None if failed.
    """
    email_col = detect_email_column(original_df.columns)
    if not email_col:
        logger.error("Cannot save verified file: Email column not found in original DataFrame.")
        return None
    if 'email' not in results_df.columns:
        logger.error("Cannot save verified file: 'email' column not found in results DataFrame.")
        return None
    if results_df.empty:
        logger.warning("Verification results are empty, skipping verified file save.")
        return None

    try:
        logger.debug(f"Starting merge process for {os.path.basename(original_filepath)}")
        temp_sanitized_col = '_sanitized_email_for_merge'
        original_df[temp_sanitized_col] = original_df[email_col].astype(str).apply(sanitize_email)

        cols_to_select = ['email', 'result', 'provider', 'role_based', 'accept_all', 'full_inbox', 'disposable']
        existing_cols = [col for col in cols_to_select if col in results_df.columns]
        results_to_merge = results_df[existing_cols].copy()

        rename_map = {
            'email': 'email_lookup',
            'result': 'Verification Result',
            'provider': 'Provider Guess',
            'role_based': 'Role-Based',
            'accept_all': 'Accept-All',
            'full_inbox': 'Inbox Full',
            'disposable': 'Disposable'
        }
        results_to_merge.rename(columns={k: v for k, v in rename_map.items() if k in existing_cols}, inplace=True)

        merged_df = original_df.merge(
            results_to_merge,
            left_on=temp_sanitized_col,
            right_on='email_lookup',
            how='left'
        )

        merged_df = merged_df.drop(columns=[temp_sanitized_col])
        if 'email_lookup' in merged_df.columns:
             merged_df = merged_df.drop(columns=['email_lookup'])

        logger.debug(f"Merge complete for {os.path.basename(original_filepath)}")

        output_dir = os.path.dirname(original_filepath)
        base_name, ext = os.path.splitext(os.path.basename(original_filepath))
        if base_name.endswith('_verified'):
             base_name = base_name[:-9]
        new_filename = f"{base_name}_verified{ext}"
        new_filepath = os.path.join(output_dir, new_filename)

        if ext == '.csv':
             merged_df.to_csv(new_filepath, index=False, encoding=DEFAULT_ENCODING)
        elif ext in ['.xlsx', '.xls']:
             merged_df.to_excel(new_filepath, index=False, engine='openpyxl')
        else:
             logger.error(f"Cannot save verified file: Unsupported extension '{ext}' for '{new_filepath}'")
             return None

        logger.info(f"Saved file with verification results: {new_filepath}")
        return new_filepath

    except KeyError as ke:
         logger.error(f"KeyError during merge/save for {os.path.basename(original_filepath)}: {ke}. Original Cols: {original_df.columns.tolist()}, Results Cols: {results_df.columns.tolist()}", exc_info=True)
         return None
    except Exception as e:
        logger.exception(f"Failed to merge results and save verified file based on '{os.path.basename(original_filepath)}'. Error: {e}")
        return None


def generate_summary(result_df: pd.DataFrame, list_name: str, user_id: int, upload_id: int) -> Optional[Summary]:
    """
    Generates and saves a summary of the email verification results to the database.
    Checks for existing summary for the upload_id and updates it if found.

    Args:
        result_df: DataFrame containing verification results (must have 'result' column).
        list_name: Name for this list/summary (e.g., unique_filename from UserUpload).
        user_id: ID of the user associated with this summary.
        upload_id: ID of the corresponding UserUpload record to link the summary.

    Returns:
        The created or updated Summary object or None if saving fails or input is invalid.
    """
    if result_df is None or not isinstance(result_df, pd.DataFrame) or 'result' not in result_df.columns:
        logger.error(f"Cannot generate summary for '{list_name}': Invalid or missing 'result' column in DataFrame.")
        return None

    if result_df.empty:
        logger.warning(f"Generating summary for '{list_name}' with 0 results.")
        total_emails = 0
        valid_emails = 0
        risky_emails = 0
        invalid_emails = 0
        unknown_emails = 0
    else:
        total_emails = len(result_df)
        results_filled = result_df['result'].fillna(RESULT_UNKNOWN)
        counts = results_filled.value_counts()

        valid_emails = counts.get(RESULT_EXISTS, 0)
        risky_emails = counts.get(RESULT_RISKY, 0)
        invalid_emails = counts.get(RESULT_DOES_NOT_EXIST, 0)
        standard_results = {RESULT_EXISTS, RESULT_RISKY, RESULT_DOES_NOT_EXIST, RESULT_UNKNOWN}
        unknown_emails = counts.get(RESULT_UNKNOWN, 0)
        for result_type, count in counts.items():
             if result_type not in standard_results:
                 unknown_emails += count

        calculated_total = valid_emails + risky_emails + invalid_emails + unknown_emails

        if calculated_total != total_emails:
            logger.warning(
                f"Summary count mismatch for '{list_name}': Calculated={calculated_total}, Total={total_emails}. "
                f"Counts: Valid={valid_emails}, Risky={risky_emails}, Invalid={invalid_emails}, Unknown={unknown_emails}. "
                f"Check 'result' column values: {counts.to_dict()}"
            )
            unknown_emails = total_emails - (valid_emails + risky_emails + invalid_emails)


    summary_data = {
        'list_name': list_name,
        'total_emails': int(total_emails),
        'valid_emails': int(valid_emails),
        'risky_emails': int(risky_emails),
        'invalid_emails': int(invalid_emails),
        'unknown_emails': int(unknown_emails),
        'user_id': user_id,
        'upload_id': upload_id
    }

    existing_summary = db.session.query(Summary).filter_by(
        upload_id=upload_id, user_id=user_id
        ).with_for_update().first()

    if existing_summary:
        logger.warning(f"Summary for upload_id {upload_id} already exists. Updating existing summary.")
        try:
            updated = False
            for key, value in summary_data.items():
                 if getattr(existing_summary, key) != value:
                     setattr(existing_summary, key, value)
                     updated = True
            if updated:
                 db.session.commit()
                 logger.info(f"Existing summary updated for list '{list_name}' (Upload ID: {upload_id}).")
            else:
                 logger.info(f"No changes needed for existing summary '{list_name}' (Upload ID: {upload_id}).")
            return existing_summary
        except Exception as e:
            db.session.rollback()
            logger.exception(f"Failed to update existing summary for list '{list_name}'. Error: {e}")
            return None
    else:
        summary = Summary(**summary_data)
        try:
            db.session.add(summary)
            db.session.commit()
            logger.info(f"New summary generated and saved for list '{list_name}' (User ID: {user_id}, Upload ID: {upload_id}).")
            return summary
        except Exception as e:
            db.session.rollback()
            logger.exception(f"Failed to save new summary for list '{list_name}'. Error: {e}")
            return None


def delete_upload(unique_filename: str, user_id: int) -> bool:
    """
    Deletes an upload record, its associated file(s) (original and verified),
    and summary, ensuring user ownership.
    Called from Flask route, needs user_id for authorization.
    """
    upload = db.session.query(UserUpload).filter_by(
        unique_filename=unique_filename, user_id=user_id
    ).with_for_update().first()

    if not upload:
        exists_other_user = db.session.query(UserUpload.id).filter(
            UserUpload.unique_filename == unique_filename,
            UserUpload.user_id != user_id
        ).scalar() is not None
        if exists_other_user:
             logger.warning(f"User {user_id} attempted to delete upload '{unique_filename}' owned by another user. Denied.")
        else:
             logger.warning(f"Attempted to delete non-existent or already deleted upload record '{unique_filename}' by user {user_id}.")
        return False

    original_filepath = upload.filepath
    verified_filepath = upload.verified_filepath
    upload_id = upload.id

    summary_deleted = False
    db_record_deleted = False
    original_file_deleted = False
    verified_file_deleted = False

    try:
        deleted_summary_count = db.session.query(Summary).filter_by(
            upload_id=upload_id, user_id=user_id
        ).delete()
        if deleted_summary_count > 0:
            summary_deleted = True
            logger.info(f"Deleted {deleted_summary_count} summary record(s) linked to upload ID {upload_id}.")
        else:
             logger.info(f"No summary records found or deleted for upload ID {upload_id}.")

        db.session.delete(upload)
        db_record_deleted = True

        if original_filepath and os.path.exists(original_filepath):
            try:
                os.remove(original_filepath)
                original_file_deleted = True
                logger.info(f"Deleted original physical file: '{original_filepath}'")
            except OSError as e:
                 logger.error(f"Failed to delete original physical file '{original_filepath}'. Error: {e}")
        elif original_filepath:
            logger.warning(f"Original physical file path recorded ('{original_filepath}') but file not found on disk.")

        if verified_filepath and os.path.exists(verified_filepath):
            try:
                os.remove(verified_filepath)
                verified_file_deleted = True
                logger.info(f"Deleted verified physical file: '{verified_filepath}'")
            except OSError as e:
                 logger.error(f"Failed to delete verified physical file '{verified_filepath}'. Error: {e}")
        elif verified_filepath:
            logger.warning(f"Verified physical file path recorded ('{verified_filepath}') but file not found on disk.")


        db.session.commit()
        logger.info(f"Successfully committed deletion of DB records for upload '{unique_filename}'.")
        return True

    except Exception as e:
        db.session.rollback()
        logger.exception(
            f"Failed during deletion transaction for upload '{unique_filename}'. Rolled back DB changes. "
            f"Status before rollback: SummaryMarkedDeleted={summary_deleted}, DBRecordMarkedDeleted={db_record_deleted}, "
            f"OriginalFileDeleted={original_file_deleted}, VerifiedFileDeleted={verified_file_deleted}. Error: {e}"
        )
        return False


def read_file_as_html(unique_filename: str, user_id: int) -> Optional[str]:
    """
    Reads a processed file (verified version if available, else original)
    associated with a user and returns its content as an HTML table. Checks ownership.
    Called from Flask route, needs user_id for authorization.
    """
    upload = UserUpload.query.filter_by(unique_filename=unique_filename, user_id=user_id).first()

    if not upload:
        logger.warning(f"User {user_id} attempted to read file '{unique_filename}' which was not found or not owned by them.")
        return None

    filepath_to_read = None
    is_verified = False
    if upload.verified_filepath and os.path.exists(upload.verified_filepath):
        filepath_to_read = upload.verified_filepath
        is_verified = True
        logger.info(f"Reading verified file for HTML view: {filepath_to_read}")
    elif upload.filepath and os.path.exists(upload.filepath):
        filepath_to_read = upload.filepath
        logger.info(f"Verified file not found or not processed yet. Reading original file for HTML view: {filepath_to_read}")
    else:
        logger.error(f"Neither verified nor original file path found on disk for upload '{unique_filename}'. Original: '{upload.filepath}', Verified: '{upload.verified_filepath}'")
        return "<p class='text-danger'>Error: The file data associated with this record could not be found on the server.</p>"

    filename = os.path.basename(filepath_to_read)

    try:
        _, ext = os.path.splitext(filepath_to_read)
        ext = ext.lower()
        df = None

        if ext == '.csv':
            encoding, delimiter = detect_csv_properties(filepath_to_read)
            logger.debug(f"Reading CSV '{filename}' for HTML view with encoding '{encoding}', delimiter '{delimiter}'.")
            df = pd.read_csv(filepath_to_read, encoding=encoding, delimiter=delimiter, on_bad_lines='warn')
        elif ext in ['.xlsx', '.xls']:
            logger.debug(f"Reading Excel '{filename}' for HTML view.")
            df = read_excel_file(filepath_to_read)
        else:
            logger.error(f"Cannot read file as HTML: Unsupported extension '{ext}' for file '{filepath_to_read}'")
            return f"<p class='text-danger'>Error: Unsupported file type ('{ext}') cannot be displayed.</p>"

        if df is None:
             logger.error(f"DataFrame is None after attempting to read '{filepath_to_read}'.")
             return "<p class='text-danger'>Error: Failed to load data from file.</p>"

        max_rows_display = 1000
        title_prefix = "" if is_verified else "Original Data"
        html_output = f"<h4>{title_prefix}</h4>"

        html_output += df.head(max_rows_display).fillna('').to_html(
            classes='table table-striped table-hover table-bordered table-sm',
            index=False,
            escape=True,
            border=0
        )
        if len(df) > max_rows_display:
            html_output += f"<p class='text-muted small'>Note: Display limited to the first {max_rows_display} rows.</p>"

        logger.info(f"Successfully read file '{filename}' and converted to HTML for user {user_id}.")
        return html_output

    except pd.errors.EmptyDataError:
         logger.warning(f"File '{filename}' is empty, returning empty table message.")
         return "<p class='text-info'>The file is empty.</p>"
    except FileNotFoundError:
         logger.error(f"File not found during read operation: '{filepath_to_read}'")
         return "<p class='text-danger'>Error: File not found during read operation.</p>"
    except Exception as e:
        logger.exception(f"Error reading file '{filename}' as HTML for user {user_id}. Error: {e}")
        return "<p class='text-danger'>An error occurred while trying to display the file content.</p>"
