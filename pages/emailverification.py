import re
import dns.resolver
import json
import smtplib
import socket
import time
from datetime import datetime, timedelta
from typing import Tuple, List, Optional, Any, Union, Dict, Callable
import uuid 

import redis
from sqlalchemy.orm.attributes import flag_modified 

from config import logger, disposable, Config
from app.ml_models import get_ml_models
from pages.models import SearchedEmail, searched_email_user, db
from pages.users import get_user_id

DEFAULT_PROVIDER = "Unknown Provider"
REDIS_MX_TTL = 3600       # 1 hour
REDIS_RISKY_TTL = 86400   # 1 day
SMTP_TIMEOUT = 30         # seconds
RETRY_DELAY = 60          # seconds for SMTP temporary errors
MAX_RETRIES = 1         

try:
    redis_client = redis.Redis.from_url(Config.REDIS_URL, decode_responses=True)
    redis_client.ping()  # Test connection on startup
    logger.info("Redis client connected successfully.")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Failed to connect to Redis: {e}", exc_info=True)
    redis_client = None 


def is_valid_email(email: str) -> bool:
    """Validates the basic format of an email address."""
    if not isinstance(email, str):
        return False
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(regex, email))


def get_mx_records(domain: str) -> List[str]:
    """
    Retrieve MX records for a domain, using Redis cache.
    Caches results for REDIS_MX_TTL seconds.
    Returns an empty list if no records are found or an error occurs.
    """
    if not redis_client:
        logger.warning("Redis client not available. Skipping MX cache lookup.")
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = sorted([(r.preference, str(r.exchange).lower().rstrip('.')) for r in answers])
            return [record[1] for record in mx_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.info(f"No MX records found for {domain} via DNS.")
            return []
        except Exception as e:
            logger.error(f"DNS lookup error for {domain}: {e}", exc_info=True)
            return []

    key = f"mx:{domain}"
    try:
        cached = redis_client.get(key)
        if cached:
            try:
                mx_list = json.loads(cached)
                logger.info(f"Retrieved MX records for {domain} from Redis.")
                return mx_list
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding cached MX records for {domain}: {e}. Fetching fresh.", exc_info=True)
        logger.info(f"Performing DNS lookup for MX records for {domain}.")
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange).lower().rstrip('.')) for r in answers])
        mx_list = [record[1] for record in mx_records]
        if mx_list:
            redis_client.set(key, json.dumps(mx_list), ex=REDIS_MX_TTL)
            logger.info(f"Cached MX records for {domain} in Redis for {REDIS_MX_TTL} seconds.")
        return mx_list
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        logger.info(f"No MX records found for {domain}. Caching empty result.")
        try:
            redis_client.set(key, json.dumps([]), ex=REDIS_MX_TTL)
        except Exception as redis_err:
            logger.error(f"Failed to cache empty MX result for {domain}: {redis_err}", exc_info=True)
        return []
    except Exception as e:
        logger.error(f"Error getting/caching MX records for {domain}: {e}", exc_info=True)
        return []


def _handle_smtp_connection(server: smtplib.SMTP, mx_record: str, smtp_config: Dict[str, Any]) -> None:
    """Handles EHLO and STARTTLS logic."""
    logger.info(f"Connecting to {mx_record}. Using EHLO/HELO hostname: '{server.local_hostname}'")
    server.ehlo()
    if smtp_config.get('use_tls') and 'starttls' in server.esmtp_features:
        try:
            server.starttls()
            server.ehlo() 
            logger.info(f"Re-issuing EHLO after STARTTLS. Using hostname: '{server.local_hostname}'")
            logger.info(f"Successfully initiated TLS with {mx_record}")
        except smtplib.SMTPException as tls_error:
            logger.warning(f"STARTTLS failed for {mx_record}: {tls_error}. Proceeding without TLS.")


def verify_email_attempt(mx_records: List[str], email: str, smtp_config: Dict[str, Any]) -> Tuple[Union[bool, str], bool, bool, str, str]:
    """
    Performs a single attempt to verify the given email via the provided MX records.
    Returns a tuple: (result, full_inbox, temp_error_flag, smtp_code, mx_host)
      - result: True (exists), False (doesn't exist), or "Unknown"
      - full_inbox: True if a 552 (mailbox full) response was encountered.
      - temp_error_flag: True if a temporary error was detected (e.g., 4xx/503/network issues).
    """
    full_inbox = False
    mail_from = smtp_config.get('mail_from', 'verifier@example.com')
    last_smtp_code = ""
    last_mx_host = ""
    for mx_record in mx_records:
        server: Optional[smtplib.SMTP] = None
        try:
            last_mx_host = mx_record
            logger.debug(f"Attempting connection to {mx_record} for {email}")
            helo_host = smtp_config.get('helo_host')
            server = smtplib.SMTP(mx_record, timeout=SMTP_TIMEOUT, local_hostname=helo_host)
            _handle_smtp_connection(server, mx_record, smtp_config)
            code, message = server.mail(mail_from)
            last_smtp_code = str(code)
            if code != 250:
                logger.warning(f"MAIL FROM <{mail_from}> failed on {mx_record}: {code} {message}. Trying next MX.")
                continue  # Try next MX record
            code, message = server.rcpt(email)
            last_smtp_code = str(code)
            logger.debug(f"RCPT TO <{email}> on {mx_record}: Code={code}, Msg={message}")
            if code in [250, 251]:
                logger.info(f"Email {email} confirmed exists via {mx_record}.")
                return True, full_inbox, False, last_smtp_code, last_mx_host
            elif code in [550, 551, 553, 554]:
                logger.info(f"Email {email} confirmed does not exist via {mx_record} (Code: {code}).")
                return False, full_inbox, False, last_smtp_code, last_mx_host
            elif code == 552:
                logger.info(f"Inbox full for {email} via {mx_record} (Code: {code}).")
                full_inbox = True
                return True, full_inbox, False, last_smtp_code, last_mx_host
            elif code == 503:
                logger.warning(f"Received 503 from {mx_record} for {email}.")
                return "Unknown", full_inbox, True, last_smtp_code, last_mx_host
            elif code in [421, 450, 451, 452] or "temporarily unavailable" in str(message).lower():
                logger.warning(f"Temporary error from {mx_record} for {email} (Code: {code}): {message}")
                return "Unknown", full_inbox, True, last_smtp_code, last_mx_host
            else:
                logger.error(f"Unhandled SMTP error code {code} from {mx_record} for {email}: {message}")
                return False, full_inbox, False, last_smtp_code, last_mx_host
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                smtplib.SMTPHeloError, socket.timeout, socket.gaierror,
                ConnectionRefusedError, OSError) as e:
            logger.error(f"Network/Connection error with MX record {mx_record} for {email}: {e}")
            return "Unknown", full_inbox, True, last_smtp_code, last_mx_host
        except Exception as e:
            logger.error(f"Unexpected error for {email} with MX {mx_record}: {e}", exc_info=True)
            return "Unknown", full_inbox, False, last_smtp_code, last_mx_host
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
    logger.warning(f"Could not determine status for {email} after trying all MX records in single attempt.")
    return "Unknown", full_inbox, False, last_smtp_code, last_mx_host


def extract_provider_from_mx(mx_records: List[str], providers: dict) -> str:
    """Identifies the email provider based on keywords in MX records."""
    if not mx_records:
        return DEFAULT_PROVIDER
    for mx_record in mx_records:
        for keyword, provider in providers.items():
            if keyword.lower() in mx_record.lower():
                return provider
        try:
            parts = mx_record.split('.')
            if len(parts) >= 2:
                potential_provider = f"{parts[-2]}.{parts[-1]}"
                return potential_provider
        except Exception:
            pass
    return DEFAULT_PROVIDER


def update_searched_email_user_count(user_id: int, email_id: int, increment: bool = True) -> None:
    """
    Updates the search count for a user-email pair in the association table.
    Uses direct SQL execution for potential efficiency and atomic increment.
    Relies on the caller to handle commit/rollback. Flushes the change.
    """
    if not user_id or not email_id:
        logger.warning(f"Invalid user_id ({user_id}) or email_id ({email_id}) for count update.")
        return
    try:
        exists_query = db.session.query(searched_email_user.c.user_id)\
            .filter_by(user_id=user_id, email_id=email_id)\
            .exists()
        if db.session.query(exists_query).scalar():
            if increment:
                logger.info(f"Incrementing search_count for user {user_id}, email {email_id}.")
                update_stmt = searched_email_user.update()\
                    .where(searched_email_user.c.user_id == user_id)\
                    .where(searched_email_user.c.email_id == email_id)\
                    .values(
                        timestamp=datetime.utcnow(),
                        search_count=searched_email_user.c.search_count + 1
                    )
                db.session.execute(update_stmt)
        else:
            logger.info(f"Creating new search count entry for user {user_id}, email {email_id}.")
            insert_stmt = searched_email_user.insert().values(
                user_id=user_id,
                email_id=email_id,
                timestamp=datetime.utcnow(),
                search_count=1
            )
            db.session.execute(insert_stmt)
        db.session.flush()
        logger.debug(f"Flushed search count update for user {user_id}, email {email_id}.")
    except Exception as e:
        logger.error(f"Error updating search count for user {user_id}, email {email_id}: {e}", exc_info=True)
        raise


def _format_result_dict(email_record: SearchedEmail) -> dict:
    """Formats the result dictionary from a SearchedEmail object."""
    ml_models = get_ml_models()
    role_threshold = float(ml_models.role_meta.get("threshold", 0.5)) if ml_models.available else 0.5
    prediction_summary = None
    if email_record.predicted_validity_score is not None:
        prediction_summary = f"{round(email_record.predicted_validity_score * 100)}% valid"
    role_ml_result = "Unknown"
    if email_record.role_score is not None:
        role_ml_result = "Yes" if email_record.role_score >= role_threshold else "No"
    return {
        "result": email_record.result or "Unknown",
        "predicted_result": email_record.predicted_result or "Unknown",
        "predicted_validity_score": email_record.predicted_validity_score,
        "predicted_risky_score": email_record.predicted_risky_score,
        "predicted_invalid_score": email_record.predicted_invalid_score,
        "prediction_summary": prediction_summary,
        "provider": email_record.provider or DEFAULT_PROVIDER,
        "provider_ml": email_record.provider_ml,
        "provider_ml_score": email_record.provider_ml_score,
        "role_based": "Yes" if email_record.role_based else "No",
        "role_ml_result": role_ml_result,
        "role_score": email_record.role_score,
        "accept_all": "Yes" if email_record.accept_all else "No",
        "full_inbox": "Yes" if email_record.full_inbox else "No",
        "temporary_mail": "Yes" if email_record.disposable else "No",
        "disposable_score": email_record.disposable_score,
        "spoofed_domain": "Yes" if email_record.spoofed_domain else "No",
        "spoof_score": email_record.spoof_score,
        "spoof_brand": email_record.spoof_brand,
}


def _prediction_payload(
    *,
    predicted_result: str,
    probabilities: dict[str, float],
    role_ml_result: str,
    role_score: Optional[float],
    disposable_score: Optional[float],
    provider_ml: Optional[str],
    provider_ml_score: Optional[float],
    spoof_score: Optional[float],
    spoof_brand: Optional[str],
) -> dict:
    validity_score = float(probabilities.get("Email exists", 0.0))
    risky_score = float(probabilities.get("Risky", 0.0))
    invalid_score = float(probabilities.get("Invalid", 0.0))
    return {
        "predicted_result": predicted_result,
        "predicted_validity_score": validity_score,
        "predicted_risky_score": risky_score,
        "predicted_invalid_score": invalid_score,
        "prediction_summary": f"{round(validity_score * 100)}% valid",
        "role_ml_result": role_ml_result,
        "role_score": role_score,
        "disposable_score": disposable_score,
        "provider_ml": provider_ml,
        "provider_ml_score": provider_ml_score,
        "spoof_score": spoof_score,
        "spoof_brand": spoof_brand,
        "spoofed_domain": bool(spoof_score and spoof_score >= 0.5),
    }


def _update_or_create_email_record(email: str, data: dict) -> SearchedEmail:
    """
    Finds an existing SearchedEmail record or prepares a new one.
    Adds the new record to the session if created.
    Updates fields on the existing record if found.
    Flushes the session to make the record (and its ID if new) available.
    """
    existing_email = db.session.query(SearchedEmail).filter_by(email=email).with_for_update().first()

    if existing_email:
        logger.info(f"Updating existing DB record for {email}")
        updated = False
        for key, value in data.items():
            if hasattr(existing_email, key) and getattr(existing_email, key) != value:
                setattr(existing_email, key, value)
                updated = True
        if updated:
            logger.debug(f"Fields updated for {email}.")
            try:
                db.session.flush()
                logger.debug(f"Flushed session after updating {email}.")
            except Exception as flush_err:
                 logger.error(f"Error flushing session after updating {email}: {flush_err}", exc_info=True)
                 db.session.rollback()
                 raise
        else:
            logger.debug(f"No changes detected for existing record {email}.")
        return existing_email
    else:
        logger.info(f"Creating new DB record for {email}")
        defaults = {
            "role_based": 0, "accept_all": 0, "full_inbox": 0, "disposable": 0,
            "provider": DEFAULT_PROVIDER, "result": "Unknown"
        }
        valid_keys = {column.key for column in SearchedEmail.__table__.columns}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        final_data = {**defaults, **filtered_data}

        new_email_record = SearchedEmail(email=email, **final_data)
        db.session.add(new_email_record)
        try:
            db.session.flush()
            logger.debug(f"Flushed session after adding {email}. ID: {new_email_record.email_id}")
        except Exception as flush_err:
             logger.error(f"Error flushing session after adding {email}: {flush_err}", exc_info=True)
             db.session.rollback()
             raise
        return new_email_record


def perform_email_verification(email: str, providers: dict, roles: dict, user: Optional[Any] = None,
                               force_live_check: bool = False, increment: bool = True,
                               commit_immediately: bool = True,
                               progress_callback: Optional[Callable[[dict], None]] = None) -> dict:
    """
    Performs email verification with optimized structure, caching, and database handling.
    Includes consolidated retry logic for temporary SMTP errors.
    """
    start_time = time.monotonic()
    logger.info(f"Starting verification for email: {email} (Force live: {force_live_check})")

    if not is_valid_email(email):
        logger.warning(f"Invalid email format: {email}")
        return {
            "result": "Invalid email format", "provider": DEFAULT_PROVIDER,
            "predicted_result": "Unknown", "predicted_validity_score": None,
            "predicted_risky_score": None, "predicted_invalid_score": None,
            "prediction_summary": None,
            "role_based": "No", "accept_all": "No", "full_inbox": "No",
            "temporary_mail": "No"
        }
    user_id = get_user_id(user)
    if not user_id:
        logger.error("User not authenticated for email verification.")
        return {
            "result": "Authentication Error", "provider": DEFAULT_PROVIDER,
            "predicted_result": "Unknown", "predicted_validity_score": None,
            "predicted_risky_score": None, "predicted_invalid_score": None,
            "prediction_summary": None,
            "role_based": "No", "accept_all": "No", "full_inbox": "No",
            "temporary_mail": "No"
        }
    domain = email.split('@')[-1].lower()
    username = email.split('@')[0].lower()
    ml_models = get_ml_models()
    role_prediction = ml_models.predict_role_based(username)
    disposable_prediction = ml_models.predict_disposable(domain)
    is_role = username in roles or bool(role_prediction and role_prediction.label)
    is_disposable = domain in disposable or bool(disposable_prediction and disposable_prediction.label)
    role_score = float(role_prediction.score) if role_prediction else None
    role_ml_result = "Yes" if role_prediction and role_prediction.label else "No"
    disposable_score = float(disposable_prediction.score) if disposable_prediction else None

    email_data = {
        "provider": DEFAULT_PROVIDER,
        "provider_ml": None,
        "provider_ml_score": None,
        "role_based": 1 if is_role else 0,
        "role_ml_result": role_ml_result,
        "role_score": role_score,
        "accept_all": 0,
        "full_inbox": 0,
        "disposable": 1 if is_disposable else 0,
        "disposable_score": disposable_score,
        "result": "Unknown",
        "predicted_result": "Unknown",
        "predicted_validity_score": None,
        "predicted_risky_score": None,
        "predicted_invalid_score": None,
        "spoofed_domain": 0,
        "spoof_score": None,
        "spoof_brand": None,
    }
    final_result_source = "Unknown"

    if not force_live_check and redis_client:
        try:
            risky_provider = redis_client.get(f"risky:{domain}")
            if risky_provider:
                logger.info(f"Domain {domain} found in Redis risky cache. Using cached 'Risky' status.")
                email_data.update({
                    "result": "Risky",
                    "provider": risky_provider,
                    "accept_all": 1,
                })
                final_result_source = "Redis Cache (Risky)"
        except Exception as e:
            logger.error(f"Redis error checking risky cache for {domain}: {e}", exc_info=True)

    if not force_live_check and final_result_source == "Unknown":
        try:
            db_record = db.session.query(SearchedEmail).filter_by(email=email).first()
            if db_record:
                logger.info(f"Found existing verification for {email} in DB. Using cached data.")
                email_data = {
                    "result": db_record.result,
                    "predicted_result": db_record.predicted_result,
                    "predicted_validity_score": db_record.predicted_validity_score,
                    "predicted_risky_score": db_record.predicted_risky_score,
                    "predicted_invalid_score": db_record.predicted_invalid_score,
                    "provider": db_record.provider,
                    "provider_ml": db_record.provider_ml,
                    "provider_ml_score": db_record.provider_ml_score,
                    "role_based": db_record.role_based,
                    "role_ml_result": "Unknown",
                    "role_score": db_record.role_score,
                    "accept_all": db_record.accept_all,
                    "full_inbox": db_record.full_inbox,
                    "disposable": db_record.disposable,
                    "disposable_score": db_record.disposable_score,
                    "spoofed_domain": db_record.spoofed_domain,
                    "spoof_score": db_record.spoof_score,
                    "spoof_brand": db_record.spoof_brand,
                }
                final_result_source = "DB Cache"
        except Exception as e:
            logger.error(f"Database error checking cache for {email}: {e}", exc_info=True)

    if final_result_source == "Unknown" or force_live_check:
        logger.info(f"Performing live verification for {email}.")
        final_result_source = "Live Check"
        mx_records = get_mx_records(domain)
        if not mx_records:
            logger.info(f"No MX records found for {domain}. Setting result.")
            email_data["result"] = "Unknown"
            email_data["provider"] = DEFAULT_PROVIDER
        else:
            email_data["provider"] = extract_provider_from_mx(mx_records, providers)
            logger.debug(f"MX records found for {domain}: {mx_records}. Provider identified as: {email_data['provider']}")
            try:
                mx_host = mx_records[0] if mx_records else ""
                provider_prediction = ml_models.predict_provider(
                    email=email,
                    domain=domain,
                    mx_host=mx_host,
                    smtp_code="",
                    force_live=force_live_check,
                    temp_error=False,
                    source="Live Check",
                )
                if provider_prediction:
                    email_data["provider_ml"] = provider_prediction.label
                    email_data["provider_ml_score"] = provider_prediction.confidence
                    if email_data["provider"] == DEFAULT_PROVIDER or provider_prediction.confidence >= 0.75:
                        email_data["provider"] = provider_prediction.label

                spoof_brand = ml_models.resolve_spoof_brand(domain)
                spoof_prediction = None
                domain_label = ml_models.domain_label(domain)
                if spoof_brand and domain_label:
                    spoof_prediction = ml_models.predict_spoof(domain_label, spoof_brand)
                if spoof_prediction:
                    email_data["spoof_score"] = spoof_prediction.score
                    email_data["spoof_brand"] = spoof_brand
                    email_data["spoofed_domain"] = 1 if spoof_prediction.label else 0

                precheck_prediction = ml_models.predict_deliverability(
                    email=email,
                    domain=domain,
                    mx_host=mx_host,
                    smtp_code="",
                    force_live=force_live_check,
                    temp_error=False,
                    source="Live Check",
                    provider=email_data["provider"],
                    accept_all=False,
                    duration_s=0.0,
                )
                if precheck_prediction and precheck_prediction.probabilities:
                    precheck_payload = _prediction_payload(
                        predicted_result=precheck_prediction.label,
                        probabilities=precheck_prediction.probabilities,
                        role_ml_result=email_data["role_ml_result"],
                        role_score=email_data["role_score"],
                        disposable_score=email_data["disposable_score"],
                        provider_ml=email_data["provider_ml"],
                        provider_ml_score=email_data["provider_ml_score"],
                        spoof_score=email_data["spoof_score"],
                        spoof_brand=email_data["spoof_brand"],
                    )
                    email_data.update(precheck_payload)
                    if progress_callback:
                        progress_callback(
                            {
                                "status": "predicted",
                                "email": email,
                                "details": {
                                    "result": "Pending live check",
                                    "provider": email_data["provider"],
                                    "role_based": "Yes" if email_data["role_based"] else "No",
                                    "role_ml_result": email_data["role_ml_result"],
                                    "accept_all": "No",
                                    "full_inbox": "No",
                                    "temporary_mail": "Yes" if email_data["disposable"] else "No",
                                    **precheck_payload,
                                },
                            }
                        )

                smtp_config = {
                    'mail_from': getattr(Config, 'SMTP_MAIL'),
                    'use_tls': getattr(Config, 'SMTP_USE_TLS', False),
                    'helo_host': getattr(Config, 'SMTP_HELO', None)
                }
                smtp_code = ""
                temp_error_seen = False
                logger.debug(f"Performing initial primary check for {email}")
                primary_result, full_inbox, primary_temp, smtp_code, mx_host = verify_email_attempt(mx_records, email, smtp_config)
                email_data["full_inbox"] = 1 if full_inbox else 0
                temp_error_seen = temp_error_seen or primary_temp
                logger.info(f"Initial primary check result: {primary_result}, TempError: {primary_temp}")
                needs_accept_all_check = (primary_result is True or primary_result == "Unknown")
                catch_all_result: Union[bool, str] = False
                catch_all_temp = False
                fake_email = f"verify-{uuid.uuid4().hex[:12]}@{domain}"
                if needs_accept_all_check:
                    logger.debug(f"Performing initial catch-all check for {domain} using {fake_email}")
                    catch_all_result, _, catch_all_temp, _, _ = verify_email_attempt(mx_records, fake_email, smtp_config)
                    temp_error_seen = temp_error_seen or catch_all_temp
                    logger.info(f"Initial catch-all check result: {catch_all_result}, TempError: {catch_all_temp}")
                else:
                    logger.debug(f"Skipping initial catch-all check because initial primary result is {primary_result}")
                if primary_temp or catch_all_temp:
                    logger.info(f"Temporary error detected (Primary: {primary_temp}, CatchAll: {catch_all_temp}). Waiting {RETRY_DELAY}s...")
                    time.sleep(RETRY_DELAY)
                    if primary_temp:
                        logger.info("Retrying primary email check.")
                        primary_result, full_inbox, primary_temp_retry, smtp_code, mx_host = verify_email_attempt(mx_records, email, smtp_config)
                        email_data["full_inbox"] = 1 if full_inbox else 0
                        temp_error_seen = temp_error_seen or primary_temp_retry
                        logger.info(f"Retry primary check result: {primary_result}, TempError: {primary_temp_retry}")
                        if primary_temp_retry:
                            logger.warning("Primary check still had temporary error after retry. Treating as Unknown.")
                            primary_result = "Unknown"
                    needs_accept_all_check_after_retry = (primary_result is True or primary_result == "Unknown")
                    if catch_all_temp:
                        if needs_accept_all_check_after_retry:
                            logger.info("Retrying catch-all check.")
                            catch_all_result, _, catch_all_temp_retry, _, _ = verify_email_attempt(mx_records, fake_email, smtp_config)
                            temp_error_seen = temp_error_seen or catch_all_temp_retry
                            logger.info(f"Retry catch-all check result: {catch_all_result}, TempError: {catch_all_temp_retry}")
                            if catch_all_temp_retry:
                                logger.warning("Catch-all check still had temporary error after retry. Treating as False.")
                                catch_all_result = False
                        else:
                            logger.info(f"Skipping catch-all retry because primary result after retry is {primary_result}")
                            catch_all_result = False
                accept_all = (catch_all_result is True)
                email_data["accept_all"] = 1 if accept_all else 0
                logger.info(f"Final accept-all determination for {domain}: {accept_all}")
                duration_s = time.monotonic() - start_time

                provider_prediction = ml_models.predict_provider(
                    email=email,
                    domain=domain,
                    mx_host=mx_host,
                    smtp_code=smtp_code,
                    force_live=force_live_check,
                    temp_error=temp_error_seen,
                    source="Live Check",
                )
                if provider_prediction:
                    email_data["provider_ml"] = provider_prediction.label
                    email_data["provider_ml_score"] = provider_prediction.confidence
                if provider_prediction and (
                    email_data["provider"] == DEFAULT_PROVIDER or provider_prediction.confidence >= 0.75
                ):
                    email_data["provider"] = provider_prediction.label

                final_prediction = ml_models.predict_deliverability(
                    email=email,
                    domain=domain,
                    mx_host=mx_host,
                    smtp_code=smtp_code,
                    force_live=force_live_check,
                    temp_error=temp_error_seen,
                    source="Live Check",
                    provider=email_data["provider"],
                    accept_all=accept_all,
                    duration_s=duration_s,
                )
                if final_prediction and final_prediction.probabilities:
                    email_data.update(
                        _prediction_payload(
                            predicted_result=final_prediction.label,
                            probabilities=final_prediction.probabilities,
                            role_ml_result=email_data["role_ml_result"],
                            role_score=email_data["role_score"],
                            disposable_score=email_data["disposable_score"],
                            provider_ml=email_data["provider_ml"],
                            provider_ml_score=email_data["provider_ml_score"],
                            spoof_score=email_data["spoof_score"],
                            spoof_brand=email_data["spoof_brand"],
                        )
                    )

                if primary_result is True:
                    if accept_all:
                        email_data["result"] = "Risky"
                        if redis_client:
                            try:
                                redis_client.set(f"risky:{domain}", email_data["provider"], ex=REDIS_RISKY_TTL)
                                logger.info(f"Domain {domain} determined Risky (Accept-All). Cached in Redis.")
                            except Exception as e:
                                logger.error(f"Failed to cache risky domain {domain} in Redis: {e}", exc_info=True)
                    else:
                        email_data["result"] = "Email exists"
                elif primary_result is False:
                    email_data["result"] = "Invalid"
                else:
                    email_data["result"] = "Unknown"

                if email_data["result"] in {"Unknown", "Verification Error"}:
                    deliverability_prediction = final_prediction
                    if deliverability_prediction and deliverability_prediction.confidence >= 0.70:
                        email_data["result"] = deliverability_prediction.label
                        final_result_source = "ML Fallback"

                logger.info(f"Live verification final result for {email}: {email_data['result']}")
            except Exception as e:
                logger.error(f"Unexpected error during live email verification process for {email}: {e}", exc_info=True)
                email_data["result"] = "Verification Error"

    email_record = None
    try:
        email_record = _update_or_create_email_record(email, email_data)
        db.session.flush()
        if email_record and email_record.email_id:
            if increment:
                update_searched_email_user_count(user_id, email_record.email_id, increment=True)
            else:
                logger.debug(f"Skipping search count increment for user {user_id}, email {email_record.email_id}.")
        else:
            logger.error(f"Could not get email_id for {email} after flush. Skipping user count update.")
        if commit_immediately:
            db.session.commit()
            logger.info(f"Committed changes for {email}.")
        else:
            logger.info(f"Flushed changes for {email}. Awaiting external commit.")
        final_result = _format_result_dict(email_record)
        duration = time.monotonic() - start_time
        logger.info(f"Verification for {email} completed in {duration:.2f}s. Result: {final_result['result']}, Source: {final_result_source}")
        return final_result
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error during final update/commit for {email}: {e}", exc_info=True)
        error_result = {
            "result": "Database Error",
            "predicted_result": email_data.get("predicted_result", "Unknown"),
            "predicted_validity_score": email_data.get("predicted_validity_score"),
            "predicted_risky_score": email_data.get("predicted_risky_score"),
            "predicted_invalid_score": email_data.get("predicted_invalid_score"),
            "prediction_summary": (
                f"{round(email_data['predicted_validity_score'] * 100)}% valid"
                if email_data.get("predicted_validity_score") is not None else None
            ),
            "provider": email_data.get("provider", DEFAULT_PROVIDER),
            "role_based": "Yes" if email_data.get("role_based") else "No",
            "role_ml_result": email_data.get("role_ml_result", "Unknown"),
            "accept_all": "Yes" if email_data.get("accept_all") else "No",
            "full_inbox": "Yes" if email_data.get("full_inbox") else "No",
            "temporary_mail": "Yes" if email_data.get("disposable") else "No"
        }
        duration = time.monotonic() - start_time
        logger.info(f"Verification for {email} failed after {duration:.2f}s due to DB error.")
        return error_result
