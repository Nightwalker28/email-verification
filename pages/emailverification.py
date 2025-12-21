import re,dns,numpy as np,smtplib,socket
from flask import session
from config import logger,disposable
from pages.models import SearchedEMail,searched_email_user,datetime,db
 
def is_valid_email(email):
    if isinstance(email, float) and np.isnan(email):
        return False
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, str(email))

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange).lower().rstrip('.') for record in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except Exception as e:
        logger.error(f"Error while getting MX records: {e}")
        return []

def verify_email_sync(mx_records, email):
    full_inbox = False  # Initialize full_inbox flag as False
    for mx_record in mx_records:
        try:
            with smtplib.SMTP(mx_record, timeout=30) as server:
                server.helo('mail.acumenintelligence.tech')
                server.mail('team@acumenintelligence.tech')
                code, message = server.rcpt(email)
                if code == 250:
                    return True, full_inbox  # Email exists and inbox is not full
                elif code == 550:
                    logger.info(f"Email does not exist for {email} at {mx_record}")
                    return False, full_inbox  # Email does not exist
                elif code == 552:
                    logger.info(f"Inbox is full for {email} at {mx_record}")
                    full_inbox = True  # Set full_inbox to True if inbox is full
                elif code in [450, 451, 452]:
                    logger.info(f"Temporary server issue for {email} at {mx_record}: {message}")
                    # Continue checking other MX records if a temporary error occurs
                    continue
                else:
                    logger.warning(f"Unhandled SMTP response code {code} for {email} at {mx_record}: {message}")
                    return False, full_inbox  # Return False for unhandled codes
        except smtplib.SMTPConnectError:
            logger.error(f"SMTP connection error for MX record {mx_record}")
        except smtplib.SMTPRecipientsRefused:
            logger.error(f"Recipient address refused for MX record {mx_record}")
        except socket.gaierror as e:
            logger.error(f"DNS resolution error for MX record {mx_record}: {e}")
        except (socket.timeout, ConnectionRefusedError) as e:
            logger.error(f"Network error for MX record {mx_record}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {e}")
    return False, full_inbox  # Return if no MX record confirms existence

def verify_email(mx_records, email):
    for mx_record in mx_records:
        email_exists, full_inbox = verify_email_sync(mx_records, email)
        if email_exists:
            return email_exists, full_inbox  # Return both values if the email exists
    return False, full_inbox

def extract_provider_from_mx(mx_record, providers):
    for keyword, provider in providers.items():
        if keyword in mx_record:
            return provider
    return 'Unknown Provider'

def update_searched_email_user_count(user_id, email_id, increment_count):
    existing_entry = db.session.query(searched_email_user).filter_by(user_id=user_id, email_id=email_id).first()
    if existing_entry:
        if not increment_count:
            logger.info(f"Incrementing search_count for user {user_id} and email ID {email_id}.")
            db.session.execute(
                searched_email_user.update()
                .where(searched_email_user.c.user_id == user_id)
                .where(searched_email_user.c.email_id == email_id)
                .values(
                    timestamp=datetime.utcnow(),
                    search_count=existing_entry.search_count + 1
                )
            )
    else:
        if not increment_count:
            logger.info(f"Creating new entry for user {user_id} and email ID {email_id} with search_count=1.")
            new_entry = searched_email_user.insert().values(
                user_id=user_id,
                email_id=email_id,
                timestamp=datetime.utcnow(),
                search_count=1,          
            )
            db.session.execute(new_entry)  # Move this line inside the else block
    db.session.commit()

def perform_email_verification(email, providers, roles, force_live_check=False, increment_count=False):
    """Perform email verification and return detailed verification information."""
    logger.info(f'Starting verification for email: {email}')
    if not is_valid_email(email):
        logger.warning(f'Invalid email format: {email}')
        return {
            'result': "Invalid email format",
            'provider': 'Unknown Provider',
            'role_based': 'No',
            'accept_all': 'No',
            'full_inbox': 'No',
            'temporary_mail': 'No'}  # Update here
    # Step 1: Check the database for existing verification results
    existing_email = SearchedEMail.query.filter_by(email=email).first()
    if existing_email:
        logger.info(f'Found existing email verification result for {email}')
        return {
            'result': existing_email.result,
            'provider': existing_email.provider,
            'role_based': 'Yes' if existing_email.role_based else 'No',
            'accept_all': 'Yes' if existing_email.accept_all else 'No',
            'full_inbox': 'Yes' if existing_email.full_inbox else 'No',
            'temporary_mail': 'Yes' if existing_email.disposable else 'No'}  # Update here
    domain = email.split('@')[-1]
    username = email.split('@')[0]
    # Step 2: Check if the email domain is in the disposable list
    is_disposable = domain in disposable  # Assuming `disposable` is a set of domains
    temporary_mail = 'Yes' if is_disposable else 'No'
    # Fetch MX records
    try:
        mx_records = get_mx_records(domain)
    except Exception as e:
        logger.error(f'Error fetching MX records for domain {domain}: {e}')
        return {
            'result': "Error fetching MX records",
            'provider': 'Unknown Provider',
            'role_based': 'No',
            'accept_all': 'No',
            'full_inbox': 'No',
            'temporary_mail': temporary_mail}
    if not mx_records:
        logger.info(f'No MX records found for domain {domain}')
        return {
            'result': "No MX records found",
            'provider': 'Unknown Provider',
            'role_based': 'Yes' if username in roles else 'No',
            'accept_all': 'No',
            'full_inbox': 'No',
            'temporary_mail': temporary_mail}
    # Find provider
    provider = 'Unknown Provider'
    for mx in mx_records:
        for keyword, temp_provider in providers.items():
            if keyword in mx:
                provider = temp_provider
                break
        if provider != 'Unknown Provider':
            break 
    # Verify email existence and full inbox status
    try:
        email_exists, full_inbox = verify_email(mx_records, email)
    except Exception as e:
        logger.error(f'Error verifying email {email}: {e}')
        email_exists = False
        full_inbox = False
    # Check for catch-all/accept-all domain
    fake_email = f"blablabla@{domain}"
    try:
        accept_all, _ = verify_email(mx_records, fake_email)
    except Exception as e:
        logger.error(f'Error checking catch-all status for domain {domain}: {e}')
        accept_all = False
    # Determine result based on verification status
    result = "Email exists" if email_exists else "Email does not exist"
    if email_exists and accept_all:
        result = "Risky"
    logger.info(f'Verification result for email {email}: {result}, Provider: {provider}, Role-Based: {username in roles}, Accept-All: {accept_all}, Full Inbox: {full_inbox}, Temporary Mail: {temporary_mail}')
    # Step 3: Add or update the email verification record in SearchedEMail table
    new_email_record = SearchedEMail( 
        email=email,
        result=result,
        provider=provider,
        role_based=1 if username in roles else 0,
        accept_all=1 if accept_all else 0,
        full_inbox=1 if full_inbox else 0,
        disposable=1 if is_disposable else 0)  # Update here
    db.session.add(new_email_record)
    db.session.commit()
    # Get or create the SearchedEMail entry
    searched_email_entry = SearchedEMail.query.filter_by(email=email).first()
    # Step 4: Check if the user has already verified this email, if so update the timestamp
    user_id = session['user']
    existing_entry = db.session.query(searched_email_user).filter_by(user_id=user_id, email_id=searched_email_entry.email_id).first()
    if existing_entry:
        # Update the timestamp to the current time
        db.session.execute(
            searched_email_user.update().where(searched_email_user.c.user_id == user_id)
            .where(searched_email_user.c.email_id == searched_email_entry.email_id)
            .values(timestamp=datetime.utcnow()))
    else:
        # Create a new entry if it does not exist
        new_entry = searched_email_user.insert().values(user_id=user_id, email_id=searched_email_entry.email_id, timestamp=datetime.utcnow())
        db.session.execute(new_entry)
    db.session.commit()
    return {
        'result': result,
        'provider': provider,
        'role_based': 'Yes' if username in roles else 'No',
        'accept_all': 'Yes' if accept_all else 'No',
        'full_inbox': 'Yes' if full_inbox else 'No',
        'temporary_mail': temporary_mail}  # Return the temporary_mail status