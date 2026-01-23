from flask import (
    Blueprint, render_template, redirect, url_for, 
    session, request, current_app, Response, stream_with_context, jsonify
) 
from sqlalchemy.exc import SQLAlchemyError
from .auth import login_required 
from pages.users import (
    reset_verification_attempts,
    get_verification_attempts,
    get_user_summary,
    check_user_access
)
from pages.models import User, get_last_checked_emails, db
from config import success_response, error_response, Config, mail_server
# Assuming email_verify_task is imported here, and celery instance from factory
from pages.schedule import email_verify_task 
import redis, json
import html

main = Blueprint("main", __name__)

@main.route("/")
def index():
    """Serves the index page. Redirects logged-in users to the home page."""
    if "user" in session:
        return redirect(url_for("main.home"))
    return render_template("index.html")

@main.route("/home")
@login_required
def home():
    """Serves the user's home/dashboard page."""
    user_id = session["user"]
    user = User.query.get(user_id)
    if not user:
         current_app.logger.warning(f"Invalid user ID in session: {user_id}. Clearing session.")
         session.clear()
         return redirect(url_for("main.index"))

    # Always fetch the last email for the home page's quick verify results table
    last_emails = get_last_checked_emails(limit=1)
    list_summary, recent_summary = get_user_summary(user.user_id)
    
    attempts = None
    if not user.is_paid:
        attempts = get_verification_attempts(user)
        reset_verification_attempts(user) 

    return render_template(
        "home.html",
        last_checked_emails=last_emails,
        attempts=attempts,
        useracc=user.email,
        list_summary=list_summary,
        recent_summary=recent_summary,
    )

@main.route("/pricing")
def pricing():
    """Serves the public pricing page."""
    return render_template("pricing.html")

@main.route("/get-pro")
def get_pro():
    """Handles the 'Get Pro' action. Redirects logged-in users to profile, others to signup."""
    if "user" in session:
        return redirect(url_for("auth.edit_profile")) 
    else:
        session["is_redirect_needed"] = True 
        return redirect(url_for("auth.manual_signup"))

@main.route("/verify", methods=["GET"])
@login_required
def verify_page():
    """Serves the email verification tool page."""
    user_id = session["user"]
    user = User.query.get(user_id)
    if not user:
         current_app.logger.warning(f"Invalid user ID in session: {user_id}. Clearing session.")
         session.clear()
         return redirect(url_for("main.index"))

    last_emails = get_last_checked_emails()
    attempts = None
    if not user.is_paid:
        attempts = get_verification_attempts(user)        
    return render_template("verify.html", last_checked_emails=last_emails, attempts=attempts)

@main.route("/verify", methods=["POST"])
@login_required
def verify_email_address():
    """Handles single email verification requests."""
    user_id = session["user"]
    user = User.query.get(user_id)
    if not user:
         current_app.logger.warning(f"Invalid user ID in session during POST: {user_id}.")
         return error_response("Invalid session. Please log in again.", 401)
    access_check = check_user_access(user, "verify_email_address") 
    if access_check:
        return access_check

    if not user.is_paid :
        user.verification_attempts += 1
        db.session.add(user)
        db.session.commit()

    new_attempts_remaining = None
    if not user.is_paid:
        limit = current_app.config.get('FREE_USER_VERIFICATION_LIMIT', 50) # Assuming 50 is default
        new_attempts_remaining = max(limit - user.verification_attempts, 0)

    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
       return error_response("Email is required.", 400)

    # enqueue and immediately return
    response_data = {}
    task = email_verify_task.apply_async(
        args=[ email, session["user"], False ],
        soft_time_limit=90
    )
    response_data["task_id"] = task.id
    if new_attempts_remaining is not None:
        response_data["attempts_remaining"] = new_attempts_remaining
    return success_response(data=response_data)


@main.route("/force-verify", methods=["POST"])
@login_required
def force_verify_email_address():
    """Handles forced (live check) single email verification requests."""
    user_id = session["user"]
    user = User.query.get(user_id)
    if not user:
         current_app.logger.warning(f"Invalid user ID in session during POST: {user_id}.")
         return error_response("Invalid session. Please log in again.", 401)
    
    access_check = check_user_access(user, "force_verify_email_address") 
    if access_check:
        return access_check

    # For forced verification, free users might also consume an attempt if not handled by access_check
    # Assuming forced verify is a pro feature or also consumes attempts for free users.
    # If it's pro-only, access_check handles it. If free users can use it with attempts, add logic here.
    # For this example, let's assume access_check handles attempt limits for force_verify or it's pro.
    # If attempts need to be updated for force_verify for free users, add similar logic as above.

    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
       return error_response("Email is required.", 400)

    # enqueue and immediately return
    response_data = {}
    task = email_verify_task.apply_async(
        args=[ email, session["user"], True ],
        soft_time_limit=90
    )
    response_data["task_id"] = task.id
    # Add attempts_remaining to response_data if applicable for force_verify
    return success_response(data=response_data)

@main.route("/status-sse/<task_id>")
@login_required
def status_sse(task_id):
    # Import celery instance and states here, or ensure they are globally available
    # For example, if your celery instance is created in 'factory.py':
    from factory import celery 
    from celery import states
    from config import logger # Assuming logger is configured in config.py

    def events():
        # First, check if the task has already completed
        task = celery.AsyncResult(task_id)
        logger.info(f"SSE: Client connected for task {task_id}. Initial state: {task.state}")

        # If the task is already done (success or failure), send the result immediately
        if task.state in [states.SUCCESS, states.FAILURE]:
            logger.info(f"SSE: Task {task_id} already completed ({task.state}). Sending result immediately.")
            try:
                if task.state == states.SUCCESS:
                    # task.result is now {"email": email_from_task, "details": details_dict}
                    completed_task_data = task.result if isinstance(task.result, dict) else {}
                    sse_data = {
                        "status": "completed",
                        "email": completed_task_data.get("email", "unknown_email_success"), 
                        "details": completed_task_data.get("details", {})
                    }
                else: # Task failed
                     result_meta = task.info if isinstance(task.info, dict) else {}
                     # Try to get email from task.info (set by update_state in task)
                     email_from_meta = result_meta.get("email")
                     
                     # Fallback to task.args if task.info doesn't have email
                     if not email_from_meta:
                         if task.args and isinstance(task.args, (list, tuple)) and len(task.args) > 0:
                             email_from_meta = task.args[0]
                         else:
                             # Final fallback if email cannot be determined
                             email_from_meta = "unknown_email_failure"
                             
                     sse_data = {
                        "status": "error",
                        "email": email_from_meta,
                        "message": result_meta.get("exc_message", "Task failed without specific message")
                     }
                yield f"data: {json.dumps(sse_data)}\n\n"
                logger.debug(f"SSE: Sent immediate result for task {task_id}: {sse_data}")
                return # Exit the generator immediately
            except Exception as e:
                logger.error(f"SSE: Error retrieving or formatting immediate result for task {task_id}: {e}", exc_info=True)
                yield f"data: {json.dumps({'status': 'error', 'email': f'task_{task_id}', 'message': 'Failed to retrieve task result'})}\n\n"
                return # Exit the generator

        # If task not yet completed, subscribe to Redis Pub/Sub
        logger.info(f"SSE: Task {task_id} not yet completed. Subscribing to Redis channel {task_id}.")
        client = redis.Redis.from_url(Config.REDIS_URL)
        sub = client.pubsub(ignore_subscribe_messages=True)
        sub.subscribe(task_id)
        try:
            for msg in sub.listen():
                logger.debug(f"SSE: Received message from Redis for task {task_id}: {msg}")
                yield f"data: {msg['data'] if isinstance(msg['data'], str) else msg['data'].decode()}\n\n"
        finally:
            logger.info(f"SSE: Client disconnected or task completed for {task_id}. Unsubscribing and closing Redis connection.")
            sub.unsubscribe(task_id) # Ensure unsubscription when client disconnects or generator exits
            sub.close()
    return Response(stream_with_context(events()),
                    mimetype="text/event-stream")

@main.route("/send-contact-email", methods=["POST"])
def send_contact_email():
    """Handles contact form submissions from the pricing page."""
    data = request.get_json()
    if not data:
        current_app.logger.warn("Contact form submission with no JSON data.")
        return jsonify({"success": False, "message": "Invalid request data. JSON expected."}), 400

    name = data.get("name", "").strip()
    email_from = data.get("email", "").strip()  # Email of the person contacting
    company = data.get("company", "Not provided").strip()
    volume = data.get("volume", "Not specified")
    message_content = data.get("message", "").strip()
    to_email_str = data.get("to_email", "").strip() # Comma-separated list of recipient emails
    subject = data.get("subject", "New Contact Form Submission").strip()

    if not all([name, email_from, message_content, to_email_str, subject]):
        missing_fields = []
        if not name: missing_fields.append("name")
        if not email_from: missing_fields.append("email")
        if not message_content: missing_fields.append("message")
        if not to_email_str: missing_fields.append("recipient emails")
        if not subject: missing_fields.append("subject")
        error_msg = f"Missing required fields: {', '.join(missing_fields)}."
        current_app.logger.warn(f"Contact form submission failed validation: {error_msg}")
        return jsonify({"success": False, "message": error_msg}), 400

    # Prepare HTML email body
    html_body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; max-width: 600px; margin: 20px auto; }}
            h2 {{ color: #0056b3; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            p {{ margin-bottom: 10px; }}
            strong {{ font-weight: bold; color: #555; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Professional Plan Inquiry</h2>
            <p><strong>Name:</strong> {html.escape(name)}</p>
            <p><strong>Email:</strong> {html.escape(email_from)}</p>
            <p><strong>Company:</strong> {html.escape(company)}</p>
            <p><strong>Expected Monthly Email Volume:</strong> {html.escape(volume)}</p>
            <p><strong>Message:</strong></p>
            <p>{html.escape(message_content).replace(chr(10), "<br>")}</p>
        </div>
    </body>
    </html>
    """

    recipient_emails = [e.strip() for e in to_email_str.split(',') if e.strip()]
    if not recipient_emails:
        current_app.logger.warn(f"Contact form submission from {email_from} had no valid recipient emails in '{to_email_str}'.")
        return jsonify({"success": False, "message": "No valid recipient emails provided."}), 400

    # Use the mail_server function for each recipient.
    # Note: mail_server sends one email at a time.
    # If you want to send a single email to multiple recipients, mail_server would need modification.
    all_sent_successfully = True
    errors_sending = []

    for recipient_email in recipient_emails:
        try:
            current_app.logger.info(f"Attempting to send contact email to: {recipient_email} from: {email_from} (user) with subject: {subject}")
            if not mail_server(recipient_email, subject, html_body):
                all_sent_successfully = False
                errors_sending.append(recipient_email)
                current_app.logger.error(f"mail_server failed to send contact email to {recipient_email} for inquiry from {email_from}.")
            else:
                current_app.logger.info(f"Successfully sent contact email to {recipient_email} for inquiry from {email_from}.")
        except Exception as e:
            all_sent_successfully = False
            errors_sending.append(recipient_email)
            current_app.logger.error(f"Exception sending contact email to {recipient_email} for inquiry from {email_from}: {e}", exc_info=True)

    if all_sent_successfully:
        return jsonify({"success": True, "message": "Message sent successfully! We will get back to you shortly."}), 200
    else:
        error_message = f"Message sent, but failed to deliver to some recipients: {', '.join(errors_sending)}. Please contact support if this issue persists."
        if len(errors_sending) == len(recipient_emails): # All failed
            error_message = "Sorry, we couldn't send your message at this time. Please try again later or contact us directly."
        
        current_app.logger.error(f"Contact form submission from {email_from} failed for recipients: {', '.join(errors_sending)}")
        return jsonify({"success": False, "message": error_message}), 500
