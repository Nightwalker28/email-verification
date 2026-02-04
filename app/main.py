from flask import (
    Blueprint, render_template, redirect, url_for, 
    session, request, current_app, Response, stream_with_context
) 
from sqlalchemy.exc import SQLAlchemyError
from .auth import login_required 
from pages.users import (
    get_user_summary,
)
from pages.models import User, get_last_checked_emails
from config import success_response, error_response, Config
from pages.schedule import email_verify_task 
import redis, json

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

    last_emails = get_last_checked_emails(limit=1)
    list_summary, recent_summary = get_user_summary(user.user_id)
    
    return render_template(
        "home.html",
        last_checked_emails=last_emails,
        useracc=user.email,
        list_summary=list_summary,
        recent_summary=recent_summary,
    )

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
    return render_template("verify.html", last_checked_emails=last_emails)

@main.route("/verify", methods=["POST"])
@login_required
def verify_email_address():
    """Handles single email verification requests."""
    user_id = session["user"]
    user = User.query.get(user_id)
    if not user:
         current_app.logger.warning(f"Invalid user ID in session during POST: {user_id}.")
         return error_response("Invalid session. Please log in again.", 401)

    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
       return error_response("Email is required.", 400)

    response_data = {}
    task = email_verify_task.apply_async(
        args=[ email, session["user"], False ],
        soft_time_limit=90
    )
    response_data["task_id"] = task.id
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

    data = request.get_json() or {}
    email = data.get("email", "").strip()
    if not email:
       return error_response("Email is required.", 400)

    response_data = {}
    task = email_verify_task.apply_async(
        args=[ email, session["user"], True ],
        soft_time_limit=90
    )
    response_data["task_id"] = task.id
    return success_response(data=response_data)

@main.route("/status-sse/<task_id>")
@login_required
def status_sse(task_id):
    from factory import celery 
    from celery import states
    from config import logger

    def events():
        task = celery.AsyncResult(task_id)
        logger.info(f"SSE: Client connected for task {task_id}. Initial state: {task.state}")

        if task.state in [states.SUCCESS, states.FAILURE]:
            logger.info(f"SSE: Task {task_id} already completed ({task.state}). Sending result immediately.")
            try:
                if task.state == states.SUCCESS:
                    completed_task_data = task.result if isinstance(task.result, dict) else {}
                    sse_data = {
                        "status": "completed",
                        "email": completed_task_data.get("email", "unknown_email_success"), 
                        "details": completed_task_data.get("details", {})
                    }
                else:
                     result_meta = task.info if isinstance(task.info, dict) else {}
                     email_from_meta = result_meta.get("email")
                     
                     if not email_from_meta:
                         if task.args and isinstance(task.args, (list, tuple)) and len(task.args) > 0:
                             email_from_meta = task.args[0]
                         else:
                             email_from_meta = "unknown_email_failure"
                             
                     sse_data = {
                        "status": "error",
                        "email": email_from_meta,
                        "message": result_meta.get("exc_message", "Task failed without specific message")
                     }
                yield f"data: {json.dumps(sse_data)}\n\n"
                logger.debug(f"SSE: Sent immediate result for task {task_id}: {sse_data}")
                return
            except Exception as e:
                logger.error(f"SSE: Error retrieving or formatting immediate result for task {task_id}: {e}", exc_info=True)
                yield f"data: {json.dumps({'status': 'error', 'email': f'task_{task_id}', 'message': 'Failed to retrieve task result'})}\n\n"
                return

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
            sub.unsubscribe(task_id)
            sub.close()
    return Response(stream_with_context(events()),
                    mimetype="text/event-stream")

