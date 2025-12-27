from flask import (
    Blueprint, render_template, redirect, url_for, 
    session, request, current_app
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
from pages.emailverification import perform_email_verification
from config import success_response, error_response, providers, roles

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

    show_recent_result = session.pop("show_recent_result", False)
    last_emails = get_last_checked_emails(limit=1) if show_recent_result else None
    list_summary, recent_summary = get_user_summary(user.user_id)
    
    attempts = None
    if not user.is_paid:
        attempts = get_verification_attempts(user)
        reset_verification_attempts(user) 

    return render_template(
        "home.html",
        last_checked_emails=last_emails,
        attempts=attempts,
        show_recent_result=show_recent_result,
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

    data = request.get_json()
    if not data or not data.get("email"):
         return error_response("Email is required.", 400)
    email = data.get("email").strip()

    try:
        verification_details = perform_email_verification(
            email, 
            providers, 
            roles, 
            user=user,
            commit_immediately=True
        )
        if not user.is_paid :
            user.verification_attempts += 1
            db.session.add(user)
            db.session.commit()

        session["show_recent_result"] = True
        return success_response(verification_details)

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during verification for user {user.email}: {e}")
        return error_response("A database error occurred during verification.", 500)
    except Exception as e:
        current_app.logger.error(f"Error during verification process for user {user.email}: {e}", exc_info=True)
        return error_response("An unexpected error occurred during verification.", 500)


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

    data = request.get_json()
    if not data or not data.get("email"):
         return error_response("Email is required.", 400)
    email = data.get("email").strip()

    try:
        verification_details = perform_email_verification(
            email, 
            providers, 
            roles, 
            user=user,
            force_live_check=True, 
            commit_immediately=True
        )
        session["show_recent_result"] = True
        return success_response(verification_details)

    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during force verification for user {user.email}: {e}")
        return error_response("A database error occurred during verification.", 500)
    except Exception as e:
        current_app.logger.error(f"Error during force verification process for user {user.email}: {e}", exc_info=True)
        return error_response("An unexpected error occurred during verification.", 500)