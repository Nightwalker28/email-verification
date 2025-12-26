from flask import Blueprint, render_template, redirect, url_for, session, request, jsonify, Response
from pages.users import (
    reset_verification_attempts,
    get_verification_attempts,
    get_user_summary,
    get_user_profile,
    update_user_profile,
    check_user_access
)
from pages.models import User, get_last_checked_emails
from pages.emailverification import perform_email_verification
from config import success_response, error_response, providers, roles

main = Blueprint("main", __name__)

@main.route("/")
def index():
    if "user" in session:
        return redirect(url_for("main.home"))
    return render_template("index.html")

@main.route("/home")
def home():
    if "user" in session:
        user = User.query.get(session["user"])
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
    return redirect(url_for("main.index"))

@main.route("/pricing")
def pricing():
    return render_template("pricing.html")

@main.route("/get-pro")
def get_pro():
    if "user" in session:
        return redirect(url_for("auth.edit_profile"))
    else:
        session["is_redirect_needed"] = True
        return redirect(url_for("auth.manual_signup"))

@main.route("/verify", methods=["GET"])
def verify_page():
    if "user" in session:
        from pages.users import get_verification_attempts
        user = User.query.get(session["user"])
        last_emails = get_last_checked_emails()
        attempts = None
        if not user.is_paid:
            attempts = get_verification_attempts(user)
        return render_template("verify.html", last_checked_emails=last_emails, attempts=attempts)
    return redirect(url_for("main.index"))

@main.route("/verify", methods=["POST"])
def verify_email_address():
    user = User.query.get(session["user"])
    access_check = check_user_access(user, "verify_email_address")
    if access_check:
        return access_check
    data = request.get_json()
    email = data.get("email")
    verification_details = perform_email_verification(email, providers, roles, commit_immediately=True)
    if not user.is_paid:
        user.verification_attempts += 1
        from pages.models import db
        db.session.commit()
    session["show_recent_result"] = True
    return jsonify(verification_details)

@main.route("/force-verify", methods=["POST"])
def force_verify_email_address():
    user = User.query.get(session["user"])
    access_check = check_user_access(user, "force_verify_email_address")
    if access_check:
        return access_check
    data = request.get_json()
    email = data.get("email")
    verification_details = perform_email_verification(email, providers, roles, force_live_check=True, commit_immediately=True)
    session["show_recent_result"] = True
    return jsonify(verification_details)
