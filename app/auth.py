from flask import (
    Blueprint, render_template, request, 
    session, redirect, url_for, current_app
)
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import SQLAlchemyError
from pages.loginsignup import (
    validate_user, sign_in_user, user_exists, generate_nonce,
    verify_user, create_password_reset_email, send_email,
    reset_password, generate_reset_token, validate_reset_token, temp_exists
)
from pages.models import db, User, TempUser, create_temp_user, create_user, get_or_create_google_user
from pages.users import get_user_profile, update_user_profile
from config import oauth, mail_server, success_response, error_response

auth = Blueprint("auth", __name__)

from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            session['next_url'] = request.url 
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated_function

@auth.route("/manual_signin", methods=["POST"])
def manual_signin():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
         return error_response("Email and password are required.", 400)

    user = user_exists(email) 

    if user:
        if user.is_google:
            return error_response("This email is registered via Google sign-in. Please use Google Sign-In.", 401)
        if validate_user(user, password):
            sign_in_user(user)
            redirect_url = session.pop('next_url', url_for("main.home")) 
            if session.pop("is_redirect_needed", False):
                redirect_url = url_for("auth.edit_profile")
            return success_response(message="Login successful", data={"redirect_url": redirect_url}, status_code=200)
    return error_response("Invalid email or password.", 401)

@auth.route("/signup", methods=["GET", "POST"])
def manual_signup():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")

        if not all([first_name, email, password]):
             return error_response("First name, email, and password are required.", 400)
        if user_exists(email):
            return error_response("Email is already registered. Please log in.", 409)
        if temp_exists(email):
            return error_response("This email address is pending verification. Please check your inbox.", 409)

        if not verify_user(email):
            return error_response("This email address cannot be used for signup.", 400)

        try:
            verification_token = generate_nonce()
            hashed_password = generate_password_hash(password)
            create_temp_user(first_name, last_name, email, hashed_password, verification_token)
            send_email(first_name, email, verification_token)
            return success_response("A verification email has been sent. Please check your inbox.", 201)
        except SQLAlchemyError as e:
             current_app.logger.error(f"Database error during signup for {email}: {e}")
             db.session.rollback()
             return error_response("An error occurred during signup. Please try again later.", 500)
        except Exception as e:
             current_app.logger.error(f"Error during signup process for {email}: {e}")
             return error_response("An error occurred. Please try again later.", 500)
    return render_template("signup.html")

@auth.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    temp_user = TempUser.query.filter_by(verification_token=token).first()

    if not temp_user:
        return render_template("verification_result.html", message="Invalid or expired verification link.", success=False)

    if user_exists(temp_user.email):
         db.session.delete(temp_user)
         db.session.commit()
         return render_template("verification_result.html", message="This email is already registered. Please log in.", success=False) # Or redirect to login

    try:
        new_user = create_user(
            temp_user.first_name, temp_user.last_name, temp_user.email,
            temp_user.password, temp_user.is_google
        )
        db.session.delete(temp_user)
        db.session.commit()
        return render_template("verification_result.html", message="Your email has been verified! You can now log in.", success=True)
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during email verification for token {token}: {e}")
        return render_template("verification_result.html", message="An error occurred during verification. Please try again later.", success=False)
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error during email verification for token {token}: {e}")
        return render_template("verification_result.html", message="An unexpected error occurred. Please contact support.", success=False)


@auth.route("/google/")
def google_login():
    nonce = generate_nonce()
    session["nonce"] = nonce
    redirect_uri = url_for("auth.google_auth", _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route("/google/auth/")
def google_auth():
    try:
        token = oauth.google.authorize_access_token()
        nonce = session.pop("nonce", None)
        user_info = oauth.google.parse_id_token(token, nonce=nonce)

        if not user_info:
            current_app.logger.warning("Google OAuth: Failed to retrieve user information.")
            return redirect(url_for("main.index"))

        email = user_info.get("email")
        if not email:
             current_app.logger.warning("Google OAuth: Email not provided by Google.")
             return redirect(url_for("main.index"))
        user = user_exists(email)

        if user:
            if user.is_google:
                sign_in_user(user)
                redirect_url = session.pop('next_url', url_for("main.home"))
                if session.pop("is_redirect_needed", False):
                     redirect_url = url_for("auth.edit_profile")
                return redirect(redirect_url)
            else:
                current_app.logger.warning(f"Google OAuth: Manual account exists for {email}.")
                return redirect(url_for("main.index"))
        else:
            if verify_user(email):
                first_name = user_info.get("given_name", "")
                last_name = user_info.get("family_name", "")
                new_user = get_or_create_google_user(email, first_name, last_name)
                sign_in_user(new_user)
                redirect_url = session.pop('next_url', url_for("main.home"))
                return redirect(redirect_url)
            else:
                current_app.logger.warning(f"Google OAuth: Email verification failed for {email}.")
                return redirect(url_for("main.index"))

    except Exception as e:
        current_app.logger.error(f"Google OAuth Error: {e}", exc_info=True)
        return redirect(url_for("main.index"))

@auth.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    session.pop("user_email", None)
    session.pop("nonce", None)
    session.pop("next_url", None)
    session.pop("is_redirect_needed", None)
    return redirect(url_for("main.index"))

@auth.route("/password")
def passwordreset():
    return render_template("password.html")

@auth.route("/request_password_reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    if not data or "emailAddress" not in data:
         return error_response("Email address is required.", 400)

    email = data.get("emailAddress", "").strip()
    if not email:
        return error_response("Email address cannot be empty.", 400)

    user = user_exists(email)
    if user and not user.is_google:
        try:
            token = generate_reset_token(user)
            reset_link = url_for("auth.reset_with_token", token=token, _external=True)
            subject, html_body = create_password_reset_email(reset_link)
            mail_server(email, subject, html_body)
        except Exception as e:
             current_app.logger.error(f"Error requesting password reset for {email}: {e}")
    elif user and user.is_google:
         current_app.logger.info(f"Password reset requested for Google user {email}.")
    else:
         current_app.logger.info(f"Password reset requested for non-existent email {email}.")

    return success_response("If an account exists for this email, password reset instructions have been sent.", 200)


@auth.route("/reset/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    user = validate_reset_token(token)

    if not user:
        return redirect(url_for('auth.passwordreset'))

    if request.method == "POST":
        data = request.get_json()
        new_password = data.get("password") if data else None

        if not new_password:
            return error_response("New password is required.", 400)

        # Add check: prevent using the old password? (Requires storing previous hashes or comparing)

        try:
            reset_password(user, new_password)
            return success_response({"message": "Password updated successfully!", "redirect_url": url_for("main.index")}, 200)
        except Exception as e:
             current_app.logger.error(f"Error resetting password with token for user {user.email}: {e}")
             return error_response("An error occurred while updating your password. Please try again.", 500)

    return render_template("reset_password.html", token=token)


@auth.route("/profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = User.query.get(session["user"])
    if not user:
         session.clear()
         return redirect(url_for("main.index"))

    is_google_login = user.is_google

    if request.method == "POST":
        data = request.get_json()
        if not data:
             return error_response("Invalid request data.", 400)

        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()
        password = data.get("password")

        if not first_name:
             return error_response("First name cannot be empty.", 400)

        try:
            update_successful = update_user_profile(user.user_id, first_name, last_name, password if not is_google_login else None)
            if not update_successful:
                return error_response("Error updating profile. Please try again.", 400)
            return success_response("Profile updated successfully!", 200)
        except Exception as e:
             current_app.logger.error(f"Error updating profile for user {user.email}: {e}")
             return error_response("An internal error occurred while updating the profile.", 500)

    user_data = get_user_profile(user)
    if user_data:
        return render_template("profile.html", user=user_data, is_google_login=is_google_login)
    else:
        current_app.logger.error(f"Could not retrieve profile data for user ID {session['user']}")
        return error_response("User profile data not found.", 404)