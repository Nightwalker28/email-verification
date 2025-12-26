from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash
from pages.loginsignup import (
    validate_user,
    sign_in_user,
    user_exists,
    generate_nonce,
    verify_user,
    create_password_reset_email,
    send_email,
    reset_password,
    generate_reset_token,
    validate_reset_token,
    temp_exists,
)
from pages.models import User, TempUser, create_temp_user, create_user, get_or_create_google_user
from pages.users import get_user_profile, update_user_profile
from config import oauth, mail_server, success_response, error_response

auth = Blueprint("auth", __name__)

@auth.route("/manual_signin", methods=["POST"])
def manual_signin():
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()
    if user:
        if user.is_google:
            return error_response("This email is registered via Google sign-in.", 401)
        if validate_user(user, password):
            sign_in_user(user)
            redirect_url = url_for("main.home")
            if session.pop("is_redirect_needed", False):
                redirect_url = url_for("auth.edit_profile")
            return jsonify({"redirect_url": redirect_url}), 200
    return error_response("Invalid credentials.", 400)

@auth.route("/signup", methods=["GET", "POST"])
def manual_signup():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        password = request.form.get("password")
        if user_exists(email):
            return error_response("Email is already registered. Please log in.", 400)
        if temp_exists(email):
            return error_response("Please verify your email to continue.", 400)
        if not verify_user(email):
            return error_response("Email cannot be used to create an account.", 400)
        verification_token = generate_nonce()
        hashed_password = generate_password_hash(password)
        create_temp_user(first_name, last_name, email, hashed_password, verification_token)
        send_email(first_name, email, verification_token)
        return success_response("A verification email has been sent.", 200)
    return render_template("signup.html")

@auth.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    temp_user = TempUser.query.filter_by(verification_token=token).first()
    if not temp_user:
        return render_template("verification_result.html", message="Invalid or expired token.", success=False)
    new_user = create_user(temp_user.first_name, temp_user.last_name, temp_user.email, temp_user.password, temp_user.is_google)
    from pages.models import db
    db.session.delete(temp_user)
    db.session.commit()
    return render_template("verification_result.html", message="Your email has been verified! You can now log in.", success=True)

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
            return error_response("Failed to retrieve user information.", 400)
        email = user_info.get("email")
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")
        if not email:
            return error_response("Email not provided by Google.", 400)
        user = user_exists(email)
        if user:
            if user.is_google:
                sign_in_user(user)
                if session.pop("is_redirect_needed", False):
                    return redirect(url_for("auth.edit_profile"))
                return redirect(url_for("main.home"))
            else:
                return error_response("This email is registered with manual signup.", 400)
        if verify_user(email):
            new_user = get_or_create_google_user(email, first_name, last_name)
            sign_in_user(new_user)
            return redirect(url_for("main.home"))
        else:
            return error_response("Email verification failed.", 400)
    except Exception as e:
        return error_response("Authentication error.", 500)

@auth.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("user_email", None)
    return redirect(url_for("main.index"))

@auth.route("/password")
def passwordreset():
    return render_template("password.html")

@auth.route("/request_password_reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    email = data.get("emailAddress")
    if not email:
        return error_response("Email is required", 400)
    user = user_exists(email)
    if user is None:
        return error_response("User email does not exist.", 404)
    if user.is_google:
        return success_response("Logged in via Google.", 200)
    token = generate_reset_token(user)
    reset_link = url_for("auth.reset_with_token", token=token, _external=True)
    subject, html_body = create_password_reset_email(reset_link)
    mail_server(email, subject, html_body)
    return success_response("Reset instructions sent.", 200)

@auth.route("/reset/<token>", methods=["GET", "POST"])
def reset_with_token(token):
    user = validate_reset_token(token)
    if not user:
        return error_response("Invalid or expired token.", 400)
    if request.method == "POST":
        data = request.get_json()
        new_password = data.get("password")
        if not new_password:
            return error_response("New password required.", 400)
        reset_password(user, new_password)
        return success_response("Password updated!", 200)
    return render_template("reset_password.html", token=token)

@auth.route("/profile", methods=["GET", "POST"])
def edit_profile():
    if "user" not in session:
        return redirect(url_for("main.index"))
    user = User.query.get(session["user"])
    is_google_login = user.is_google
    if request.method == "POST":
        data = request.get_json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        password = data.get("password")
        update_successful = update_user_profile(user.user_id, first_name, last_name, password)
        if not update_successful:
            return error_response("Error updating profile", 400)
        return success_response("Profile updated!", 200)
    user_data = get_user_profile(user)
    if user_data:
        return render_template("profile.html", user=user_data, is_google_login=is_google_login)
    else:
        return error_response("User not found", 404)

@auth.route("/apis")
def api_keys():
    if "user" not in session:
        return redirect(url_for("main.index"))
    user_id = session.get("user")
    from pages.models import ApiKey
    api_keys = ApiKey.query.filter_by(user_id=user_id).all()
    return render_template("api_keys.html", api_keys=api_keys)

@auth.route("/create_api", methods=["POST"])
def create_api():
    api_key_name = request.form.get("name")
    user_id = session.get("user")
    from pages.apis import create_api_key
    return create_api_key(api_key_name, user_id)

@auth.route("/edit_api", methods=["POST"])
def edit_api():
    api_key_id = request.form["id"]
    new_name = request.form["name"]
    user_id = session.get("user")
    from pages.apis import edit_api_key
    return edit_api_key(api_key_id, new_name, user_id)

@auth.route("/delete_api", methods=["POST"])
def delete_api():
    api_key_id = request.form["id"]
    user_id = session.get("user")
    from pages.apis import delete_api_key
    return delete_api_key(api_key_id, user_id)
