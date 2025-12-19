from config import logger,app,UPLOAD_FOLDER,oauth,providers,roles,mail_server,success_response,error_response,os
from pages.users import reset_verification_attempts,get_verification_attemps,get_user_profile,update_user_profile,check_user_access,get_user_summary
from pages.models import create_temp_user, get_or_create_searched_email,add_verified_email_for_user,get_last_checked_emails,db,User,UserUpload,Summary,TempUser,create_user
from pages.schedule import delete_old_files,schedule_task,cleanup_expired_sessions,cleanup_expired_temp_users
from pages.emailverification import perform_email_verification
from pages.fileupload import validate_uploaded_file,detect_file_properties,save_uploaded_file,read_csv_file,detect_email_column,sanitize_email,process_emails,update_csv_with_verification,delete_file_by_unique_filename,read_csv_as_html,generate_summary
from pages.loginsignup import create_password_reset_email, send_email, validate_user,sign_in_user,user_exists,generate_nonce,validate_reset_token,reset_password,generate_reset_token,verify_user,temp_exists
from flask import session,redirect,url_for,render_template,request,send_from_directory,jsonify
from werkzeug.security import generate_password_hash
from werkzeug.datastructures import FileStorage

@app.route('/')
def indexview():
     # Check if the user is in session
    if 'user' in session:  # Replace 'user_id' with the appropriate key used for session management
        return redirect(url_for('homeview'))  # Redirect to the home view if the user is logged in
    else:
        return render_template('index.html')

@app.route('/home')
def homeview():
    if 'user' in session:
        # Determine if the user just performed an email verification
        show_recent_result = session.pop('show_recent_result', False)        
        # Fetch the most recent email verification (only if needed)
        res = get_last_checked_emails(limit=1) if show_recent_result else None
        # Check user's verification attempts (if the user is not paid)
        attempts = None
        user = User.query.get(session['user'])
        list_summary, recent_summary = get_user_summary(user.user_id)
        useracc=user.email
        if not user.is_paid:
            attempts = get_verification_attemps(user)
            reset_verification_attempts(user)
        return render_template('home.html', last_checked_emails=res, attempts=attempts, show_recent_result=show_recent_result,useracc=useracc,list_summary=list_summary, recent_summary=recent_summary)   
    return redirect('/')

@app.route('/verify')
def verifyview():     
    if 'user' in session:
        user = User.query.get(session['user'])
        last_checked_emails = get_last_checked_emails()
        attempts = None
        if not user.is_paid:
            attempts = get_verification_attemps(user)      
        return render_template('verify.html', last_checked_emails=last_checked_emails, attempts=attempts)
    else:
        return redirect('/')

@app.route('/list')
def listview():
    if 'user' in session:
        user = User.query.get(session['user'])
        access_check = check_user_access(user, 'listview')
        if access_check:
            return access_check  # If access check fails, return that response
        user_id = user.user_id
        # Step 1: Get all UserUpload entries for the user
        uploads = UserUpload.query.filter_by(user_id=user_id).order_by(UserUpload.upload_date.desc()).all()
        # Step 2: Get corresponding Summary entries based on unique_filename
        unique_filenames = [upload.unique_filename for upload in uploads]
        summaries = Summary.query.filter(Summary.list_name.in_(unique_filenames)).all()
        # Create a dictionary to map summaries to their unique filenames
        summary_map = {summary.list_name: summary for summary in summaries}
        # Prepare the uploads list with summaries
        uploads_list = []
        for upload in uploads:
            summary = summary_map.get(upload.unique_filename)
            uploads_list.append({
                'id': upload.id,  # Add the unique ID here
                'original_filename': upload.original_filename,
                'upload_date': upload.upload_date,
                'unique_filename': upload.unique_filename,
                'total_emails': summary.total_emails if summary else 0,
                'valid_emails': summary.valid_emails if summary else 0,
                'risky_emails': summary.risky_emails if summary else 0,
                'invalid_emails': summary.invalid_emails if summary else 0,
                'unknown_emails': summary.unknown_emails if summary else 0,
            })
        return render_template('list.html', uploads=uploads_list)
    return redirect('/')

@app.route('/verify', methods=['POST'])
def verify_email_address():
    user = User.query.get(session['user'])
    access_check = check_user_access(user, 'verify_email_address')
    if access_check:
        return access_check 
    data = request.get_json()
    email = data.get('email')
    # Perform email verification
    verification_details = perform_email_verification(email, providers, roles,increment_count=False)
    searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
    add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
    if not user.is_paid:
        user.verification_attempts += 1
        db.session.commit()
    session['show_recent_result'] = True
    return verification_details

@app.route('/force-verify', methods=['POST'])
def force_verfiy_email_address():
    user = User.query.get(session['user'])
    access_check = check_user_access(user, 'force_verify_email_address')
    if access_check:
        return access_check 
    data = request.get_json()
    email = data.get('email')
    # Perform email verification
    verification_details = perform_email_verification(email, providers, roles, force_live_check=True,increment_count=False)
    searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
    add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
    session['show_recent_result'] = True
    return verification_details

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect('/')
    user_id = session['user']
    file = validate_uploaded_file(request.files)
    # Ensure file validation was successful
    if not isinstance(file, FileStorage):
        return file
    filename, filepath = save_uploaded_file(file, user_id)
    encoding, delimiter = detect_file_properties(filepath)
    df = read_csv_file(filepath, encoding, delimiter)
    if isinstance(df, dict): # Read error
        delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
        return error_response(df.get('File read error',400))
    email_column = detect_email_column(df)
    if not email_column:
        delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
        return error_response('No email column found',400)
    df[email_column] = df[email_column].apply(sanitize_email)
    result_df = process_emails(df[email_column])
    generate_summary(result_df, filename, user_id)
    update_csv_with_verification(df, result_df, filepath, filename)
    return success_response('file uploaded and processed',200)

@app.route('/force-upload', methods=['POST'])
def force_upload_file():
    user_id = session.get('user')
    if not user_id:
        return redirect('/')
    file = validate_uploaded_file(request.files)
    # Ensure file validation was successful
    if not isinstance(file, FileStorage):
        return file
    filename, filepath = save_uploaded_file(file, user_id)
    encoding, delimiter = detect_file_properties(filepath)
    df = read_csv_file(filepath, encoding, delimiter)
    if isinstance(df, dict):  # Read error
        delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
        return error_response(df.get('File read error',400))
    email_column = detect_email_column(df)
    if not email_column:
        delete_file_by_unique_filename(filename, UPLOAD_FOLDER)
        return error_response('No email column found')
    df[email_column] = df[email_column].apply(sanitize_email)
    result_df = process_emails(df[email_column], force=True)
    generate_summary(result_df, filename, user_id)
    update_csv_with_verification(df, result_df, filepath, filename)
    return success_response('file uploaded and processed',200)

@app.route('/download/<unique_filename>', methods=['GET'])
def download_file(unique_filename):
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if upload_entry:
        # Construct the full path to the file
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        # Check if the file exists on the server
        if os.path.exists(file_path):
            # Use send_from_directory with original filename
            return send_from_directory(
                UPLOAD_FOLDER, unique_filename,
                as_attachment=True, download_name=upload_entry.original_filename
            )
    # If the record doesn't exist or file is missing, return error response
    return error_response('File not found', 404)
 
@app.route('/manual_signin', methods=['POST'])
def manual_signin():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user:
        # Check if the user registered with Google
        if user.is_google:
            return error_response('This email is registered via Google sign-in.', 401)
        # Validate user password
        if validate_user(user, password):
            sign_in_user(user)
            # Check the session flag for redirect
            if session.pop('is_redirect_needed', False):  # Remove the flag after checking
                redirect_url = url_for('edit_profile')  # Set the URL for the profile page
            else:
                redirect_url = url_for('homeview')  # Default URL (homeview)
            # Return the redirect URL directly
            return jsonify({'redirect_url': redirect_url}), 200
    # If no user is found or password is incorrect
    return error_response('The Username or Password is Invalid.', 400)

@app.route('/signup', methods=['GET', 'POST'])
def manual_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        # Check if email is already registered
        if user_exists(email):
            return error_response('Email is already registered. Please log in.', 400)
        if temp_exists(email):
            return error_response('Please verify your email to Continue.',400)
        # Validate email
        if not verify_user(email):
            return error_response('Email cannot be used to create an account.',400)
        # Generate a verification token, hash the password, and create a TempUser
        verification_token = generate_nonce()
        hashed_password = generate_password_hash(password)
        create_temp_user(first_name, last_name, email, hashed_password, verification_token)
        # Send verification email
        send_email(first_name, email, verification_token)
        return success_response('A verification email has been sent to your email address. Please verify to complete registration.',200)
    return render_template('/signup.html')

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    temp_user = TempUser.query.filter_by(verification_token=token).first()
    if not temp_user:
        return render_template('verification_result.html', message='Invalid or expired token.', success=False)
    # Add the verified user to the database
    new_user = create_user(
        temp_user.first_name,
        temp_user.last_name,
        temp_user.email,
        temp_user.password,
        temp_user.is_google
    )
    # Clean up the temporary data
    db.session.delete(temp_user)
    db.session.commit()
    return render_template('verification_result.html', message='Your email has been verified! You can now log in.', success=True)

@app.route('/google/')
def google_login():
    nonce = generate_nonce()
    logger.debug(f"Generated nonce: {nonce}")  # Log generated nonce
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/auth/')
def google_auth():
    try:
        # Process Google auth
        token = oauth.google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        email = user_info.get('email')
        user = user_exists(email)
        if user:
            if user.is_google:
                sign_in_user(user)
                # Check the session for 'is_redirect_needed' flag
                if session.pop('is_redirect_needed', False):
                    # Redirect to the intended page (e.g., edit profile)
                    return redirect(url_for('edit_profile'))
                # Default redirect if no special page was requested
                return redirect(url_for('homeview'))
            else:
                return error_response('This email is already registered with a manual signup.', 400)
        # Handle new user creation if needed here
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return error_response('An authentication error occurred.', 500)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_email', None)
    return redirect(url_for('indexview'))

@app.route('/password')
def passwordreset():
    return render_template('/password.html')

@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('emailAddress') # Get email from the request body
    if not email:  # Check if the email field is empty or not present
        return error_response("Email is required", 400)
    user = user_exists(email)  # Check if the user exists
    if user is None:
        return error_response('The User email does not exist.', 404)  # Return 404 if user does not exist
    # If user exists, handle login type
    if user.is_google:
        return success_response('You have logged in using Google Login.', 200)
    else:
        # Generate a reset token
        token = generate_reset_token(user)
        # Create the reset link
        reset_link = url_for('reset_with_token', token=token, _external=True)
        # Generate the subject and HTML body using the password reset email template
        subject, html_body = create_password_reset_email(reset_link)
        # Send the email
        mail_server(user.email, subject, html_body)
        return success_response("An email has been sent with instructions to reset your password.", 200)

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    user = validate_reset_token(token)
    if not user:
        return error_response('Invalid or expired token.', 400)  # Add status code for invalid token
    if request.method == 'POST':
        # Use request.get_json() to get JSON data instead
        data = request.get_json()
        new_password = data.get('password')  # Get the password from JSON data
        # Check if the new_password is provided
        if not new_password:
            return error_response('New password is required.', 400)  # Return an error if password is missing
        reset_password(user, new_password)
        return success_response('Your password has been updated!', 200)
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user' not in session:
        return redirect('/')
    user = User.query.get(session['user'])
    is_google_login = user.is_google
    if not user:
        return error_response("User not found", 404)  # Handle case where user does not exist
    if request.method == 'POST':
        data = request.get_json()
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        password = data.get('password')  # Optional password update
        # Update the user's details directly
        update_successful = update_user_profile(user.user_id, first_name, last_name, password)
        if not update_successful:
            return error_response("Error updating profile", 400)
        return success_response("Profile updated successfully!", 200)
    # If it's a GET request, fetch and display the user's details
    user_data = get_user_profile(user)
    if user_data:
        return render_template('profile.html', user=user_data, is_google_login=is_google_login)
    else:
        return error_response("User not found", 404)
    
@app.route('/delete/<unique_filename>', methods=['GET', 'POST'])
def delete_file(unique_filename):
    delete_file_by_unique_filename(unique_filename, UPLOAD_FOLDER)
    return redirect(url_for('listview'))

@app.route('/delete_old_files', methods=['GET'])
def delete_old_files_route():
    delete_old_files(UPLOAD_FOLDER)
    return "Old files deleted", 200

@app.route('/view_csv/<unique_filename>', methods=['GET'])
def view_csv(unique_filename):
    csv_data_html = read_csv_as_html(unique_filename)
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if csv_data_html is None:
        return "Error reading the CSV file.", 500
    return render_template('view_csv.html', csv_data=csv_data_html, upload=upload_entry)

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/get-pro')
def get_pro():
    # Check if the user is logged in by checking for a session key (e.g., 'user')
    if 'user' in session:
        # User is logged in, redirect to profile page
        return redirect(url_for('edit_profile'))
    else:
        # User is not logged in, set a flag in the session
        session['is_redirect_needed'] = True
        # Redirect to the registration or login page
        return redirect(url_for('manual_signup'))
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        # Schedule the tasks
        schedule_task(delete_old_files, 'days', 1)
        schedule_task(cleanup_expired_sessions, 'hours', 2)
        schedule_task(cleanup_expired_temp_users, 'days', 1)
    app.run(debug=True)  # Start the Flask application


