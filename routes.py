from config import logger,app,UPLOAD_FOLDER,oauth,providers,roles
from pages.users import reset_verification_attempts,get_verification_attemps,get_user_profile,update_user_profile,check_user_access,get_user_summary
from pages.models import get_or_create_searched_email,add_verified_email_for_user,get_last_checked_emails,db,User,UserUpload,Summary
from pages.schedule import delete_old_files,schedule_task,cleanup_expired_sessions
from pages.emailverification import perform_email_verification
from pages.fileupload import validate_uploaded_file,detect_file_properties,save_uploaded_file,read_csv_file,detect_email_column,sanitize_email,process_emails,update_csv_with_verification,delete_file_by_unique_filename,read_csv_as_html,generate_summary
from pages.loginsignup import validate_user,sign_in_user,user_exists,create_user,get_or_create_google_user,generate_nonce,send_password_reset_email,validate_reset_token,reset_password,generate_reset_token
from flask import session,redirect,url_for,render_template,jsonify,request,send_from_directory

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
    verification_details = perform_email_verification(email, providers, roles)
    searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
    add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
    if not user.is_paid:
        user.verification_attempts += 1
        db.session.commit()
    session['show_recent_result'] = True
    return jsonify(verification_details), 200

@app.route('/force-verify', methods=['POST'])
def force_verfiy_email_address():
    user = User.query.get(session['user'])
    access_check = check_user_access(user, 'force_verify_email_address')
    if access_check:
        return access_check 
    data = request.get_json()
    email = data.get('email')
    # Perform email verification
    verification_details = perform_email_verification(email, providers, roles, force_live_check=True)
    searched_email_entry = get_or_create_searched_email(email, verification_details['result'])    # Now store the user_id and email_id in the association table
    add_verified_email_for_user(user.user_id, searched_email_entry.email_id)
    session['show_recent_result'] = True
    return jsonify(verification_details), 200

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return jsonify({'error': 'User not logged in'}), 403
    user_id = session['user']  # Assuming session['user'] contains the user ID
    # Check and validate the uploaded file
    file = validate_uploaded_file(request.files)
    if isinstance(file, dict):  # If validation failed
        return jsonify(file), 400
    filename, filepath = save_uploaded_file(file, user_id)  # Pass user_id here
    logger.info(f'File uploaded: {filename}')
    # Detect file properties (encoding, delimiter)
    encoding, delimiter = detect_file_properties(filepath)
    logger.info(f'Detected file properties: encoding={encoding}, delimiter={delimiter}')
    # Read the CSV file
    df = read_csv_file(filepath, encoding, delimiter)
    if isinstance(df, dict):  # If there was an error in reading the file
        return jsonify(df), 400
    # Detect the email column
    email_column = detect_email_column(df)
    if not email_column:
        logger.error('No email column found')
        return jsonify({'error': "No email column found"}), 400
    logger.info(f'Email column detected: {email_column}')
    # Sanitize the emails
    df[email_column] = df[email_column].apply(sanitize_email)
    logger.info('Email addresses sanitized')
    # Process emails and update the DataFrame with verification details
    result_df = process_emails(df[email_column])
    generate_summary(result_df,filename,user_id)
    update_csv_with_verification(df, result_df, filepath, filename)
    return jsonify({'filename': filename}), 200

@app.route('/force-upload', methods=['POST'])
def force_upload_file():
    # Check and validate the uploaded file
    user_id = session['user']
    file = validate_uploaded_file(request.files)
    if isinstance(file, dict):  # If validation failed
        return jsonify(file), 400
    filename, filepath = save_uploaded_file(file,user_id)
    logger.info(f'File uploaded: {filename}')
    # Detect file properties (encoding, delimiter)
    encoding, delimiter = detect_file_properties(filepath)
    logger.info(f'Detected file properties: encoding={encoding}, delimiter={delimiter}')
    # Read the CSV file
    df = read_csv_file(filepath, encoding, delimiter)
    if isinstance(df, dict):  # If there was an error in reading the file
        return jsonify(df), 400
    # Detect the email column
    email_column = detect_email_column(df)
    if not email_column:
        logger.error('No email column found')
        return jsonify({'error': "No email column found"}), 400
    logger.info(f'Email column detected: {email_column}')
    # Sanitize the emails
    df[email_column] = df[email_column].apply(sanitize_email)
    logger.info('Email addresses sanitized')
    # Process emails and update the DataFrame with force verification details
    result_df = process_emails(df[email_column], force=True)  # Force verification
    update_csv_with_verification(df, result_df, filepath, filename) 
    return jsonify({'filename': filename}), 200

@app.route('/download/<unique_filename>', methods=['GET'])
def download_file(unique_filename):
    # Look up the file entry in the database to get the original filename
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if upload_entry:
        # Send the file from the directory with the original filename
        return send_from_directory(UPLOAD_FOLDER,unique_filename,as_attachment=True,download_name=upload_entry.original_filename)
    return "File not found", 404  # Handle case where upload_entry is None
 
@app.route('/manual_signin', methods=['POST'])
def manual_signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = validate_user(email, password)
    if user:
        if user.is_google:
            return jsonify({'success': False, 'message': 'This email is registered via Google sign-in.'}), 401
        sign_in_user(user)
        return jsonify({'success': True}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401
    
@app.route('/signup', methods=['GET', 'POST'])
def manual_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        if user_exists(email):
            return jsonify({'message': 'Email is already registered. Please log in.'}), 400
        new_user = create_user(first_name, last_name, email, password)
        sign_in_user(new_user)
        return redirect('/')
    return render_template('signup.html')

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
        token = oauth.google.authorize_access_token()
        nonce = session.pop('nonce', None)
        logger.debug(f"Retrieved nonce from session: {nonce}")  # Log retrieved nonce
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        email = user_info.get('email')
        first_name = user_info.get('given_name')
        last_name = user_info.get('family_name')
        # Fetch or create the user based on email
        user = get_or_create_google_user(email, first_name, last_name)
        # Check if the user is registered via Google
        if not user.is_google:
            logger.error(f"User with email {email} is not registered for Google sign-in.")
            return jsonify({'success': False, 'message': 'This email is not registered via Google sign-in.'}), 401
        # Sign in the user if all checks pass
        sign_in_user(user)
        return redirect('/home')
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return jsonify({'success': False, 'message': 'An authentication error occurred.'}), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_email', None)
    jsonify('You have been logged out.')
    return redirect(url_for('indexview'))

@app.route('/password')
def passwordreset():
    return render_template('/password.html')
    
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.json  # Get the JSON data from the request
    email = data.get('emailAddress')
    if not email:  # Check if the email field is empty or not present
        return jsonify({"error": "Email is required"}), 400
    user = user_exists(email)
    if user:
        if user.is_google:
            return jsonify({"error": "You have logged in using Google Login."}), 200
        else:
            # Generate a reset token
            token = generate_reset_token(user)
            # Create the reset link
            reset_link = url_for('reset_with_token', token=token, _external=True)
            # Send the reset email
            send_password_reset_email(user.email, reset_link)
            return jsonify({"message": "An email has been sent with instructions to reset your password."}), 200      
    return jsonify({"error": "The User Mail doesnt exist"}), 200

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    user = validate_reset_token(token)
    if not user:
        return jsonify('Invalid or expired token.', 'danger')
    if request.method == 'POST':
        new_password = request.form['password']
        reset_password(user, new_password)
        return jsonify('Your password has been updated!', 'success')
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
 # Redirect to login if not logged in
    user = User.query.get(session['user'])
    user_id = user.user_id # Retrieve the user from the database
    if not user:
        return "User not found", 404  # Handle case where user does not exist
    if request.method == 'POST':
        # Handle the form submission
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']  # Optional password update
        # Update the user's details directly
        update_successful = update_user_profile(user_id, first_name, last_name, email, password)
        if update_successful:
            return jsonify({"message": "Profile updated successfully", "status": "success"})
        else:
            return jsonify({"message": "Error updating profile", "status": "error"})
    # If it's a GET request, fetch and display the user's details
    user_data = get_user_profile(user)
    if user_data:
        return render_template('profile.html', user=user_data)
    else:
        return "User not found", 404
    
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        # Schedule the tasks
        schedule_task(delete_old_files, 'days', 1)
        schedule_task(cleanup_expired_sessions, 'hours', 2)
    app.run(debug=True)  # Start the Flask application


