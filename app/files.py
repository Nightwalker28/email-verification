from flask import Blueprint, request, render_template, redirect, url_for, session, jsonify
from werkzeug.datastructures import FileStorage
from pages.fileupload import (
    validate_uploaded_file,
    save_uploaded_file,
    detect_file_properties,
    read_csv_file,
    detect_email_column,
    sanitize_email,
    process_emails,
    update_csv_with_verification,
    delete_file_by_unique_filename,
    read_csv_as_html,
    generate_summary,
)
from pages.models import UserUpload, Summary, User
from config import UPLOAD_FOLDER, success_response, error_response
import os

files = Blueprint("files", __name__)

@files.route("/list")
def listview():
    if "user" in session:
        from pages.users import check_user_access
        user = User.query.get(session["user"])
        access_check = check_user_access(user, "listview")
        if access_check:
            return access_check
        uploads = UserUpload.query.filter_by(user_id=user.user_id).order_by(UserUpload.upload_date.desc()).all()
        unique_filenames = [upload.unique_filename for upload in uploads]
        summaries = Summary.query.filter(Summary.list_name.in_(unique_filenames)).all()
        summary_map = {summary.list_name: summary for summary in summaries}
        uploads_list = []
        for upload in uploads:
            summary = summary_map.get(upload.unique_filename)
            uploads_list.append({
                "id": upload.id,
                "original_filename": upload.original_filename,
                "upload_date": upload.upload_date,
                "unique_filename": upload.unique_filename,
                "total_emails": summary.total_emails if summary else 0,
                "valid_emails": summary.valid_emails if summary else 0,
                "risky_emails": summary.risky_emails if summary else 0,
                "invalid_emails": summary.invalid_emails if summary else 0,
                "unknown_emails": summary.unknown_emails if summary else 0,
            })
        return render_template("list.html", uploads=uploads_list)
    return redirect(url_for("auth.manual_signin"))

@files.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return redirect(url_for("auth.manual_signin"))
    user_id = session.get("user")
    file = validate_uploaded_file(request.files)
    if not isinstance(file, FileStorage):
        return file
    filename, filepath = save_uploaded_file(file, user_id)
    from pages.schedule import process_uploaded_file_task
    process_uploaded_file_task.delay(filename, user_id, force=False)
    return success_response("File uploaded. Processing initiated in background.", 200)

@files.route("/force-upload", methods=["POST"])
def force_upload_file():
    if "user" not in session:
        return redirect(url_for("auth.manual_signin"))
    user_id = session["user"]
    file = validate_uploaded_file(request.files)
    if not isinstance(file, FileStorage):
        return file
    filename, filepath = save_uploaded_file(file, user_id)
    from pages.schedule import process_uploaded_file_task
    process_uploaded_file_task.delay(filename, user_id, force=True)
    return success_response("Force upload initiated. Processing in background.", 200)

@files.route("/download/<unique_filename>", methods=["GET"])
def download_file(unique_filename):
    from flask import send_from_directory
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if not upload_entry:
        return error_response("File not found in the database", 404)
    file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    if not os.path.exists(file_path):
        return error_response("File not found on the server", 404)
    try:
        return send_from_directory(
            UPLOAD_FOLDER,
            unique_filename,
            as_attachment=True,
            download_name=upload_entry.original_filename,
        )
    except Exception as e:
        return error_response("Error downloading file", 500)

@files.route("/delete/<unique_filename>", methods=["GET", "POST"])
def delete_file(unique_filename):
    delete_file_by_unique_filename(unique_filename, UPLOAD_FOLDER)
    return redirect(url_for("files.listview"))

@files.route("/view_csv/<unique_filename>", methods=["GET"])
def view_csv(unique_filename):
    csv_data_html = read_csv_as_html(unique_filename)
    upload_entry = UserUpload.query.filter_by(unique_filename=unique_filename).first()
    if csv_data_html is None:
        return "Error reading the CSV file.", 500
    return render_template("view_csv.html", csv_data=csv_data_html, upload=upload_entry)

@files.route("/delete_old_files", methods=["GET"])
def delete_old_files_route():
    from pages.schedule import delete_old_files_task
    delete_old_files_task.delay()
    return "Old files deletion initiated", 200
