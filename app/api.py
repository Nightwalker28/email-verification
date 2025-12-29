# from flask import Blueprint, request, jsonify
# from pages.apis import (
#     api_verify,
#     create_api_key,
#     edit_api_key,
#     delete_api_key,
#     require_api_key,
#     api_forceverify,
#     api_upload,
#     api_forceupload,
# )

# api = Blueprint("api", __name__)

# @api.route("/verify", methods=["POST"])
# @require_api_key
# def apiverify():
#     """API endpoint to verify an email address."""
#     return api_verify()

# @api.route("/forceverify", methods=["POST"])
# @require_api_key
# def apiforceverify():
#     """API endpoint to force a live email verification."""
#     return api_forceverify()

# @api.route("/upload", methods=["POST"])
# @require_api_key
# def apiupload():
#     """API endpoint to process file upload and email verification."""
#     return api_upload()

# @api.route("/forceupload", methods=["POST"])
# @require_api_key
# def apiforceupload():
#     """API endpoint to force file upload processing with live verification."""
#     return api_forceupload()
