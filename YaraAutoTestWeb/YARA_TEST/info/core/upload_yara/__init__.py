from flask import Blueprint

upload_yara_bp = Blueprint("upload_yara", __name__)


from .views import *
