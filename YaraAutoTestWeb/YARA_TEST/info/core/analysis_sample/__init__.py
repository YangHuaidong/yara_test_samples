from flask import Blueprint

analysis_sample_bp = Blueprint("analysis_sample", __name__)

from .views import *
