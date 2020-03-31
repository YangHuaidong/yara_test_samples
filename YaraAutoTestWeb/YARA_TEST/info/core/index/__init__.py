from flask import Blueprint

# 创建蓝图对象
index_bp = Blueprint("index", __name__)

# 导入views中的视图函数
from .views import *
