# -*-coding:utf8-*-
from . import index_bp
from flask import render_template
from wtforms import StringField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired





# 使用蓝图
@index_bp.route("/", methods=['GET'])
def home():
    form = QueryForm()
    return render_template('index.html', form=form)


class QueryForm(FlaskForm):
    filepath = StringField(u'文件上传路径', validators=[DataRequired()])





