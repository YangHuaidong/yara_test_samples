# -*-coding:utf8-*-
import json

from . import analysis_sample_bp
from flask import request, render_template
from common.postfile_collect import submit
from common.get_submitres import get_submitlog
from common.analysis_status import status_query
from common.post_result import post_summary,post_details




# 投放样本
@analysis_sample_bp.route('/post', methods=['POST'])
def post():
    filepath = request.form.get("filepath")
    samplestype = request.form.get("samplestype")
    postret = submit(filepath, samplestype)
    return "1"


# #获取样本投放日志
@analysis_sample_bp.route('/getlog', methods=['GET'])
def getlog():
    submit_log = get_submitlog()
    return render_template(
        'log.html',
        log=submit_log,
    )


# 获取样本检测结果日志
@analysis_sample_bp.route('/getresult/<result>', methods=['GET'])
def getresult(result):
    status = status_query()
    if result == "all_black":
        summary = post_summary("black")
        return render_template("result_black.html",log=summary,status=status)

    elif result == "all_white":
        summary = post_summary("white")
        return render_template("result_white.html",log=summary,status=status)

    else:
        urlcrack_data = result.split("_")
        submit_date = urlcrack_data[0]
        check_type = urlcrack_data[1]
        judge = urlcrack_data[2]
        return render_template("details.html",details=json.dumps(post_details(submit_date, check_type, judge), ensure_ascii=False,indent=4))
