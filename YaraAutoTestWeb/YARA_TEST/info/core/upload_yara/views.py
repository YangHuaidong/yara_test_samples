# -*-coding:utf8-*-
from flask import render_template, request
import os
from time import ctime
from . import upload_yara_bp
from werkzeug.utils import secure_filename
from common.check_yara_format import check_Yara_Format
from common.analysis_status import status_query
from common.tmp_rule import add2analyse
from common.config import Config

cfg = Config()

if not os.path.exists("/home/YaraAutoTestWeb/YARA_TEST/uploads2lib"):
    os.mkdir("/home/YaraAutoTestWeb/YARA_TEST/uploads2lib")
if not os.path.exists("/home/YaraAutoTestWeb/YARA_TEST/uploads2judge"):
    os.mkdir("/home/YaraAutoTestWeb/YARA_TEST/uploads2judge")
if not os.path.exists("/home/YaraAutoTestWeb/YARA_TEST/uploads2analyse"):
    os.mkdir("/home/YaraAutoTestWeb/YARA_TEST/uploads2analyse")

curdir = os.path.dirname(os.path.realpath(__file__))
yarajudge = check_Yara_Format()


def allowed_file(filename):
    ALLOWED_EXTENSIONS = cfg.config_path.allowed_extensions
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@upload_yara_bp.route('/yara', methods=['GET'])
def yarahome():
    return render_template('yaraindex.html')


# 上传入库文件
@upload_yara_bp.route('/uploads2lib', methods=['POST'])
def uploads2lib():
    uploaded_files = request.files.getlist("file[]")
    savetime = "_".join(ctime().split(" ")).replace(":", "_")
    savedir = os.path.join(cfg.config_path.upload_folder_2lib, savetime)
    if not os.path.exists(savedir):
        os.mkdir(savedir)

    filenames = []
    ret = ""
    for file in uploaded_files:
        filename = secure_filename(file.filename)
        filepath = os.path.join(curdir, savedir, filename)
        file.save(filepath)
        if file and allowed_file(file.filename):
            p = os.popen("curl {0} -F f=@{1}".format(cfg.config_path.yaralib, filepath))
            ret = p.read()
            p.close()

            if ret.find("success") != -1:
                filenames.append((savetime, filename, "successed!"))
            if ret.find("false") != -1:
                filenames.append((savetime, filename, "failed! check network status please!"))
        else:
            filenames.append((savetime, filename, "failed! unsupport file type"))
    return render_template('libupload.html', filenames=filenames)


# 上传校验文件
@upload_yara_bp.route('/uploads2judge', methods=['POST'])
def uploads2judge():
    uploaded_files = request.files.getlist("file[]")
    savetime = "_".join(ctime().split(" ")).replace(":", "_")
    savedir = os.path.join(cfg.config_path.upload_folder_2judge, savetime)
    if not os.path.exists(savedir):
        os.mkdir(savedir)

    allright_status = 1
    filenames = []
    ret = ""
    # senmail
    qqmail = request.values.get('qqmail', "")
    if not qqmail:
        return "Please enter your qq mail!"

    for file in uploaded_files:
        filename = secure_filename(file.filename)
        filepath = os.path.join(curdir, savedir, filename)
        file.save(filepath)
        if file and allowed_file(file.filename):
            res = yarajudge.check_yara_format(filepath, savetime)
            if res[0]:
                filenames.append((savetime, filename, "ok"))
            elif len(res) == 4:
                filenames.append((savetime, filename, "{0}:{1}".format(res[2], res[1])))
                allright_status = 0
            else:
                filenames.append((savetime, filename, res[1]))
                allright_status = 0
        else:
            filenames.append((savetime, filename, "unsupport file type, yara or yar file"))
            allright_status = 0
    status = status_query()
    if allright_status:
        add2analyse(savedir, qqmail)
    return render_template('judgeupload.html', filenames=filenames, status=status)
