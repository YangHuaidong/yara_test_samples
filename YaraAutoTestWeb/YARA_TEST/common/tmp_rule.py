# -*- coding: utf-8 -*-

import os, re
import shutil
from .config import Config

cfg = Config()
workdir = cfg.workdir.path
tmprule_dir = os.path.join(workdir, "uploads2analyse")


def add2analyse(judgerule_dir, qqmail):
    """上传yara规则之后，先按日期归档，然后备份到规则文件夹"""
    dirlist = os.listdir(tmprule_dir)
    dirlist.sort(key=lambda i: int(re.match(r'(\d+)', i).group()))
    if not dirlist:
        last_dirname = "1_ready_{}".format(qqmail)
        os.mkdir(os.path.join(tmprule_dir, last_dirname))
    else:
        last_dirname = dirlist[-1]
    # else:
    # last_dirname = dirlist[-1]
    # TODO 如果分批上传的话 目前默认使用第一次输入的邮箱 后续会改进
    # num = int(last_dirname.split("_")[0])
    # num += 1
    # last_dirname = "{0}_ready_{1}".format(num,qqmail)
    # os.mkdir(os.path.join(tmprule_dir,last_dirname))

    if last_dirname.find("finished") != -1 or last_dirname.find("processing") != -1:
        num = int(last_dirname.split("_")[0])
        num += 1
        last_dirname = "{0}_ready_{1}".format(num, qqmail)
        os.mkdir(os.path.join(tmprule_dir, last_dirname))

    for root, dirname, filenames in os.walk(judgerule_dir):
        for filename in filenames:
            filepath = os.path.join(root, filename)
            shutil.copy(filepath, os.path.join(tmprule_dir, last_dirname, filename))
