# -*- coding:utf8-*-
import json
import os
import re
import sched
import subprocess
import time
import sys

curdir =os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(curdir)

from common.config import Config
from spider_webshell.virus_type.get_time import gettime

s = sched.scheduler(time.time, time.sleep)
a = os.path.dirname(os.path.realpath(__file__))

class Extract_Md5():
    def __init__(self):
        self.cfg = Config()
        self.curdir = os.path.dirname(os.path.realpath(__file__))
        self.md5_ = os.path.join(self.curdir, 'md5')
        self.json_file = os.path.join(self.curdir, 'json')
        self.downloads_md5 = os.path.join(self.curdir, 'downloads_md5')
        self.extract_time = self.cfg.time.extract_time
        self.log_paths = self.cfg.samplepath.black_path
        self.md5_total = os.path.join(self.md5_, 'extract_' + gettime() + ".txt")

    def extract_md5(self):
        hour_day = time.strftime("%H,%M", time.localtime())
        if hour_day == self.extract_time:
            md5list = []
            total_count = 0
            dirlist = os.listdir(self.json_file)
            dirlist.sort(key=lambda x: int(x[8:-5]))
            last_dirname = dirlist[-1]
            filepath = self.json_file + "/" + last_dirname
            with open(filepath, 'r')as f:
                f.seek(0)
                content = f.readlines()
                for i in content:
                    content_dict = json.loads(i)
                    md5 = content_dict['content']['md5']
                    with open(self.md5_total, 'a')as code:
                        code.write(md5 + '\n')
            dir_md5 = os.listdir(self.md5_)
            for z in dir_md5:
                path = self.md5_ + "/" + z
                with open(path, 'r')as f:
                    f.seek(0)
                    hash = f.readlines()
                    for i in hash:
                        if i not in md5list:
                            total_count += 1
                            md5list.append(i)
            lasts_download_md5 = os.listdir(self.downloads_md5)
            lasts_download_md5.sort(key=lambda x: int(x[4:-4]))
            file_path = self.downloads_md5 + '/' + lasts_download_md5[-1]
            with open(file_path)as f:
                count = f.readlines()
                for t in md5list:
                    if t not in count:
                        timestr = time.strftime('%Y%m%d', time.localtime())+'000000'
                        md5_file = self.downloads_md5 + '/md5_' + timestr + '.txt'
                        with open(md5_file, 'a') as f:
                            f.write(t)
            CMD = ["python", "/home/YaraAutoTestWeb/YARA_TEST/common/Archive/download_.py", self.file_path_(), md5_file]
            subprocess.call(CMD)

    def file_path_(self):
        dirlist = os.listdir(self.log_paths)
        dirlist.sort(key=lambda i: int(re.match(r'(\d+)', i).group()))
        if not dirlist:
            last_dirname = "1_ready"
            os.mkdir(os.path.join(self.log_paths, last_dirname))
        else:
            last_dirname = dirlist[-1]

        if last_dirname.find("finish") != -1:
            num = int(last_dirname.split("_")[0])
            num += 1
            last_dirname = "{0}_ready".format(num)
            os.mkdir(os.path.join(self.log_paths, last_dirname))
        path = os.path.join(self.log_paths, last_dirname)
        return path


def perform(inc):
    s.enter(inc, 0, perform, (inc,))
    beautygirl = Extract_Md5()
    beautygirl.extract_md5()


def task_run(inc=5):
    s.enter(0, 0, perform, (inc,))
    s.run()


if __name__ == '__main__':
    task_run()
