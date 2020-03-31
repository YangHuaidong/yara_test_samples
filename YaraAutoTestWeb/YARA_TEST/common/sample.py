# coding=utf-8
import requests
import sched
import os, sys, re
import time
import subprocess
import logging
import xlrd
from xlutils.copy import copy
from bs4 import BeautifulSoup

curdir =os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(curdir)

logging.getLogger("requests").setLevel(logging.WARNING)


from common.config import Config

s = sched.scheduler(time.time, time.sleep)


class file_download():
    def __init__(self):
        self.cfg = Config()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1'}  # 给请求指定一个请求头来模拟chrome浏览器
        self.web_url = ['http://www.virscan.org/antivirusvendor/{}'.format(str(i)) for i in ['antiy', 'kaspersky']]
        curdir = os.path.dirname(os.path.realpath(__file__))
        self.md5_path = os.path.join(curdir, "Archive", 'list.log')
        self.log_paths = self.cfg.samplepath.black_path
        self.log_path = os.path.join(os.path.dirname(self.log_paths), 'black_sample.xls')
        # self.log_path = os.path.join(os.path.dirname(self.log_paths),'test.xls')
        self.md5judge = False

    def get_pic(self):
        hour1 = time.strftime("%H,%M", time.localtime())
        cfg_time = self.cfg.time.download_time
        # hour2 = time.strftime("%a,%H,%M", time.localtime())
        # black_time = self.cfg.time.black_time
        if hour1 == cfg_time:
            wbk = xlrd.open_workbook(self.log_path)
            newb = copy(wbk)
            sheet = newb.get_sheet('yara test')
            data = wbk.sheet_by_name('yara test')
            cols = data.col_values(0)
            colNum = len(sheet.rows)
            sheet.col(0).width = 9999
            sheet.col(1).width = 9999
            if os.path.exists(self.md5_path):
                os.remove(self.md5_path)
            print('开始网页get请求')
            j = 0
            md5list = []
            for url in self.web_url:
                print(url)
                try:
                    r = requests.get(url, headers=self.headers, timeout=5)
                    soups = BeautifulSoup(r.text, 'lxml')
                    for soup in soups.find_all("table", {"class": "sortable ScannerListTb"}):
                        for a in soup.find_all("a"):
                            list1 = []
                            if 'html' in a.get('href'):
                                for b in a.find_all("font"):
                                    rulename = str(b.string)
                                    if self.md5judge:
                                        sheet.write(colNum, 1, label=rulename)
                                        newb.save(self.log_path)
                                        j += 1
                            else:
                                url = a.get('href')
                                t = requests.get(url, headers=self.headers, timeout=5)
                                soup_txt = BeautifulSoup(t.text, 'lxml')
                                for m in soup_txt.find_all("table", {"class": "ScannerListTb_noborder"}):
                                    for n in m.find_all("a"):
                                        if 'md5' in n.get('href'):
                                            md5 = str(n.string)
                                            if md5 not in cols:
                                                md5 = md5.rstrip()
                                                self.md5judge = True
                                                with open(self.md5_path, "a") as f:
                                                    f.write(md5 + '\n')
                                                sheet.write(colNum, 0, label=md5)
                                                newb.save(self.log_path)
                                                j += 1
                                            else:
                                                self.md5judge = False
                            if j == 2:
                                j = 0
                                colNum = colNum + 1
                except BaseException as e:
                    print(e, '************************************************')
            print("samples download")
            black_path = self.file_path()
            CMD = ["python", "./Archive/download_.py", black_path, self.md5_path]
            subprocess.call(CMD)
            self.cfg.update('sampletype', 'type', 'black')
        # if hour2 == black_time:
        #     self.cfg.update('sampletype', 'type', 'black')
        #     an = YaraPoster()
        #     an.yara_()

    def file_path(self):
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
    beauty = file_download()
    beauty.get_pic()


def task_run(inc=10):
    s.enter(0, 0, perform, (inc,))
    s.run()


if __name__ == '__main__':
    task_run()
    # beauty = file_download()
    # beauty.get_pic()
