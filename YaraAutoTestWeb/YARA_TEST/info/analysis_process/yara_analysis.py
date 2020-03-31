# -*- coding: utf-8 -*-
import os, re
import json
import hashlib
import codecs
import shutil
import time
import sched
import multiprocessing
import logging

from multiprocessing import Process, Manager
from common.get_time import gettime
from common.mail import SendMail
from common.yaradetect import get_yara
from common.yara_result import YaraResult
from common.config import Config
from common.md5 import md5_file
from common.loger import init_loger
from common.excel import excel_result
from common.mail_conf import conf

curdir = os.path.dirname(os.path.realpath(__file__))
s = sched.scheduler(time.time, time.sleep)
init_loger(curdir)
log = logging.getLogger(__name__)


def func(path, data, value1, lock, save_path):
    lock.acquire()
    try:
        try:
            md5 = md5_file(path)
            yara_detect = get_yara(path)
            code = open(save_path, "a")
            ret = {"status": 1, "message": "success", "md5": md5}
            code.write(json.dumps(ret) + "\n")
            if yara_detect:
                value1.value += 1
                info = {}
                info["md5"] = md5
                info["info"] = yara_detect
                data.append(info)
        except Exception as e:
            md5 = md5_file(path)
            code = open(save_path, "a")
            log.error("Yara analysis failed !{0},{1}".format(e, path))
            ret = {"status": 1, "message": "failure", "md5": md5}
            code.write(json.dumps(ret) + "\n")
        code.close()
    finally:
        lock.release()


class YaraPoster():
    def __init__(self):
        self.cfg = Config()
        self.send = self.cfg.sendmail.enable
        self.sample_type = self.cfg.sampletype.type
        self.white_path = self.cfg.samplepath.white_path
        self.black_path = self.cfg.samplepath.black_path
        self.curdir = self.cfg.samplepath.file_path

        self.curtime = gettime()
        self.result_log = os.path.join(self.curdir, "result_log", self.sample_type)
        self.submit_log = os.path.join(self.curdir, "submit_log", self.sample_type)
        if not os.path.exists(self.submit_log):
            os.makedirs(self.submit_log)
        save_name = 'submit_ret_' + self.curtime + '.log'
        self.save_path = os.path.join(self.submit_log, save_name)
        if not os.path.exists(self.result_log):
            os.makedirs(self.result_log)
        self.result_name = self.curtime + '.log'
        self.result_path = ''
        self.sample_path = ''
        self.data = []
        self.value1 = ''

    def Process(self, idlist=[]):
        manager = Manager()
        lock = multiprocessing.Manager().Lock()
        self.data = manager.list([])
        self.value1 = manager.Value('i', 0)
        pool = multiprocessing.Pool(processes=20)
        for oneid in idlist:
            pool.apply_async(func, (oneid, self.data, self.value1, lock, self.save_path))
        pool.close()
        pool.join()

    def yara_(self):
        if self.sample_type == 'black':
            dirlist = os.listdir(self.black_path)
            dirlist.sort(key=lambda i: int(re.match(r'(\d+)', i).group()))
            if dirlist and dirlist[-1].find("temp") != -1:
                last_dirname = dirlist[-1]
                last_dirpath = os.path.join(self.black_path, last_dirname)
                self.sample_path = last_dirpath
                self.result_path = os.path.join(self.result_log, self.result_name)
            if dirlist and dirlist[-1].find("ready") != -1:
                last_dirname = dirlist[-1]
                last_dirpath = os.path.join(self.black_path, last_dirname)
                self.sample_path = last_dirpath
                self.result_path = os.path.join(self.result_log, self.result_name)

        if self.sample_type == 'white':
            dirlist = os.listdir(self.white_path)
            dirlist.sort(key=lambda i: int(re.match(r'(\d+)', i).group()))

            if dirlist and dirlist[-1].find("ready") != -1:
                last_dirname = dirlist[-1]
                last_dirpath = os.path.join(self.white_path, last_dirname)
                self.sample_path = last_dirpath
                self.result_path = os.path.join(self.result_log, self.result_name)
            self.result_path = os.path.join(self.result_log, self.result_name)

        if self.sample_path != '':
            pathlist = []
            md5list = []
            total_count = 0
            for root, dirname, filenames in os.walk(self.sample_path):
                for filename in filenames:
                    total_count = total_count + 1
                    path = os.path.join(root, filename)
                    md5 = md5_file(path)
                    pathlist.append(path)
                    md5list.append(md5)

            log.info('start process,A total of {0} samples'.format(len(pathlist)))
            self.Process(idlist=pathlist)
            with open(self.save_path, "a") as code:
                code.write("finished")
            yara_count = self.value1.value
            if 'temp' in self.sample_path:
                num = int(last_dirname.split("_")[0])
                la_num = num - 1
                la_dirname = "{0}_finish".format(la_num)
                la_dirpath = os.path.join(self.black_path, la_dirname)
                os.rename(last_dirpath, la_dirpath)
                self.sample_path = la_dirpath
                ne_dirname = dirlist[-2]
                new_dirname = "{0}_ready".format(num)
                ne_dirpath = os.path.join(self.black_path, ne_dirname)
                new_dirpath = os.path.join(self.black_path, new_dirname)
                os.rename(ne_dirpath, new_dirpath)
            else:
                finish_dirpath = last_dirpath.replace("ready", "finish")
                os.rename(last_dirpath, finish_dirpath)
                self.sample_path = finish_dirpath
            an = YaraResult(self.curtime, total_count, self.sample_path)
            an.yar_result(self.data, yara_count)
            result = an.get_result()
            ret_f = codecs.open(self.result_path, "w", "utf-8")
            json.dump(result, ret_f, sort_keys=False, ensure_ascii=False, indent=4)
            ret_f.close()
            print(self.data, '**************************************')
            excel_path = excel_result(self.data, md5list, self.sample_type, self.curtime)

            badrule_map = {}
            yara_res = result["yara"]["details"]
            for item_yara in yara_res:
                for rule in item_yara["info"]:
                    badrule_map[rule["rulename"]] = rule["meta"]["author"]

            # sendmail
            try:
                logging.info('start sendmail')
                if self.send:
                    newdata = result
                    newdata["samples_type"] = self.sample_type
                    MAIL_TO = conf["to"]
                    SendMail(excel_path, newdata, badrule_map).sendmail(MAIL_TO)
            except Exception as e:
                print('No excel file! so sendmail failed!')
            return result


if __name__ == '__main__':
    an = YaraPoster()
    an.yara_()
