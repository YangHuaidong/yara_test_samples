# -*- coding: utf-8 -*-

import multiprocessing
import sys
import os
import codecs
import json
import time
import shutil

from multiprocessing import Process, Manager
from common.get_result import Result
from common.get_time import gettime
from common.mail import SendMail
from common.config import Config
from common.md5 import md5_file
from common.yaradetect import get_yara
from common.yara_result import YaraResult
from common.excel import excel_result
import logging

cfg = Config()
curdir = os.path.dirname(os.path.realpath(__file__))


def func(path, data, value1, md5list):
    try:
        md5 = md5_file(path)
        md5list.append(md5)
        yara_detect = get_yara(path)
        if yara_detect:
            value1.value += 1
            info = {}
            info["md5"] = md5
            info["info"] = yara_detect
            data.append(info)
    except Exception as e:
        print(e)


def Process(idlist=[]):
    manager = Manager()
    data = manager.list([])
    md5list = manager.list([])
    value1 = manager.Value('i', 0)
    pool = multiprocessing.Pool(processes=10)
    for oneid in idlist:
        pool.apply_async(func, (oneid, data, value1, md5list))
    pool.close()
    pool.join()

    return data, value1.value, md5list


def reanalysis(date, samples_type, new_yaradir='', num=None):
    """"""
    num_yara = int(num)
    send = cfg.sendmail.enable
    curdir = os.path.dirname(os.path.realpath(__file__))
    result_log = os.path.join(curdir, "result_log")
    save_path = os.path.join(curdir, "yara.log")
    white_sample_path = cfg.samplepath.white_path
    black_sample_path = cfg.samplepath.black_path
    result_path = ""
    yara_count = 0
    total_count = 0

    jsonResult = Result().get_json()

    for item in jsonResult:
        result_dir = os.path.join(result_log, item["samples_type"])
        if not os.path.exists(result_dir):
            os.makedirs(result_dir)
        result_path = os.path.join(result_dir, item["submit_time"] + ".log")
        if item["submit_time"] == date:
            with open(result_path, 'r') as f:
                line = json.load(f)
            samplepath = line['samples_path']
            reanalysis_starttime = gettime()
            pathlist = []
            md5list = []
            for root, dirname, filenames in os.walk(samplepath):
                for filename in filenames:
                    total_count = total_count + 1
                    path = os.path.join(root, filename)
                    pathlist.append(path)

            data, yara_count, md5list = Process(idlist=pathlist)
            an = YaraResult(item["submit_time"], total_count, samplepath, reanalysis_starttime)
            an.yar_result(data, yara_count)
            result = an.get_result()
            print(result)
            ret_f = codecs.open(result_path, "w", "utf-8")
            json.dump(result, ret_f, sort_keys=False, ensure_ascii=False, indent=4)
            ret_f.close()
            excel_path = excel_result(data, md5list, samples_type, item["submit_time"])

            badrule_map = {}
            yara_list = []
            if samples_type == 'white':
                yara_res = result["yara"]["details"]
                for item_yara in yara_res:
                    for rule in item_yara["info"]:
                        badrule_map[rule["rulename"]] = rule["meta"]["author"]
                        # 将yara误报的规则存至缓存文件
                        if rule["rulename"] not in yara_list:
                            yara_list.append(rule["rulename"])
                        else:
                            pass
                        code = open(save_path, "w")
                        for i in yara_list:
                            code.write(i)
                            code.write("\n")
                        code.close()

            # 入库
            if num_yara == 0 and samples_type == 'white':
                new_list = []
                code = open(save_path, "r")
                codes = code.readlines()
                for name in codes:
                    name = name.strip('\n')
                    new_list.append(name)
                code.close()

                for root, dirname, filenames in os.walk(new_yaradir):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        if filename.split(".")[0] not in new_list:
                            try:
                                p = os.popen("curl {0} -F f=@{1}".format(cfg.upload.address, filepath))
                                ret = p.read()
                                p.close()
                            except Exception as e:
                                print(e)
                                logging.error("Failure!!!!!!!!!{0}", format(e))
                # 入库完成后一个测试流程结束,更改缓存文件夹状态
                os.rename(new_yaradir, new_yaradir.replace("processing", "finished"))

            # sendmail
            # try:
            #     if send:
            #         newdata = result
            #         newdata["samples_type"] = item["samples_type"]
            #         # add sendmail
            #         # MAIL_TO 1_processing_327086445@qq.com
            #         MAIL_TO = new_yaradir.split('_')[-1]
            #         SendMail(excel_path, newdata, badrule_map).sendmail(MAIL_TO)
            #
            #         logging.info("send message success!")
            # except Exception as e:
            #     print(e)
            #     logging.error("message sending failed!", format(e))
            # return 1


if __name__ == '__main__':
    datetime = sys.argv[1]
    new_yaradir = sys.argv[2]
    num = sys.argv[3]
    samples_type = sys.argv[4]
    # datetime = '20190301-173548'
    # samples_type = 'black'
    # new_yaradir = '/home/YaraAutoTestWeb/YARA_TEST/uploads2analyse/1_processing_327086445@qq.com'
    # num = 23
    reanalysis(datetime, samples_type, new_yaradir, num)
