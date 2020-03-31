# -*- coding: utf-8 -*-

import time
import sched
import subprocess
import os, sys

curdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(curdir)

from common.config import Config
from common.post_result import post_summary
from common.yaralib_update import update
from info.analysis_process.yara_analysis import YaraPoster

cfg = Config()
cfg_time = cfg.time.reanalysis_time
black_time = cfg.time.black_time
s = sched.scheduler(time.time, time.sleep)


def event_func():
    hour_week = time.strftime("%a,%H,%M", time.localtime())
    if hour_week == cfg_time:
        result, rulepath = update()
        if result:
            for i in ["white", "black"]:
                summary = post_summary(i)
                num = len(summary)
                for item in summary:
                    num -= 1
                    try:
                        CMD = ["python", "/home/YaraAutoTestWeb/YARA_TEST/common/reanalyzer.py", item["sumbit_date"],
                               rulepath, str(num), i]
                        subprocess.call(CMD)
                    except Exception as e:
                        print(e, '================')
        else:
            print("rule update failed.")

    hour2 = time.strftime("%a,%H,%M", time.localtime())
    # TODO
    if hour2 == black_time:
        cfg.update('sampletype', 'type', 'black')
        an = YaraPoster()
        an.yara_()


def perform(inc):
    s.enter(inc, 0, perform, (inc,))
    event_func()


def task_run(inc=5):
    s.enter(0, 0, perform, (inc,))
    s.run()


if __name__ == '__main__':
    task_run()
