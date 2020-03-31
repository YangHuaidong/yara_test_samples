# -*- coding: UTF-8 -*-
from __future__ import division
import os
import sys
import json
import hashlib
import codecs
import xlwt

from common.get_time import gettime


class YaraResult():
    """docstring for YaraResult"""

    def __init__(self, sumbit_date, total_count, samples_path='', reanalysis_starttime=''):
        self.sumbit_date = sumbit_date
        self.yara_count = 0
        self.total_count = total_count
        self.analysis_date = gettime()
        self.reanalysis_starttime = reanalysis_starttime
        self.samples_path = samples_path

        self.ret_dict = {
            "samples_path": "",
            "sumbit_date": "",
            "analysis_date": "",
            "reanalysis_starttime": "",
            "total_count": 0,
            "yara": {"details": []}
        }

    def yar_result(self, result, yara_count):
        for data in result:
            self.ret_dict["yara"]["details"].append(data)
        self.yara_count = yara_count
        self.total_checkout = yara_count

    def get_result(self):
        self.ret_dict["samples_path"] = self.samples_path
        self.ret_dict["sumbit_date"] = self.sumbit_date
        self.ret_dict["analysis_date"] = self.analysis_date
        self.ret_dict["reanalysis_starttime"] = self.reanalysis_starttime

        self.ret_dict["total_count"] = self.total_count

        self.ret_dict["yara"]["yara_count"] = self.yara_count
        if self.total_count == 0:
            percount = 0
        else:
            percount = self.yara_count / self.total_count
        self.ret_dict["yara"]["yara_percent"] = format(percount, '0.2%')
        return self.ret_dict
