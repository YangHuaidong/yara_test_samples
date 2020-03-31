#!/usr/bin/env python
# coding=utf-8
import sys
import os
import yaratool
import yara
import json
import re
import pefile
import hashlib
import shutil
from time import ctime
from common.config import Config

key_threattype = ['DDOS', 'RAT', 'BACKDOOR', 'APT', 'DDOS|RAT', 'RAT|DDOS', \
                  'EXPLOIT', 'VIRUS', 'CONTROL', 'RANSOMWARE', 'DOWNLOADER', \
                  'HACKTOOL', 'ROOTKIT', 'DROPPER', 'MALWARE', 'ADWARE', 'STEALPASS', \
                  'STEALINFOR', 'KEYLOG', 'KILLDISK', 'ICS']
behavior_threattype = ['AUTORUN', 'DELETESELF', 'FAKE', 'HIDE', 'BYPASS', 'ANTI', 'EXPLOIT', 'HIJACK', 'SPREAD', \
                       'INJECT', 'DDOS', 'RAT', 'KEYLOG', 'PASSSTEAL', 'RANSOMWARE', 'BANK', 'ADWARE', 'MALWARE']
judge_list = ["unknown", "white", "black", "suspicious"]


class check_Yara_Format():
    def __init__(self):
        self.cfg = Config()
        savetime = "_".join(ctime().split(" ")).replace(":", "_")
        self.refdir = self.cfg.upload.back_path
        self.filename = ''
        self.refpath = ''
        curdir = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(curdir, "errorInfoConfig_yara.json")) as fr:
            self.errordict = json.load(fr)

    def check_yara_format(self, filepath, savetime=''):
        yara_result = self.check_is_yara(filepath)
        if yara_result[0]:
            pass
        else:
            if isinstance(yara_result[1], str):
                return yara_result
            else:
                yara_result[1] = self.errordict[str(yara_result[1])]
                return yara_result

        check_result = self.check_meta_key(filepath, savetime)
        if check_result[0]:
            return check_result
        else:
            if isinstance(check_result[1], str):
                return check_result
            else:
                check_result[1] = self.errordict[str(check_result[1])]
                return check_result

    def check_is_yara(self, filepath):
        try:
            rule = yara.compile(filepath)
            return [True]
        except Exception as e:
            return [False, str(e), filepath]

    def check_meta_key(self, filepath, savetime):
        try:
            #    rb
            f = open(filepath, 'r')
            rules = f.readline()
            if rules.find('-') != -1:
                return [False, 1024, filepath]
            f.seek(0)
            rule = f.read()
            try:
                yr = yaratool.YaraRule(rule)
                if not yr.strings:
                    return [False, 1004, "yara_strings"]
                if not yr.conditions:
                    return [False, 1004, "yara_condition"]
                if len(yr.metas.keys()) >= 10:
                    for key in yr.metas.keys():
                        if key == "judge":
                            if yr.metas[key] in judge_list:
                                continue
                            else:
                                return [False, 1003, key, filepath]

                        if key == "threatname":
                            ret = []
                            ret = self.check_threatname(yr.metas, key, filepath)
                            if not ret[0]:
                                return ret
                            continue

                        if key == "threattype":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            if "threatname" not in yr.metas.keys():
                                return [False, 1015, key, filepath]
                            ret = self.check_threatname(yr.metas, "threatname", filepath)
                            if not ret[0]:
                                return [False, 1016, key, filepath]
                            if '/' in yr.metas["threatname"]:
                                if ',' in yr.metas[key]:
                                    list1 = (yr.metas[key]).split(',')
                                    for i in range(len(list1)):
                                        if not list1[i].upper() in key_threattype:
                                            return [False, 1005, key, filepath]
                                else:
                                    if not yr.metas[key].upper() in key_threattype:
                                        return [False, 1005, key, filepath]
                                continue
                            else:
                                if not yr.metas[key].upper() in behavior_threattype:
                                    return [False, 1018, key, filepath]
                                continue

                        if key == "family":
                            if "threatname" not in yr.metas.keys():
                                return [False, 1015, key, filepath]
                            ret = self.check_threatname(yr.metas, "threatname", filepath)
                            if not ret[0]:
                                return [False, 1016, key, filepath]
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            if '.' not in yr.metas["threatname"]:
                                return [False, 1012, key, filepath]

                            if '/' in yr.metas["threatname"]:
                                if yr.metas[key] != yr.metas["threatname"].split('/')[1].split('.')[1]:
                                    return [False, 1008, key, filepath]
                                continue
                            else:
                                if yr.metas[key] != "unknown":
                                    return [False, 1014, key, filepath]
                                continue

                        if key == "hacker":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            else:
                                continue

                        if key == "refer":
                            if not yr.metas[key] or yr.metas[key] == "None":
                                if self.cfg.upload.back_all:
                                    self.refpath = os.path.join(self.refdir, savetime)
                                    if not os.path.exists(self.refpath):
                                        os.makedirs(self.refpath)
                                    self.filename = filepath.split('/')[-1]
                                    path = os.path.join(self.refpath, self.filename)
                                    shutil.copy(filepath, path)
                                return [False, 1004, key, filepath]
                            if ',' in yr.metas[key]:
                                refer_md5 = yr.metas[key].split(',')
                                for md5 in refer_md5:
                                    if md5[:4] == "http":
                                        continue
                                    elif len(md5) != 32:
                                        return [False, 1010, key, filepath]
                                continue
                            else:
                                if len(yr.metas[key]) != 32:
                                    return [False, 1010, key, filepath]
                                continue

                        if key == "description":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            else:
                                continue

                        if key == "comment":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            else:
                                continue

                        if key == "author":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            else:
                                continue

                        if key == "date":
                            if not yr.metas[key]:
                                return [False, 1004, key, filepath]
                            else:
                                continue
                        else:
                            continue
                    return [True]
                else:
                    return [False, 1017, filepath]
            except BaseException as e:
                return [False, str(e), filepath]
        except Exception as e:
            return [False, str(e), filepath]

    def check_threatname(self, yr_metas, key, filepath):
        if not "threatname" in yr_metas.keys():
            return [False, 1016, key, filepath]
        if not yr_metas[key]:
            return [False, 1004, key, filepath]
        if '.' not in yr_metas[key]:
            return [False, 1009, key, filepath]
        if '/' in yr_metas[key]:
            name_lists = yr_metas[key].split('/')
            if len(name_lists[1].split('.')) < 2:
                return [False, 1021, key, filepath]

            if '[' in name_lists[0]:
                malwaretype = name_lists[0].split('[')[0]
                name_system = name_lists[1].split('.')[0]
                name_threattype = yr_metas[key].split(']')[0].split('[')[1]
                if not malwaretype in ['Trojan', 'Worm', 'Virus', "WebShell"]:
                    return [False, 1006, key, filepath]
                if not name_system in ['Linux', 'Win32', 'MSIL', 'Win64', "Unlimit"]:
                    return [False, 1007, key, filepath]
                if not name_threattype.upper() in key_threattype:
                    return [False, 1005, key, filepath]
            else:
                malwaretype = name_lists[0]
                name_system = name_lists[1].split('.')[0]
                if not malwaretype in ['Trojan', 'Worm', 'Virus', "WebShell"]:
                    return [False, 1006, key, filepath]
                if not name_system in ['Linux', 'Win32', 'MSIL', 'Win64', "Unlimit"]:
                    return [False, 1007, key, filepath]
        else:
            return [False, 1016, key, filepath]
        return [True]


if __name__ == '__main__':
    cyf = check_Yara_Format()
    i = 0
    for root, dirname, filenames in os.walk("/opt/TEST_lsh/te"):
        for filename in filenames:
            res = cyf.check_yara_format(os.path.join(root, filename))
            if not res[0]:
                i = i + 1
                print(res, '========================================')
    print(i)
