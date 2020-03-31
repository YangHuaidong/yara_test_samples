# -*- coding: utf-8 -*-

import os, json, re
from common.config import Config


class Result():
    def __init__(self):
        self.cfg = Config()
        curdir = os.path.dirname(os.path.realpath(__file__))

        self.shadowroot = self.cfg.samplepath.white_path
        self.send = self.cfg.sendmail.enable
        self.submit_log = os.path.join(curdir, "submit_log")
        self.result_log = os.path.join(curdir, "result_log")

    def getallpath(self, dirname):
        pathlist = []
        if not os.path.exists(dirname):
            return pathlist

        for rootpath, dirpath, filenames in os.walk(dirname):
            for filename in filenames:
                allpath = os.path.join(rootpath, filename)
                if allpath not in pathlist:
                    pathlist.append(allpath)
        return pathlist

    def judge_status(self):
        pass

    def get_json(self):
        result = []
        filepath = self.getallpath(self.submit_log)

        if not filepath:
            return result
        for path in filepath:
            with open(path, "r") as f:
                submit_time = re.findall("[0-9|-]{3,}", os.path.basename(path))[0]

                path_dict = {}
                path_dict["submit_time"] = submit_time
                path_dict["task_info"] = []

                if path.find("white") != -1:
                    path_dict["samples_type"] = "white"
                elif path.find("black") != -1:
                    path_dict["samples_type"] = "black"

                line = f.readline()
                total_count = -1
                while True:
                    if not line:
                        break
                    try:
                        dict_obj = json.loads(line)
                        task_info = {}
                        try:
                            task_info["md5"] = dict_obj["md5"]
                            path_dict["task_info"].append(task_info)
                        except Exception as e:
                            print(e)
                    except Exception as e:
                        print(e)
                    total_count = total_count + 1
                    line = f.readline()

                path_dict["total_count"] = total_count
                if path_dict not in result:
                    result.append(path_dict)
        return result


if __name__ == '__main__':
    res = Result()

    #"[{[{'md5': '6ac26866e1d5455f26d97812cb668f08'}, {'md5': '5578cf7b84b53548833c135aa2255a41'}, { 'md5': '905f26435625afb877b9f2e8ae0f7bf3'}, {'md5': 'dad3c0aca6320e646c3798c3defd2026'}], 'samples_type': 'white', 'total_count': 2807}]"
