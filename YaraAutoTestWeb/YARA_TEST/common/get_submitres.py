# -*- coding: utf-8 -*-

import os, json, re


def get_submitlog():
    result = []

    curdir = os.path.dirname(os.path.realpath(__file__))
    submitlog = os.path.join(curdir, "submit_log")
    if not os.path.exists(submitlog):
        return result

    logspath = []
    for rootpath, dirpath, filenames in os.walk(submitlog):
        for filename in filenames:
            allpath = os.path.join(rootpath, filename)
            if allpath not in logspath:
                logspath.append(allpath)

    for logpath in logspath:
        with open(logpath, "r") as f:
            status_dict = {}
            submit_time = re.findall("[0-9|-]{3,}", os.path.basename(logpath))[0]
            status_dict["submit_date"] = submit_time
            status_dict["submit_status"] = "submiting"

            line = f.readline()
            total_count = -1
            fail_count = 0
            while True:
                if not line:
                    break
                try:
                    dict_obj = json.loads(line)
                    if dict_obj["status"] != 1:
                        fail_count = fail_count + 1
                except:
                    if line == "finished":
                        status_dict["submit_status"] = "finished"
                total_count = total_count + 1
                line = f.readline()

            if status_dict["submit_status"] == "finished":
                status_dict["total_count"] = total_count
                status_dict["fail_count"] = fail_count
            if logpath.find("white") != -1:
                status_dict["samlpes_type"] = "white"
            if logpath.find("black") != -1:
                status_dict["samlpes_type"] = "black"
            if status_dict not in result:
                result.append(status_dict)

    result.sort(key=lambda x: x["submit_date"])

    return result


if __name__ == '__main__':
    test = [1, 2, 3, 4, 5, 6, 7]
    print(test[-3:])
    # get_submitlog()
