# -*- coding: utf-8 -*-
import os, json, re


def post_summary(samples_type):
    """输出检测结果日志"""
    result = []

    curdir = os.path.dirname(os.path.realpath(__file__))
    resultlog = os.path.join(curdir, "result_log", samples_type)
    if not os.path.exists(resultlog):
        return result

    for rootpath, dirpath, filenames in os.walk(resultlog):
        logspath = filenames

        for path in logspath:
            logpath = os.path.join(resultlog, path)
            with open(logpath, "r") as f:
                try:
                    dict_obj = json.load(f)
                    for key in dict_obj.keys():
                        if key == "yara":
                            if "details" in dict_obj[key]:
                                dict_obj[key].pop("details")
                    result.append(dict_obj)
                except:
                    pass

    result.sort(key=lambda x: x["sumbit_date"])
    print(result)

    return result


def post_details(sumbit_date, check_type, samples_type):
    """"""
    curdir = os.path.dirname(os.path.realpath(__file__))
    resultlog = os.path.join(curdir, "result_log", samples_type)
    if not os.path.exists(resultlog):
        return None

    for rootpath, dirpath, filenames in os.walk(resultlog):
        logspath = filenames

        for path in logspath:
            logpath = os.path.join(resultlog, path)
            with open(logpath, "r") as f:
                try:
                    dict_obj = json.load(f)
                    if dict_obj["sumbit_date"] == sumbit_date:
                        return dict_obj[check_type]
                except Exception as e:
                    print(e)


if __name__ == '__main__':
    post_summary("black")
    for i in ["white", "black"]:
        summary = post_summary(i)
        num = len(summary)
        for item in summary:
            num -= 1
            # try:
            #     CMD = ["python", "./reanalyzer.py", item["sumbit_date"], rulepath, str(num), i]
            #     subprocess.call(CMD)
            # except Exception as e:
            #     print(e, '================')
            print(item["sumbit_date"])
            print(str(num))
            print(i)