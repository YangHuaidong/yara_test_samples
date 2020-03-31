# -*- coding: utf-8 -*-

from common.fpid_operation import findpid_py


# 获取是否正在解析的状态
def status_query():
    status = {}
    res = findpid_py("reanalyzer.py")[0]
    for i in res:
        date = i.split(" ")[-4].strip()
        dates = date.split(',')
        status[date] = 1
    return status


if __name__ == '__main__':
    print(status_query())
