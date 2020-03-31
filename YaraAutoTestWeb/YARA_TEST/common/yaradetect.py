# -*- coding: UTF-8 -*-
import os
import traceback

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False
from common.md5 import md5_file

curdir = os.path.dirname(os.path.realpath(__file__))
print(curdir)


def get_yara(file_path):
    """Get Yara signatures matches.
    @return: matched Yara signatures.
    """
    global result
    result = []
    curdir = os.path.dirname(os.path.realpath(__file__))
    ruledata = os.path.join(curdir, "rule", "yara.dat")
    if HAVE_YARA:
        try:
            rules = yara.load(ruledata)
            rules.match(file_path, callback=callback)
            return result
        except Exception as e:
            print(traceback.print_exc())
            return None


def callback(data):
    if data["matches"] == True:
        redict = {}
        redict["rulename"] = data["rule"]
        redict["meta"] = data["meta"]
        result.append(redict)
    return yara.CALLBACK_CONTINUE


if __name__ == '__main__':
    rootdir = '/home/nginx/html/yara_black_samples/2_finish'
    i = 0
    data = []
    for root, dirname, filenames in os.walk(rootdir):
        for filename in filenames:
            filepath = os.path.join(root, filename)
            md5 = md5_file(filepath)
            list_yara = get_yara(filepath)
            if list_yara:
                info = {}
                info["md5"] = md5
                info["info"] = list_yara
                data.append(info)
                i = i + 1

    print(data)
    print(i)
