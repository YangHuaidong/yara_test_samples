#-*- coding: utf-8 -*- 

import time

def gettime(flag = None):
    if flag == 'time' or flag == None:
        ISOTIMEFORMAT='%Y%m%d-%H%M%S'
        timestr = time.strftime(ISOTIMEFORMAT, time.localtime())
        return timestr
    elif flag == 'data':
        ISODATAFORMAT='%Y%m%d'
        datastr = time.strftime(ISODATAFORMAT, time.localtime())
        return datastr
    else:
        return "param need put in 'data','time' or None"
if __name__ == '__main__':
    print(gettime())