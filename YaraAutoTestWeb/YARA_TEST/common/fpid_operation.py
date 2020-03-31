# -*- coding: utf-8 -*-
import os
import sys

def findpid_excute(processname):
    """根据进程名称获取进程PID值
    参数：
        processname: 进程名称，如mandatord
    返回值：
        detaillist: 进程详细信息，列表
        pidlist：进程PIDz值，列表
    """
    pidlist,detaillist = [],[]
    ret = os.popen("pgrep %s -a"%(processname))
    lines = ret.readlines()
    ret.close()
    try:
        for line in lines:
            detaillist.append(line)
            pidlist.append(line.split(" ")[0])
    except:
        pass
    return detaillist,pidlist

def findpid_py(pyprocessname):
    """获取python程序进程PID
    参数：
        pyprocessname：python程序
    返回值：
        detaillist: 进程详细信息，列表
        pidlist：进程PIDz值，列表
    """
    pidlist,detaillist = [],[]
    ret = os.popen("pgrep python -a|grep '%s'"%(pyprocessname))
    lines = ret.readlines()
    ret.close()
    try:
        for line in lines:
            detaillist.append(line)
            pidlist.append(line.split(" ")[0])
    except:
        pass
    return detaillist,pidlist

if __name__ == '__main__':
    #print "find excute",findpid_excute("linux1x")
    print("find py",findpid_py("manage.py"))
    # if len(sys.argv)!=3:
    #     print "usage:\n1.python PIDoperation.py -e excuteprocess\n2.python PIDoperation.py -p pythoproc.py"
    # elif sys.argv[1]=="-e":
    #     print findpid_excute(sys.argv[2])[:-1]
    # elif sys.argv[1]=="-p":
    #     print findpid_py(sys.argv[2])[:-1]
    # else:
    #     print "usage:\n1.python PIDoperation.py -e excuteprocess\n2.python PIDoperation.py -p pythoproc.py"
