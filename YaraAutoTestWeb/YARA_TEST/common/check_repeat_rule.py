#-*- coding: utf-8 -*- 
# ****************************
# shadowbox test web project
# author@zq 2018/05/10
# ******************************

def repeat_check(tmp_dict,filepath):
    with open(filepath,"r") as f:
        line = f.readline()
        while 1:
            if not line:
                break
            if line.find("rule")!=-1:
                if line in tmp_dict:
                    return False
                else:
                    tmp_dict[line] = None
                    return True
            line = f.readline()

