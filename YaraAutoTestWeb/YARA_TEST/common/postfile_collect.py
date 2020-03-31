#-*- coding: utf-8 -*- 
import os,re
import sys
import shutil
from common.config import Config

cfg=Config()

def submit(samplesdir,samplestype = None):

    cfg.update('sampletype','type', samplestype)
    print("Start putting in samples")
    if samplestype == 'white':
        white_sample_path = cfg.samplepath.white_path
        samplepath = files_path(samplestype,white_sample_path)
    elif samplestype =='black':
        black_sample_path = cfg.samplepath.black_path
        samplepath = files_path(samplestype,black_sample_path)
    else:
        pass

    for root,dirname,filenames in os.walk(samplesdir):
        for filename in filenames:
            filepath = os.path.join(root,filename)
            shutil.copy(filepath, samplepath)

def files_path(samplestype,file_path):
    dirlist = os.listdir(file_path)
    dirlist.sort(key = lambda i:int(re.match(r'(\d+)',i).group()))
    if not dirlist:
        last_dirname = "1_ready"
        os.mkdir(os.path.join(file_path,last_dirname))
    else:
        last_dirname = dirlist[-1]
    if samplestype == 'white':
        if last_dirname.find("finish")!=-1:
            num = int(last_dirname.split("_")[0])
            num += 1
            last_dirname = "{0}_ready".format(num)
            os.mkdir(os.path.join(file_path,last_dirname))
    elif samplestype =='black':
        num = int(last_dirname.split("_")[0])
        num += 1
        last_dirname = "{0}_temp".format(num)
        os.mkdir(os.path.join(file_path,last_dirname))
    path = os.path.join(file_path,last_dirname)

    return path

if __name__ == '__main__':
    submit("/home/nginx/html")