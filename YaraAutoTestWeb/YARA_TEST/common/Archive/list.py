# -*- coding: UTF-8 -*-
import hashlib
import os


def md5_file(filepath):
    md5_1 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read()
            if data:
                md5_1.update(data)
            else:
                break
    ret = md5_1.hexdigest()
    print(ret)
    with open('/opt/LSH/YARA_sam/Archive/list.log', 'a') as f:
        f.write(ret + '\n')
    f.close()
    # return ret


def list_all_files(rootdir):
    _files = []
    list = os.listdir(rootdir)  # 列出文件夹下所有的目录与文件
    for i in range(0, len(list)):
        path = os.path.join(rootdir, list[i])
        if os.path.isdir(path):
            _files.extend(list_all_files(path))
        if os.path.isfile(path):
            _files.append(path)
    return _files


if __name__ == '__main__':
    _files = list_all_files('/home/nginx/html/Windows')
    print(len(_files))
    for i in _files:
        md5_file(i)
