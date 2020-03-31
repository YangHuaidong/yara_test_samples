# -*- coding: utf-8 -*-

import os, re
import requests
import json
import shutil
import yara
from common.config import Config
from common.aes_rsa import AESCipher
from common.check_repeat_rule import repeat_check

cfg = Config()
aes = AESCipher("_YaraUploadPost_")
workdir = cfg.workdir.path

liburl = cfg.download.liburl
versionurl = cfg.download.versionurl
downloadname = cfg.download.filename
downloadext = cfg.download.ext
libname = cfg.download.libname

tisyaralib = cfg.tis.libpath
tisyaraversion = cfg.tis.versionpath

libdir = os.path.join(workdir, "yaralib")
kfldir = os.path.join(libdir, "kfl_yara")
includefile = os.path.join(kfldir, "newindex.yar")
yaradat = os.path.join(libdir, "yara.dat")
versionfile = os.path.join(libdir, "version.xml")

enfilepath = os.path.join(libdir, downloadname, libname)  ##加密库文件是所在路径

if not os.path.exists(libdir):
    os.mkdir(libdir)


def download():
    if os.path.exists(libdir):
        shutil.rmtree(libdir)
    os.mkdir(libdir)
    try:
        libpath = os.path.join(libdir, "{0}{1}".format(downloadname, downloadext))
        try:
            os.system("wget -O {0} {1}".format(libpath, liburl))
        except Exception as e:
            pass
        try:
            cmdline = "tar -zxf {0} -C {1}".format(libpath, libdir)
            os.system(cmdline)
            decrypt(enfilepath)  ##解密库文件
            cmdline = "tar -zxf {0} -C {1}".format(enfilepath.strip(".aes"), libdir)
            os.system(cmdline)
            os.system("rm -rf {0}".format(os.path.join(libdir, downloadname + downloadext)))
            os.system("rm -rf {0}".format(os.path.join(libdir, downloadname)))
        except Exception as e:
            raise e
    except Exception as e:
        raise e


def decrypt(enfilepath):
    with open(enfilepath.strip(".aes"), "wb") as fw:
        with open(enfilepath, "rb") as fr:
            buf = fr.read()
            decrypt_data = aes.decrypt(buf)
            fw.write(decrypt_data)
        fr.close()
    fw.close()


def addrule():
    tmprule_dir = os.path.join(workdir, "uploads2analyse")
    dirlist = os.listdir(tmprule_dir)
    dirlist.sort(key=lambda i: int(re.match(r'(\d+)', i).group()))

    if dirlist and dirlist[-1].find("ready") != -1:
        last_dirname = dirlist[-1]
        last_dirpath = os.path.join(tmprule_dir, last_dirname)
        for root, dirname, filenames in os.walk(last_dirpath):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                shutil.copyfile(filepath, os.path.join(kfldir, filename))
        tmp_dict = {}
        with open(includefile, "w") as f:
            for root, dirname, filenames in os.walk(kfldir):
                for filename in filenames:
                    if filename == "newindex.yar":
                        pass
                    elif repeat_check(tmp_dict, os.path.join(root, filename)):  ##检测提交了同一规则名称的规则防止编译时出错,规则本身格式没问题,但yara编译器不允许相同的规则名称
                        f.write('include "{0}"\n'.format(filename))
                    else:
                        pass
        f.close()
        processing_dirpath = last_dirpath.replace("ready", "processing")
        os.rename(last_dirpath, processing_dirpath)
        return True, processing_dirpath
    else:
        return False, None


def compiler():
    rule = yara.compile(includefile, includes=True)
    rule.save(yaradat)
    return yaradat


def copy2tis():
    shutil.copyfile(yaradat, tisyaralib)
    shutil.copyfile(versionfile, tisyaraversion)


def update():
    download()
    result, rulepath = addrule()
    print(result, rulepath)
    if result:
        compiler()
        copy2tis()
        return True, rulepath
    else:
        return False, None


if __name__ == "__main__":
    print(update())
