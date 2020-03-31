# -*- coding: UTF-8 -*-
import hashlib


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
    return ret


if __name__ == '__main__':
    ret = md5_file('/home/nginx/html/yara_white_samples/1_finish/js_q8xDii2AkTCSm5Uh6DO2RTo0OT3tUBGfn1aU25aJSk4.js')
    print(ret)
