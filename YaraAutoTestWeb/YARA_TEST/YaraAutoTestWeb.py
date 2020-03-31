import os
import sys

from info import create_app
from gevent import monkey
from gevent.pywsgi import WSGIServer

# curdir =os.path.dirname(os.path.realpath(__file__))
# common = os.path.join(curdir,'common')
# sys.path.append(common)
curdir =os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(curdir)


print(curdir)

monkey.patch_all()

"""
从单一职责的思想考虑:YaraAutoTestWeb.py 文件仅仅作为项目的启动文件即可,其余配置全部抽取出去
"""

# 创建 app，并传入配置模式：development / production
app = create_app("development")

if __name__ == '__main__':
    print("TIS auto test web is running...")
    http_server = WSGIServer(('', 8081), app)
    http_server.serve_forever()
    # app.run(host='0.0.0.0', port=8081)
