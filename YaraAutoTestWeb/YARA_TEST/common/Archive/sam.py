# coding=utf-8

import requests
import os, sys
import time
import subprocess

# from selenium import webdriver  #导入Selenium
from bs4 import BeautifulSoup  # 导入BeautifulSoup

ROOTDIR = "/".join(os.path.dirname(os.path.realpath(__file__)).split("/")[:-1])
sys.path.append(ROOTDIR)


class file_download():
    def __init__(self):  # 类的初始化操作
        self.proxies = {
            "http": "http://10.10.1.10:3128",
            "https": "http://10.10.1.10:1080"
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1'}  # 给请求指定一个请求头来模拟chrome浏览器
        self.web_url = ['http://www.virscan.org/viruslist/{}'.format(str(i)) for i in range(1, 41)]
        self.web_html = []
        self.md5_path = '/opt/LSH/list.log'
        self.path = '/opt/LSH/YARA_sam/test.log'

    def get_pic(self):
        print('开始网页get请求')
        for url in self.web_url:
            print(url, '====================================')
            try:
                r = requests.get(url, headers=self.headers, timeout=5)
                soup = BeautifulSoup(r.text, 'lxml')
                for a in soup.find_all("table", {"class": "ScannerListTb"}):
                    for b in a.find_all("a"):
                        self.web_html.append(b.get('href'))
            except BaseException as e:
                print(e, '************************************************')
        self.get_file()

    def get_file(self):
        p = 0
        for html in self.web_html:
            k = 0
            file_md5 = []
            file_url = []
            judge = ''
            try:
                r = requests.get(html, timeout=10)
                soup = BeautifulSoup(r.text, 'lxml')
                for a in soup.find_all("table", {"class": "sortable ScannerListTb"}):
                    p = p + 1
                    for b in a.find_all('a'):
                        if 'html' in b.get('href'):
                            md5 = (b.get('href')).split('/')[3].split('.')[0]
                            if md5 not in file_md5:
                                with open(self.md5_path, "a") as f:
                                    f.write(md5 + '\n')
                                f.close()
                                file_md5.append(md5)
                                k = k + 1
                                with open(self.path, "a") as ch:
                                    ch.write(md5 + '  ' + judge + '\n')
                                ch.close()
                        else:
                            url = b.get('href')
                            if url not in file_url:
                                file_url.append(url)
                                t = requests.get(url, headers=self.headers, timeout=5)
                                soup_txt = BeautifulSoup(t.text, 'lxml')
                                for m in soup_txt.find_all("table", {"class": "sortable ScannerListTb_noborder"}):
                                    for n in m.find_all("tr"):
                                        um = n.find('a')
                                        if um == None:
                                            pass
                                        else:
                                            for i in n.find("a"):
                                                if i == 'antiy':
                                                    for j in n.find_all("font"):
                                                        judge = str(j.string)
                                                elif i == 'kaspersky' and judge == 'Found nothing':
                                                    for j in n.find_all("font"):
                                                        judge = str(j.string)
                                                else:
                                                    pass
                        if k == 2:
                            k = 0
                            break
            except BaseException as e:
                print (e, '=====================================')
        print(p, '111111111111111111111111111111')
        # if p==2:
        #     p=0
        #     break
        CMD = ["python", "./Archive/download_.py"]
        subprocess.call(CMD)


if __name__ == '__main__':
    beauty = file_download()
    beauty.get_pic()
