# -*- coding: utf-8 -*-

import smtplib
import json

from email import encoders
from email.header import Header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parseaddr, formataddr
from email.mime.application import MIMEApplication

from .mail_conf import conf


class SendMail():
    def __init__(self, att_path, py_data="", bad_rule={}):
        self.py_data = py_data
        self.bad_rule = bad_rule
        self.att_path = att_path
        self.filename = ''

    # def _format_addr(self, s):
    #     name, addr = parseaddr(s)
    #     # return formataddr((Header(name, 'utf-8').encode(),addr.encode('utf-8') if isinstance(addr, str) else addr))


    def htmlcontent(self):
        if self.py_data["samples_type"] == "black":
            htmlstr = u"<html> \
                             <p>投放样本时间:%s</p> <p>样本类型:%s</p> <p>重解析开始时间:%s</p> <p>解析结束时间:%s</p> \
                             <p>投放成功总数:%s</p> \
                             <table> \
                                <tr> <td>yara检出率</td> </tr> \
                                <tr> <td>%s</td> </tr> \
                             </table> \
                       </html>" \
                      % (self.py_data["sumbit_date"],
                         self.py_data["samples_type"], \
                         self.py_data["reanalysis_starttime"], \
                         self.py_data["analysis_date"], \
                         self.py_data["total_count"], \
                         self.py_data["yara"]["yara_percent"])
            self.filename = self.py_data["sumbit_date"] + '未检出工单.xls'
            return htmlstr
        else:
            htmlstr = u"<p>投放样本时间:%s</p> <p>样本类型:%s</p> <p>重解析开始时间:%s</p> <p>解析结束时间:%s</p> <p>投放成功总数:%s</p> \
                        <table> \
                          <tr> <td>yara误报率</td> </tr> \
                          <tr> <td>%s</td> </tr> \
                        </table>" \
                      % (self.py_data["sumbit_date"],
                         self.py_data["samples_type"], \
                         self.py_data["reanalysis_starttime"], \
                         self.py_data["analysis_date"], \
 \
                         self.py_data["total_count"], \
                         self.py_data["yara"]["yara_percent"])

            sum_li = ""
            for key in self.bad_rule.keys():
                li = u"<li>误报规则:{0} 规则提交人:{1}</li>".format(key, self.bad_rule[key])
                sum_li += li
            self.filename = self.py_data["sumbit_date"] + '误报工单.xls'
            return u"<html>{0}</html>".format(htmlstr + sum_li)

    def constructmail(self):
        msg = MIMEMultipart()
        msg_text = MIMEText(self.htmlcontent(), 'html', 'utf-8')
        msg.attach(msg_text)
        msg['From'] = Header('批量测试 <{0}>'.format(conf["from"]), 'utf-8')
        msg['To'] = Header('管理员', 'utf-8')
        msg['Subject'] = Header('批量测试结果', 'utf-8')
        att = MIMEText(open(self.att_path, "rb").read(), 'base64', 'utf-8')
        att['Content-type'] = 'application/octet-stream'
        att.add_header('Content-Disposition', 'attachment', filename=self.filename)
        msg.attach(att)
        return msg

    def sendmail(self, MAIL_TO):
        server = smtplib.SMTP()
        server.connect(conf["mailhost"], "587")
        server.starttls()
        server.login(conf["username"], conf["password"])
        server.sendmail(conf["from"], MAIL_TO, self.constructmail().as_string())

        print("send email succeess.")
        server.quit()


if __name__ == '__main__':
    data = {
        "yara": {
            "yara_percent": "0.00%",
            "details": [],
            "yara_count": 1
        },
        "total_count": 38382,
        "analysis_date": "20190226-130002",
        "samples_path": "/home/nginx/html/yara_white_samples/2_finish",
        "sumbit_date": "20190226-115749",
        "reanalysis_starttime": "",
        "samples_type": "black"
    }
    MAIL_TO = '327086445@qq.com'
    an = SendMail("/home/YaraAutoTestWeb/YARA_TEST/core/excel_log/white/20190226-130520.xls", data,
                  {"Trojan_Backdoor_Liunx_BitCoinMiner_B_729": "abc"})
    an.sendmail(MAIL_TO)
