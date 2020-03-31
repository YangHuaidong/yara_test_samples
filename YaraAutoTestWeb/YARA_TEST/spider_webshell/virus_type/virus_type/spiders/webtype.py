# -*- coding: utf-8 -*-
import json
import os
from urllib.parse import urlencode

import scrapy
from scrapy import Request
from ..items import VirusTypeItem

curdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

virus_total = os.path.join(curdir, 'virus_total')
virus_total_hash = os.path.join(virus_total, 'hash')


class WebtypeSpider(scrapy.Spider):
    name = 'webtype'
    allowed_domains = ['virustotal.com']
    start_urls = ['https://www.virustotal.com']
    API_KEY = 'b1637ab04a2f725d6a852f61c8531a64b2248c4438fd120abd3cb08196235af6'
    # 检索文件扫描报告
    BASE_TYPE = 'https://www.virustotal.com/vtapi/v2/file/report?'


    def start_requests(self):
        dirlist = os.listdir(virus_total_hash)
        dirlist.sort(key=lambda x: int(x[5:-5]))
        last_dirname = dirlist[-1]
        # for i in dirlist:
        #     path_1 = virus_total_hash + '/' + i
        path_1 = virus_total_hash + '/' + last_dirname
        with open(path_1, 'r')as f:
            f.seek(0)
            line = f.readlines()
            for y in line:
                hash = json.loads(y)
                for i in hash['hash']:
                    param = {'resource': i, 'apikey': self.API_KEY, 'allinfo': '1'}
                    url = self.BASE_TYPE + urlencode(param)
                    yield Request(url, callback=self.parse)

    def parse(self, response):
        item = VirusTypeItem()
        result = json.loads(response.text)
        if result['response_code'] == 1:
            scan_detail = {}
            for av in result['scans'].keys():
                if result['scans'][av]['detected']:
                    scan_detail[av] = result['scans'][av]['result']
            count = 0
            for sour in scan_detail.keys():
                if sour in ['FireEye', 'Kaspersky', 'Microsoft', 'McAfee', 'Antiy_avl']:
                    count += 1
            if count == 0:
                return

            item['content'] = {
                'scans': "%s/%s" % (result['positives'], result['total']),
                'last_seen': result['last_seen'],
                'ITW_urls': result['ITW_urls'],
                'format': result['type'],
                'scans_detail': scan_detail,
                'sha1': result['sha1'],
                'sha256': result['sha256'],
                'md5': result['md5'],
                'tags': result['tags'],
            }

            yield item
