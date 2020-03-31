# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://doc.scrapy.org/en/latest/topics/item-pipeline.html
import codecs
import json
import os

from .get_time import gettime

curdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_ = os.path.join(curdir, 'json')


class VirusTypePipeline(object):
    def __init__(self):
        self.hash_name = json_ + '/' + 'extract_' + gettime() + '.json'
        self.filename = codecs.open(self.hash_name, 'a', encoding="utf-8")

    def process_item(self, item, spider):
        content = json.dumps(dict(item), ensure_ascii=False)
        self.filename.write(content + '\n')
        return item

    def spider_closed(self, spider):
        self.filename.close()
