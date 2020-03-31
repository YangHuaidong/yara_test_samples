# -*- coding: utf-8 -*-
import json
import scrapy
from urllib.parse import urlencode
from ..items import VirusTotalItem


class WebshellSpider(scrapy.Spider):
    name = 'webshell'
    allowed_domains = ['virustotal.com']
    start_urls = ['https://www.virustotal.com']
    API_KEY = 'b1637ab04a2f725d6a852f61c8531a64b2248c4438fd120abd3cb08196235af6'
    # search file api
    BASE_HASH = 'https://www.virustotal.com/vtapi/v2/file/search?'
    query = 'Webshell'

    def start_requests(self):
        parma = {'apikey': self.API_KEY, 'query': self.query}
        url = self.BASE_HASH + urlencode(parma)
        yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        try:
            result = json.loads(response.text)
            item = VirusTotalItem()
            if result['response_code'] == 1:
                item['hash'] = result['hashes']
                item['offset'] = result['offset']
                yield item

                if item['offset']:
                    parma = {'apikey': self.API_KEY, 'query': self.query, 'offset': item['offset']}
                    url = self.BASE_HASH + urlencode(parma)
                    yield scrapy.Request(url, callback=self.parse)

        except Exception as e:
            print(e)
