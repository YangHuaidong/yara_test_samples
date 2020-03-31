#! /bin/bash
source ~/.virtualenvs/yara_rules/bin/activate
cd /home/YaraAutoTestWeb/YARA_TEST/spider_webshell/virus_type
nohup scrapy crawl webtype >> webtype.log 2>&1 &
