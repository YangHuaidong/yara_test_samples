#! /bin/bash
source ~/.virtualenvs/yara_rules/bin/activate
cd /home/YaraAutoTestWeb/YARA_TEST/spider_webshell/virus_total
nohup scrapy crawl webshell >> webshell.log 2>&1 &
