# -*- coding: utf-8 -*-

import logging
import os

def init_loger(logdir):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # date = str(datetime.date.today())
    # if not os.path.exists(os.path.join(logdir,date)):
    #     os.mkdir(os.path.join(logdir,date))
    fh = logging.FileHandler(os.path.join(logdir,"{0}.{1}".format("yaratest","log")))
    fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')  
    fh.setFormatter(fh_formatter)
    logger.addHandler(fh)
    
    ch = logging.StreamHandler()
    ch_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(ch_formatter)
    logger.addHandler(ch)
    
    
if __name__ == '__main__':
    log = init_loger(os.path.join(logdir,"{0}.{1}".format("yaratest","log")))
    log.info("asdfasdfs")