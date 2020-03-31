#-*- coding:utf8 -*-

import logging


class Config(object):
    """项目配置信息(父类配置)"""
    DEBUG = True
    SECRET_KEY = 'zhuqing666'



class DevelopmentConfig(Config):
    """开发环境的项目配置信息"""
    DEBUG = True
    # 开发模式的日志级别 DEBUG
    LOG_LEVEL = logging.DEBUG
    #SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:@localhost/project1"



class ProductionConfig(Config):
    """生产环境的项目配置"""
    DEBUG = False

    # 线上模式的日志级别 WARNING
    LOG_LEVEL = logging.WARNING


# 给外界暴露一个使用配置类的接口
# 使用方法:config_dict["development"] --->DevelopmentConfig
config_dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig
}
