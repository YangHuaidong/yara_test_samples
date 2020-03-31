import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from config import config_dict


def setup_log(config_name):
    """记录日志的配置"""
    # 根据传入的配置字符串获取不配置
    configClass = config_dict[config_name]
    logging.basicConfig(level=configClass.LOG_LEVEL)
    file_log_handler = RotatingFileHandler("logs/log", maxBytes=1024 * 1024 * 100, backupCount=10)
    formatter = logging.Formatter('%(levelname)s %(filename)s:%(lineno)d %(message)s')
    file_log_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_log_handler)


def create_app(config_name):
    """创建app方法,工厂方法"""
    # 0.记录日志
    setup_log(config_name)

    # 1.创建app对象
    app = Flask(__name__)

    # development -->DevelopmentConfig 开发模式的配置类
    # production --->ProductionConfig 线上模式的配置类
    configClass = config_dict[config_name]

    # 将配置类注册到app上 根据配置的不同类 赋予不用模式的app
    app.config.from_object(configClass)

    # 注册蓝图
    # 真正用到蓝图对象的时候才导入,延迟导入(只有函数被调用才回来导入) 解决循环导入问题
    # 注册首页的蓝图对象
    from info.core.index import index_bp
    app.register_blueprint(index_bp)

    from info.core.analysis_sample import analysis_sample_bp
    app.register_blueprint(analysis_sample_bp)


    from info.core.upload_yara import upload_yara_bp
    app.register_blueprint(upload_yara_bp)






    # 返回不同模式下的app对象
    return app
