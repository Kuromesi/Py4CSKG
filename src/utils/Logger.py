import logging

class Logger():

    # 初始化 Logger
    def __init__(self,
                 name='root',
                 logger_level= 'INFO',
                 file=None,
                 logger_format = '[%(asctime)s]-[%(levelname)s]-%(message)s'
                 ):

        logger = logging.getLogger(name)
        logger.setLevel(logger_level)
        fmt = logging.Formatter(logger_format)

        if file:
            file_handler = logging.FileHandler(file)
            file_handler.setLevel(logger_level)
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logger_level)
        stream_handler.setFormatter(fmt)
        logger.addHandler(stream_handler)
        self.logger = logger

    def debug(self,msg):
        return self.logger.debug(msg)

    def info(self,msg):
        return self.logger.info(msg)

    def warning(self,msg):
        return self.logger.warning(msg)

    def error(self,msg):
        return self.logger.error(msg)

    def critical(self,msg):
        return self.logger.critical(msg)
    
logger = Logger()