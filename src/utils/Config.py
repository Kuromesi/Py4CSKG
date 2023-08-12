import configparser


class ConfigBuilder():
    def new_config_parser(path):
        cp = configparser.ConfigParser()
        cp.read(path)
        return cp
    
config = ConfigBuilder.new_config_parser("./config.cfg")