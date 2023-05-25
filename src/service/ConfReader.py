import json

class ConfReader():
    @staticmethod
    def readConf():
        with open('src/service/resources/database.json', 'r') as f:
            conf = json.load(f)
        return conf