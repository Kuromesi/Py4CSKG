import json
from utils.Config import config
class ConfReader():
    @staticmethod
    def readConf():
        server = config.get("Neo4j", "server")
        username = config.get("Neo4j", "username")
        password = config.get("Neo4j", "password")
        conf = {}
        conf["neo4j"] = {}
        conf["neo4j"]['server'] = server
        conf["neo4j"]['username'] = username
        conf["neo4j"]['password'] = password
        return conf