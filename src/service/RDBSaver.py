import redis
from service.ConfReader import ConfReader

class RDBSaver():

    def __init__(self):
        database = ConfReader.readConf()
        self.r = redis.StrictRedis(host=database['redis']['server'], port=database['redis']['port'], db=0)

    def saveNodeId(self, name, id):
        self.r.set(name, id)

    def checkNode(self, key):
        return self.r.exists(key)

    def getNode(self, key):
        return self.r.get(key)

    def flushDatabase(self):
        self.r.flushall()