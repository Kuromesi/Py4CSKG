import redis

class RDBSaver():

    def __init__(self):
        self.r = redis.StrictRedis()

    def saveNodeId(self, name, id):
        self.r.set(name, id)

    def checkNode(self, key):
        return self.r.exists(key)

    def getNode(self, key):
        return self.r.get(key)
        
    def flushDatabase(self):
        self.r.flushall()