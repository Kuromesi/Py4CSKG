import redis
from service.ConfReader import ConfReader

class RDBSaver():

    def __init__(self):
        database = ConfReader.readConf()
        self.r = redis.StrictRedis(host=database['redis']['server'], port=database['redis']['port'], password=database['redis']['password'], db=2)

    def saveNodeId(self, name, id):
        self.r.select(2) # Table for node id
        self.r.set(name, id)

    def checkNode(self, key):
        return self.r.exists(key)

    def getNode(self, key):
        return self.r.get(key)

    def flushDatabase(self):
        self.r.flushall()
        
    def select_database(self, num):
        self.r.select(num)
    
    def appendList(self, key, value):
        self.r.lpush(key, value)
        
    def addSet(self, key, value):
        self.r.sadd(key, value)
        
    def checkSet(self, key, value):
        return self.r.sismember(key, value)
        
    def removeKey(self, key):
        self.r.delete(key)

    def saveRDF(self, src, dest, rel):
        self.r.select(0) # Table for relations
        temp = str(rel) + "-+-" + str(dest)
        self.r.sadd(src, temp)
    
if __name__=="__main__":
    rdb = RDBSaver()
    print (rdb)