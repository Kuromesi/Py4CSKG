from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver

class R2N(): 
    def init(self): 
        self.rs =  RDBSaver()
        self.ds = GDBSaver()

    def r2n(self):
        self.rs.select(0)
        keys = self.rs.r.keys("*")
        for key in keys:
            print(key)
            self.rs.select(0)
            vals = self.rs.r.smembers(key)
            self.rs.select(1)
            for val in vals:
                temp = val.split("-\\+-")
                srcID = self.rs.r.get(key)
                destID = self.rs.r.get(temp[1])
                if destID is not None:
                    self.ds.addRelation(srcID, destID, temp[0])
