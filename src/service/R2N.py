from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from tqdm import tqdm

class R2N(): 
    def __init__(self): 
        self.rs =  RDBSaver()
        self.ds = GDBSaver()

    def r2n(self):
        self.rs.r.select(0)
        keys = self.rs.r.keys("*")
        keys = tqdm(keys)
        for key in keys:
            key = key.decode()
            keys.set_postfix(key=key)
            self.rs.r.select(0)
            vals = self.rs.r.smembers(key)
            self.rs.r.select(2)
            srcID = self.rs.r.get(key)
            if srcID:
                for val in vals:
                    val = val.decode()
                    temp = str(val).split("-+-")
                    destID = self.rs.r.get(temp[1])
                    if destID:
                        self.ds.addRelation(int(srcID), int(destID), temp[0])
