from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver

class PathFinder():
    def __init__(self):
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
        self.rdb.select_database(6)
        self.rdb.r.flushdb()
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        
    def __find_tactic(self):
        print("------Finding Tactic -> Technique------")
        query = "MATCH path=(a:Tactic)-[]-(b:Technique) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            self.rdb.addSet(end_id, start_id)
        
        
    def __find_technique(self):
        print("------Finding Technique -> CAPEC------")
        query = "MATCH path=(a:Technique)-[]-(b:Pattern) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
        
    def __find_pattern(self):
        print("------Finding CAPEC -> CWE------")
        query = "MATCH path=(a:Pattern)-[]-(b:Weakness) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
        
    def __find_weakness(self):
        print("------Finding CWE -> CVE------")
        query = "MATCH path=(a:Weakness)-[]-(b:Vulnerability) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            self.rdb.select_database(6)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
            self.rdb.select_database(5)
        
    def find(self):
        self.__find_tactic()
        self.__find_technique()
        self.__find_pattern()
        self.__find_weakness()
        
    