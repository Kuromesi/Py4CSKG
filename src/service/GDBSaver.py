from neo4j import GraphDatabase

from service.ConfReader import ConfReader


class GDBSaver:

    def __init__(self):
        database = ConfReader.readConf()
        self.driver = GraphDatabase.driver(database['neo4j']['server'], auth=(database['neo4j']['username'], database['neo4j']['password']))

    def _exec(self, tx, query):
        result = tx.run(query)
        try:
            return result.single()[0]
        except:
            return 0
    
    def _result(self, tx, query):
        result = tx.run(query)
        try:
            return result.values()
        except:
            return 0
        
    def addSlashes(self, string):
        if isinstance(string, str):
            string = string.replace("\\", "\\\\")
            string = string.replace("\'", "\\\'")
            string = string.replace("\"", "\\\"")
        return string

    def addNode(self, kvpairs):
        driver = self.driver
        query = "CREATE (a:%s) "%kvpairs['prop']
        del kvpairs['prop']
        for (key, value) in kvpairs.items():
            query += "SET a.%s = '%s' "%(key, self.addSlashes(value))
        query += "RETURN id(a)"
        with driver.session() as session:
            nodeid = session.write_transaction(self._exec, query)
        return nodeid

    def addRelation(self, src, dest, relation):
        driver = self.driver
        if (src and dest):
            if (not self.checkRelation(src, dest, relation)):
                query = "MATCH (a) WHERE id(a)=%d MATCH (b) WHERE id(b)=%d CREATE (a)-[r:%s]->(b) RETURN r"%(src, dest, relation)
                with driver.session() as session:
                    session.write_transaction(self._exec, query)
        
    def checkRelation(self, src, dest, relation):
        query = "MATCH(a) WHERE id(a)=%d MATCH(b) WHERE id(b)=%d RETURN EXISTS((a)-[:%s]->(b))"%(src, dest, relation)
        with self.driver.session() as session:
            isExist = session.write_transaction(self._exec, query)
        return isExist

    def checkRelation1(self, dest, relation):
        query = "MATCH (b) WHERE id(b)=%d RETURN EXISTS(()-[:%s]->(b))"%(dest, relation)
        with self.driver.session() as session:
            isExist = session.write_transaction(self._exec, query)
        return isExist

    def clearDatabase(self):
        query = "MATCH (n) DETACH DELETE n RETURN 1"
        with self.driver.session() as session:
            session.write_transaction(self._exec, query)

    def sendQuery(self, query):
        if isinstance(query, list):
            res = []
            with self.driver.session() as session:
                for q in query:
                    res.append(session.write_transaction(self._result, q))
        else:
            with self.driver.session() as session:
                res = session.write_transaction(self._result, query)
        return res

if __name__=="__main__":
    gdb = GDBSaver()
    print (gdb.sendQuery("MATCH (n) RETURN n"))