from service.GDBSaver import GDBSaver
import os, sys, json
from KnowledgeGraph.ToLocal.JSONTraverser import *
from KnowledgeGraph.ToLocal.XMLTraverser import *
from KnowledgeGraph.TraverserBuilder import *

class KGBuilder():
    def __init__(self) -> None:
        self.gdb = GDBSaver()

    def update_cve_type(self, path):
        paths = []
        if os.path.isdir(path):
            paths = os.listdir(path)
        else:
            paths.append(path)
        for path in paths:
            if os.path.splittext(path)[-1] == ".json":
                with open(path, 'r') as f:
                    cve = json.load(f)
                queries = []
                for k, v in cve:
                    query = "MATCH (n:Vulnerability) WHERE n.id=%s SET n.type=%s"
                    queries.append(query)
                self.gdb.sendQuery(queries)

    def to_csv_neo4j(self):
        """convert knowledge bases to csv format which could be directly loaded by neo4j
        """        
        logger.info("Starting to convert raw data into neo4j csv format")
        if not os.path.exists("./data/neo4j/nodes"):
            os.makedirs("./data/neo4j/nodes")
        if not os.path.exists("./data/neo4j/relations"):
            os.makedirs("./data/neo4j/relations")
        cvet = TraverserBuilder.new_cve_traverser()
        cwet = TraverserBuilder.new_cwe_traverser()
        capect = TraverserBuilder.new_capec_traverser()
        attackt = TraverserBuilder.new_attack_traverser()
        # attackt.traverse()
        cvet.traverse()
        capect.traverse()
        cwet.traverse()