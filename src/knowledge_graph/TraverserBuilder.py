from knowledge_graph.ToLocal.JSONTraverser import *
from knowledge_graph.ToLocal.XMLTraverser import *
from utils.Logger import logger
from utils.Config import config

class TraverserBuilder():
    def new_cve_traverser() -> CVETraverser:
        cvet = CVETraverser()
        return cvet

    def new_capec_traverser() -> CAPECTraverser:
        capect = CAPECTraverser()
        return capect
    
    def new_attack_traverser() -> ATTACKTraverser:
        attackt = ATTACKTraverser()
        return attackt
    
    def new_cwe_traverser() -> CWETraverser:
        cwet = CWETraverser()
        return cwet

class KGBuilder():
    def __init__(self) -> None:
        self.cve_traverser = CVETraverser()
        self.capec_traverser = CAPECTraverser()
        self.attack_traverser = ATTACKTraverser()
        self.cwe_traverser = CWETraverser()

    def traverse_cve(self) -> bool:
        try:
            self.cve_traverser.traverse()
        except Exception as e:
            logger.error(f"failed to traverse cve: {e}")
            return False
        return True
    
    def traverse_capec(self) -> bool:
        try:
            self.capec_traverser.traverse()
        except Exception as e:
            logger.error(f"failed to traverse capec: {e}")
            return False
        return True
    
    def traverse_attack(self) -> bool:
        try:
            self.attack_traverser.traverse()
        except Exception as e:
            logger.error(f"failed to traverse attack: {e}")
            return False
        return True
    
    def traverse_cwe(self) -> bool:
        try:
            self.cwe_traverser.traverse()
        except Exception as e:
            logger.error(f"failed to traverse cwe: {e}")
            return False
        return True

    def traverse_all(self):
        base = config.get("KnowledgeGraph", "base_path")
        logger.info("starting to convert raw data into neo4j csv format")
        if not os.path.exists(os.path.join(base, "neo4j/nodes")):
            os.makedirs(os.path.join(base, "neo4j/nodes"))
        if not os.path.exists(os.path.join(base, "neo4j/relations")):
            os.makedirs(os.path.join(base, "neo4j/relations"))
        total, success = 4, 4
        failed_list = []
        if not self.traverse_capec():
            success -= 1
            failed_list.append("capec")
        if not self.traverse_attack():
            success -= 1
            failed_list.append("att&ck")
        if not self.traverse_cwe():
            success -= 1
            failed_list.append("cwe")
        if not self.traverse_cve():
            success -= 1
            failed_list.append("cve")
        logger.info(f"{success}/{total} traversal success")
        if failed_list:
            logger.warning(f"failed to traverse [{' '.join(failed_list)}]")