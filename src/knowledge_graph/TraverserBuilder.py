from knowledge_graph.ToLocal.JSONTraverser import *
from knowledge_graph.ToLocal.XMLTraverser import *

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