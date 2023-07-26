from KnowledgeGraph.ToLocal.JSONTraverser import *
from KnowledgeGraph.ToLocal.XMLTraverser import *

class TraverserBuilder():
    def new_cve_traverser() -> CVETraverser:
        cvet = CVETraverser()
        return cvet

    def new_capec_traverser() -> CAPECTraverser:
        capect = CAPECTraverser('data/base/capec/CAPEC.xml')
        return capect
    
    def new_attack_traverser() -> ATTACKTraverser:
        attackt = ATTACKTraverser()
        return attackt
    
    def new_cwe_traverser() -> CWETraverser:
        cwet = CWETraverser('data/base/cwe/CWE.xml')
        return cwet