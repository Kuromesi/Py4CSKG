from KnowledgeGraph.ToLocal.JSONTraverser import *
from KnowledgeGraph.ToLocal.XMLTraverser import *

class TraverserBuilder():
    def new_cve_traverser(self) -> CVETraverser:
        cvet = CVETraverser()
        return cvet

    def new_capec_traverser(self) -> CAPECTraverser:
        capect = CAPECTraverser('data/base/capec/CAPEC.xml')
        return capect
    
    def new_attack_traverser(self) -> ATTACKTraverser:
        attackt = ATTACKTraverser('data/attack/enterpriseN.xml', 'data/attack/tactic.json')
        return attackt
    
    def new_cwe_traverser(self) -> CWETraverser:
        cwet = CWETraverser('data/base/cwe/CWE.xml')
        return cwet