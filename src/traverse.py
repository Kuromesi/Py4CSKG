from traversers.XMLTraverser import *
from traversers.JSONTraverser import *
from service.R2N import *

if __name__ == '__main__':
    attackt = ATTACKTraverser('data/attack/enterprise.xml', 'data/attack/tactic.json')
    attackt.ds.clearDatabase()
    attackt.rs.flushDatabase()
    attackt.traverse()
    capect = CAPECTraverser('data/CAPEC/CAPEC.xml')
    # capect.ds.clearDatabase()
    # capect.rs.flushDatabase()
    capect.traverse()
    cwet = CWETraverser('data/CWE/CWE.xml')
    # cwet.ds.clearDatabase()
    # cwet.rs.flushDatabase()
    cwet.traverse()
    cves = ['data/CVE/CVE-2021.json']
    cvet = CVETraverser()
    # cvet.ds.clearDatabase()
    # cvet.rs.flushDatabase()
    cvet.traverse(cves)
    r2n = R2N()
    r2n.r2n()