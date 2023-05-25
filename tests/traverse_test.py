import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'src'))

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
    cves = [
        'data/CVE/CVE-2002.json', 'data/CVE/CVE-2003.json', 'data/CVE/CVE-2004.json',
        'data/CVE/CVE-2005.json', 'data/CVE/CVE-2006.json', 'data/CVE/CVE-2007.json',
        'data/CVE/CVE-2008.json', 'data/CVE/CVE-2009.json', 'data/CVE/CVE-2010.json',
        'data/CVE/CVE-2011.json', 'data/CVE/CVE-2012.json', 'data/CVE/CVE-2013.json',
        'data/CVE/CVE-2014.json', 'data/CVE/CVE-2015.json', 'data/CVE/CVE-2016.json',
        'data/CVE/CVE-2017.json', 'data/CVE/CVE-2018.json', 'data/CVE/CVE-2019.json',
        'data/CVE/CVE-2020.json', 'data/CVE/CVE-2021.json']
    cvet = CVETraverser()
    # cvet.ds.clearDatabase()
    # cvet.rs.flushDatabase()
    cvet.traverse(cves)
    r2n = R2N()
    r2n.r2n()