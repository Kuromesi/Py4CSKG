import json
from analyzer.atomic_convert.atomic_converter import AtomicConverter
from ontologies.modeling import AtomicAttack
from utils import logger
from service import gdb
from analyzer.utils.generate_atomic_attack import get_privilege_level
from ontologies.constants import *
from ontologies.modeling import *
from ontologies.cve import CVEEntry
from utils.version_compare import cmp_version

class Neo4jAtomicConverter(AtomicConverter):

    def find_by_id(self, cve_id: str) -> AtomicAttack:
        try:
            cve_des, access, cvss_v2, cvss_v3 = self.request_cve_id(cve_id)
        except Exception as e:
            logger.error(f"Error in getting cve data: {e}, skipping {cve_id}")
            return None
        
        gain = get_privilege_level(cve_des, cvss_v2, cvss_v3)
        score = 0.0
        if cvss_v3 is not None:
            access = cvss_v3['cvssV3']['attackVector']
            score = cvss_v3['impactScore']
        elif cvss_v2 is not None:
            access = cvss_v2['cvssV2']['accessVector']
            score = cvss_v2['impactScore']
        else:
            logger.error("Neither cvss2 nor cvss3 exists: {cve_id}")
        return AtomicAttack(cve_id, access, gain, score, "None")
    
    def find_by_product(self, product: str, version: str) -> list[AtomicAttack]:
        query = "MATCH (n:Platform) WHERE n.product='%s' AND n.vulnerable='True' RETURN n"%product.replace("_", " ")
        nodes = self.gs.sendQuery(query)
        vul_products = []
        atomic_attacks = []
        for node in nodes:
            node = node[0]
            version_start = node['versionStart']
            version_end = node['versionEnd']
            if cmp_version(version, version_start) != -1 and cmp_version(version, version_end) != 1 or\
                version_start == "-" and version_end == "-" or\
                version_start == "0" and version_end == "0":
                vul_products.append(node['id'])
        query = []
        cves = []
        if vul_products:
            query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE"
            for vul_product in vul_products:
                query += " a.id='%s' OR"%vul_product
            query = query.strip("OR") + "RETURN n"
            results = self.gs.sendQuery(query)
            cves = [CVEEntry(res[0]) for res in results]
        for vul in cves:
            atomic_attacks.append(AtomicAttack(vul.id, vul.access, vul.impact, vul.score, "None"))
        return atomic_attacks
    
    def request_cve_id(self, cve_id):
        logger.info(f"getting cve data: {cve_id}")
        query = f"MATCH (n:Vulnerability) WHERE n.id=\"{cve_id}\" RETURN n"
        nodes = gdb.sendQuery(query)
        if not nodes:
            raise Exception(f"{cve_id} is not recorded")
        des = nodes[0][0]['description']
        cvss3, cvss2 = None, None
        access = ""
        if  nodes[0][0]['baseMetricV3'] != "{}":
            cvss3 = json.loads(nodes[0][0]['baseMetricV3'])
            access = cvss3['cvssV3']['attackVector']
        if nodes[0][0]['baseMetricV2'] != "{}":
            cvss2 = json.loads(nodes[0][0]['baseMetricV2'])
            if not access:
                access = cvss2['cvssV2']['accessVector']
        if cvss2 or cvss3:
            return des, access, cvss2, cvss3
        raise Exception(f"neither cvss2 nor cvss3 exists: {cve_id}")