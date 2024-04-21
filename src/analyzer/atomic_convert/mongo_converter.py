from analyzer.atomic_convert.atomic_converter import AtomicConverter
from ontologies.modeling import AtomicAttack
from service.mongo_connector import new_mongo_connector
from analyzer.utils.generate_atomic_attack import get_privilege_level
from utils import logger
from pymongo import MongoClient

class MongoAtomicConverter(AtomicConverter):
    def __init__(self, connector: MongoClient) -> None:
        if 'knowledge' not in connector.list_database_names():
            raise Exception("knowledge database not found")
        if 'cve' not in connector['knowledge'].list_collection_names():
            raise Exception("cve collection not found")
        self.col = connector['knowledge']['cve']

    def find_by_id(self, cve_id: str) -> AtomicAttack:
        one = self.col.find_one({'id': cve_id})
        if not one:
            logger.error(f"CVE {cve_id} not found")
            return None
        
        cve_des = one['description']
        cvss_v2 = one['cvssV2']
        cvss_v3 = one['cvssV3']
        
        gain = get_privilege_level(cve_des, cvss_v2, cvss_v3)
        score = 0.0
        if cvss_v3:
            access = cvss_v3['cvssV3']['attackVector']
            score = cvss_v3['impactScore']
        elif cvss_v2:
            access = cvss_v2['cvssV2']['accessVector']
            score = cvss_v2['impactScore']
        else:
            logger.error("Neither cvss2 nor cvss3 exists: {cve_id}")
        return AtomicAttack(cve_id, access, gain, score, "None")
        
    def find_by_product(self, product: str, version: str) -> list[AtomicAttack]:
        return super().find_by_product(product, version)