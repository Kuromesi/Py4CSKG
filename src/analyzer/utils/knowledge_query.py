from service import gdb
from ontologies.cve import CVEEntry
from utils.version_compare import cmp_version

class KGQuery():
    def __init__(self) -> None:
        self.gs = gdb
    
    def find_vuls(self, product, version) -> list[CVEEntry]:
        """_summary_

        Args:
            product (string): _description_
            version (string): _description_

        Returns:
            _type_: _description_
        """        
        query = "MATCH (n:Platform) WHERE n.product='%s' AND n.vulnerable='True' RETURN n"%product.replace("_", " ")
        nodes = self.gs.sendQuery(query)
        vul_products = []
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
        return cves

    def get_vuls(self, cves):
        ret = []
        for cve in cves:
            query = f"MATCH (n:Vulnerability) WHERE n.id='{cve}' RETURN n"
            result = self.gs.sendQuery(query)
            ret.append(CVEEntry(result[0][0]))
        return ret