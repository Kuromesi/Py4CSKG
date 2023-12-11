import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from utils.version_compare import cmp_version
import json
from service.GDBSaver import GDBSaver
from knowledge_graph.Ontology.CVE import *
from analyzer.tests.tests import gen_test_graph
from utils.Logger import logger

class ModelAnalyzer():
    def __init__(self, gs, graph) -> None:
        logger.info("Initializing ModelAnalyzer")
        self.kg = KGQuery(gs)
        vul_graph = self.gen_vul_graph(graph)
        self.graph = graph
        self.vul_graph = vul_graph
        self.attack_graph = None

    def gen_vul_graph(self, graph: dict):
        """return data like
        {
            node_name: {
                os: {
                    product_name: [CVEEntry]
                }
            }
        }

        Args:
            graph (_type_): _description_
        """        
        logger.info("Analyzing vulnerabilities")
        vul_map = {}
        for node in graph.nodes(data=True):
            temp = {}
            cves = []
            for os in node[1]["os"]:
                cves = self.kg.find_vuls(os[0], os[1])
                if cves:
                    if "os" not in temp:
                        temp["os"] = {}
                    temp["os"][os[0]] = cves

            for firware in node[1]["firmware"]:
                cves = self.kg.find_vuls(firware[0], firware[1])
                if cves:
                    if "firware" not in temp:
                        temp["firware"] = {}
                    temp["firware"][firware[0]] = cves
                
            for software in node[1]["software"]:
                cves = self.kg.find_vuls(software[0], software[1])
                if cves:
                    for cve in cves:
                        cve.access = software[2] if cmp_access(cve.access, software[2]) < 0 else cve.access
                    if "software" not in temp:
                        temp["software"] = {}
                    temp["software"][software[0]] = cves

            if node[1]["cve"]:
                cves.extend(self.kg.get_vuls(node[1]["cve"]))
            temp["other"] = {}
            temp["other"]["cve"] = cves
            if temp:
                vul_map[node[0]] = {}
                vul_map[node[0]]['vuls'] = temp
                vul_map[node[0]]['entry'] = node[1]['entry']
        return vul_map

    def find_attack_path(self, src: str, dst: str, graph: nx.Graph, vul_graph: dict):
        # first check if the dst can be compromised remotely
        # if not, return the dst can not be compromised by moving laterally
        if dst not in vul_graph:
            logger.info("%s is not vulnerable and can not be compromised")
            return
        is_dst_vulnerable = False
        vul_map = vul_graph[dst]['vuls']
        for component_type, vul_products in vul_map.items():
            for product, entries in vul_products.items():
                for entry in entries:
                    if entry.access in (ACCESS_ADJACENT, ACCESS_NETWORK) and entry.impact != CIA_LOSS:
                        is_dst_vulnerable = True
                        break
        if not is_dst_vulnerable:
            logger.info(f"({dst}) contains vulnerable components but can not be compromised remotely")
            # return

        if not self.attack_graph:
            AG = nx.DiGraph()
            nodes = []
            edges = []
            for node in graph.nodes(data=True):
                max_pos_entry = None
                if not node[1]['os'] and not node[1]['hardware'] and not node[1]['firmware'] and not node[1]['software'] and not node[1]['cve']:
                    max_pos_entry = CVEEntry()
                if node[0] in vul_graph:
                    vul_map = vul_graph[node[0]]['vuls']
                    for component_type, vul_products in vul_map.items():
                        for product, entries in vul_products.items():
                            for entry in entries:
                                if self.is_node_access(entry.access, vul_graph[node[0]]['entry']) and entry.effect not in (CIA_LOSS, APP_PRIV):
                                # if entry.access in (ACCESS_ADJACENT, ACCESS_NETWORK) :
                                    if max_pos_entry:
                                        max_pos_entry = entry if entry.score > max_pos_entry.score else max_pos_entry
                                    else:
                                        max_pos_entry = entry
                if max_pos_entry:
                    nodes.append((node[0], {"entry": max_pos_entry}))
                    for neighbor in graph.neighbors(node[0]):
                        if nx.has_path(self.graph, neighbor, node[0]):
                            edges.append((neighbor, node[0], {'weight': max_pos_entry.score}))
            AG.add_nodes_from(nodes)
            AG.add_edges_from(edges)
            self.attack_graph = AG
            nx.draw_networkx(AG)
            plt.show()      
        try:
            shortest_path = nx.shortest_path(self.attack_graph, src, dst, weight="weight")
            logger.info("Shortest attack path generated")
            self.print_path([shortest_path])
        except Exception as e:
            logger.error(e)
        paths = nx.all_simple_paths(self.attack_graph, src, dst)
        if paths:
            logger.info("All attack paths generated")
            self.print_path(paths)

    def print_path(self, paths):
        idx = 1
        print("Attack path: ")
        for path in paths:
            print(f"\t[{idx}] " + " --> ".join(path))
            idx += 1

    def is_node_access(self, access, entry) -> bool:
        is_access = cmp_access(access, ACCESS_ADJACENT) >= 0
        is_access = is_access or entry and access != ACCESS_PHYSICAL
        return is_access

class KGQuery():
    def __init__(self, gs: GDBSaver) -> None:
        self.gs = gs
    
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
            if cmp_version(version, version_start) != -1 and cmp_version(version, version_end) != 1:
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
        
if __name__ == "__main__":
    G = gen_test_graph()
    ma = ModelAnalyzer()
    ma.find_attack_path(1, 4, G)