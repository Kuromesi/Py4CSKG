import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from utils.version_compare import cmp_version
import json
from service.GDBSaver import GDBSaver
from KnowledgeGraph.Ontology.CVE import *
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

    def gen_vul_graph(self, graph):
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
                    if "software" not in temp:
                        temp["software"] = {}
                    temp["software"][software[0]] = cves

            if temp:
                vul_map[node[0]] = temp
        return vul_map

    def find_attack_path(self, src, dst, graph, vul_graph):
        # first check if the dst can be compromised remotely
        # if not, return the dst can not be compromised by moving laterally
        if dst not in vul_graph:
            logger.info("%s is not vulnerable and can not be compromised")
            return
        is_dst_vulnerable = False
        vul_map = vul_graph[dst]
        for component_type, vul_products in vul_map.items():
            for product, entries in vul_products.items():
                for entry in entries:
                    if entry.access in (ACCESS_ADJACENT, ACCESS_NETWORK) and entry.impact != CIA_LOSS:
                        is_dst_vulnerable = True
                        break
        if not is_dst_vulnerable:
            logger.info("%s contains vulnerable components but can not be compromised remotely")
            return

        if not self.attack_graph:
            AG = nx.DiGraph()
            nodes = []
            edges = []
            for node in graph.nodes(data=True):
                if node[0] in vul_graph:
                    max_pos_entry = None
                    vul_map = vul_graph[node[0]]
                    for component_type, vul_products in vul_map.items():
                        for product, entries in vul_products.items():
                            for entry in entries:
                                if entry.access in (ACCESS_ADJACENT, ACCESS_NETWORK) and entry.effect not in (CIA_LOSS, APP_PRIV):
                                    if max_pos_entry:
                                        max_pos_entry = entry if entry.score > max_pos_entry.score else max_pos_entry
                                    else:
                                        max_pos_entry = entry
                    if max_pos_entry:
                        nodes.append((node[0], {"entry": entry}))
                        for neighbor in graph.neighbors(node[0]):
                            if nx.has_path(self.graph, neighbor, node[0]):
                                edges.append((neighbor, node[0], {'weight': max_pos_entry.score}))
            AG.add_nodes_from(nodes)
            AG.add_edges_from(edges)
            self.attack_graph = AG
        shortest_path = nx.shortest_path(self.attack_graph, src, dst, weight="weight")
        paths = nx.all_simple_paths(self.attack_graph, src, dst)

class KGQuery():
    def __init__(self, gs: GDBSaver) -> None:
        self.gs = gs
    
    def find_vuls(self, product, version):
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

        
if __name__ == "__main__":
    G = gen_test_graph()
    ma = ModelAnalyzer()
    ma.find_attack_path(1, 4, G)