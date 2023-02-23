import json
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from utils.version_compare import *

class ModelAnalyzer():
    def __init__(self) -> None:
        self.gs = GDBSaver()
    
    def convert_pyvis(self, graph:dict):
        # Nodes
        color_map = []
        nodes = []
        node_type = {}
        for node in graph['nodes']:
            color_map.append(node.pop('color'))
            id = node.pop('id')
            nodes.append((id, node))
            if node['type'] not in node_type:
                node_type[node['type']] = []
            node_type[node['type']].append({id: node})
            
        # Edges
        edges = []
        for edge in graph['edges']:
            if 'from' in edge and 'to' in edge:
                src = edge.pop('from')
                dest = edge.pop('to')
                edges.append((src, dest, edge))
        
        G = nx.Graph()    
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)
        
        graph = {
            'graph': G,
            'node_type': node_type
            }
        self.graph = graph

    def vul_find(self, product, version):
        query = "MATCH (n:Platform) WHERE n.product='%s' RETURN n"%product
        nodes = self.gs.sendQuery(query)
        vul_product = []
        vuls = {}
        for node in nodes:
            node = node[0]
            version_start = node['versionStart']
            version_end = node['versionEnd']
            if cmp_version(version, version_start) != -1 and cmp_version(version, version_end) != 1:
                vul_product.append(node['uri'])
        if vul_product:    
            query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE"
            for product in vul_product:
                query += " a.uri='%s' OR"%product
            query = query.strip("OR") + "RETURN n"
            nodes = self.gs.sendQuery(query)
            for node in nodes:
                    node = node[0]
                    if node['id'] not in vuls:
                        vuls[node['id']] = node
        # for product in vul_product:
        #     query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE a.uri='%s' RETURN n"%product
        #     nodes = self.gs.sendQuery(query)
        #     for node in nodes:
        #         node = node[0]
        #         if node['id'] not in vuls:
        #             vuls[node['id']] = node
        return vuls
    
    def analyze(self):
        G = self.graph['graph']
        nodes = list(G.nodes(data=True))
        edges = list(G.edges(data=True))
        nt = Network()
        nt.from_nx(G)
        
        print(1)