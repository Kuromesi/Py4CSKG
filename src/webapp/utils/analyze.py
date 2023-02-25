import json
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from utils.version_compare import *
import pandas as pd
from utils.prediction import *

class ModelAnalyzer():
    def __init__(self) -> None:
        self.gs = GDBSaver()
        # self.cve2capec = CVE2CAPEC()
        self.cve2cwe = CVE2CWE()
    
    def convert_pyvis(self, graph:dict):
        '''
        Receive pyvis json format graph from frontend and convert it into networkx grapg.
        '''
        # Nodes
        color_map = []
        nodes = []
        node_type = {
            'software': [],
            'hardware': [],
            'os': [],
            'firmware': [],
            'component': [],
            'defender': [],
            'entry': []
        }
        for node in graph['nodes']:
            # color_map.append(node.pop('color'))
            # id = node.pop('id')
            color_map.append(node['color'])
            id = node['id']
            nodes.append((id, node))
            if node['type'] not in node_type:
                node_type[node['type']] = []
            node_type[node['type']].append({id: node}) # Classified with corresponding ontologies
            
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
        self.G = G

    def vul_find(self, product, version):
        query = "MATCH (n:Platform) WHERE n.product='%s' RETURN n"%product
        nodes = self.gs.sendQuery(query)
        vul_products = []
        vuls = {}
        vul_report = pd.DataFrame(columns=['Product', 'CVE-ID', 'CVE-Description'])
        for node in nodes:
            node = node[0]
            version_start = node['versionStart']
            version_end = node['versionEnd']
            if cmp_version(version, version_start) != -1 and cmp_version(version, version_end) != 1:
                vul_products.append(node['uri'])
        if vul_products:
            query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE"
            for vul_product in vul_products:
                query += " a.uri='%s' OR"%vul_product
            query = query.strip("OR") + "RETURN n"
            nodes = self.gs.sendQuery(query)
            for node in nodes:
                node = node[0]
                if node['id'] not in vuls:
                    vuls[node['id']] = node
                vul_report.loc[len(vul_report.index)] = [product, node['id'], node['des']]
        self.vul_analyze(vul_report)
        # for product in vul_product:
        #     query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE a.uri='%s' RETURN n"%product
        #     nodes = self.gs.sendQuery(query)
        #     for node in nodes:
        #         node = node[0]
        #         if node['id'] not in vuls:
        #             vuls[node['id']] = node
        return vuls
    
    def vul_analyze(self, vul_report):
        '''
        Find related CAPEC, CWE, ATT&CK, CVSS and make a summary.
        '''
        cwe_df = pd.DataFrame(columns=['CWE-ID', 'Name', 'Description', 'Count'])
        for index, row in vul_report.iterrows():
            cve = row['CVE-ID']
            query = "MATCH (n:Vulnerability)<-[:observed_example]-(m:Weakness) WHERE n.id='%s' RETURN m"%cve
            cwes = self.gs.sendQuery(query)
            if cwes:
                for cwe in cwes:
                    cwe = cwe[0]
                    if cwe['id'] in cwe_df['CWE-ID'].values:
                        cwe_df.loc[cwe_df['CWE-ID'] == cwe['id'], 'Count'] += 1
                    else:
                        cwe_df.loc[len(cwe_df.index)] = [cwe['id'], cwe['name'], cwe['des'], 1]
            else:
                cwe = self.cve2cwe.predict(row['CVE-Description'])
                query = "MATCH (n:Weakness) WHERE n.id='%s' RETURN n"%cwe
                cwe = self.gs.sendQuery(query)
                if cwe:
                    cwe = cwe[0][0]
                    if cwe['id'] in cwe_df['CWE-ID'].values:
                            cwe_df.loc[cwe_df['CWE-ID'] == cwe['id'], 'Count'] += 1
                    else:
                        cwe_df.loc[len(cwe_df.index)] = [cwe['id'], cwe['name'], cwe['des'], 1]
        print(1)
        

    def __find_vul_nodes(self, nodes, vul_nodes):
        for node in nodes:
            for key in node:
                product = node[key]['product']
                version = node[key]['version']
                vuls = self.vul_find(product, version)
                if vuls:
                    vul_nodes.append(key)
                    neighbors = [n for n in self.G.neighbors(key)]
                    vul_nodes.extend(neighbors)
    
    def analyze(self):
        node_type = self.graph['node_type']
        
        # Find vulnerabilities
        vul_nodes = []
        self.__find_vul_nodes(node_type['software'], vul_nodes)
        self.__find_vul_nodes(node_type['hardware'], vul_nodes)
        self.__find_vul_nodes(node_type['os'], vul_nodes)
        
        vul_node_attrs = {}
        for vul_node in vul_nodes:
            vul_node_attrs[vul_node] = {'color': "#ff0000"}
        nx.set_node_attributes(self.G, vul_node_attrs)
        
                    
        
        nt = Network()
        nt.from_nx(self.G)
        nt.show('nx.html')
        return {
            'nodes': nt.nodes,
            'edges': nt.edges
        }