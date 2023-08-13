import json
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt
from service.GDBSaver import GDBSaver
# from service.RDBSaver import RDBSaver
from webapp.utils.version_compare import *
import pandas as pd
from text_similarity.TextSimilarity import *
from text_classification.TextClassification import *
from graph.GraphProcessor import GraphProcessor

PRIVS = ['None', 'Low', 'High']
CONS = {
    'root': [""]
}

class ModelAnalyzer():
    def __init__(self, cev2capec, cve2cwe, graph) -> None:
        self.gs = GDBSaver()
        self.cve2capec = cev2capec
        self.cve2cwe = cve2cwe
        self.gp = GraphProcessor()
        res = self.gp.convert_pyvis(graph)
        self.graph = res
        self.G = res["graph"]

    def find_attack_path(self, src, dst):
        visited = set()
        self.__dfs_path(src, dst, visited)
        # privilege state transition, None, application, user, root, escalating
        pass

    def __dfs_path(self, node, dst, visited):
        if node in visited:
            return
        neighbors = self.gp.get_neighbors(neighbors, {"type": "Node"}) # And example

    def get_graph_impact(self):
        """Get impact for nodes in graph
        """
        impact_map = {}
        for node in self.G.nodes:
            attrs = self.G.nodes[node]
            report = self.vul_find(attrs['product'], attrs['version'])
            tmp_map = {
                'root': {},
                'escalating': {},
                'user': {},
                'app': {},
                'cia': {}
            }

            impact_map.update({node: tmp_map})


    def __get_max_possibility_vul(self, report:pd.DataFrame, cond:list):
        rows = report[report['CVE-Impact'].isin(cond)]
        for priv in PRIVS:
            if rows[rows['PrivilegesRequired'] == priv]:
                rows = rows.loc[rows['ImpactScore'].idxmax()]
                break
        return rows

    def vul_find(self, product:str, version:str) -> pd.DataFrame:
        """Find related vulnerabilities of a specific product and return vul_report like below:
        Product, CVE-ID, CVE-Description, CVE-Impact, Access

        Args:
            product (str): product, exactly the same // n.product='product'
            version (str): version of the product

        Returns:
            pd.DataFrame: vul_report
        """        
        query = "MATCH (n:Platform) WHERE n.product='%s' AND n.vulnerable='True' RETURN n"%product
        nodes = self.gs.sendQuery(query)
        vul_products = []
        # vuls = {}
        vul_report = pd.DataFrame(columns=['Product', 'CVE-ID', 'CVE-Description', 'CVE-Impact', 
                                           'Access', 'PrivilegesRequired', 'ImpactScore', 'ExploitabilityScore'])
        for node in nodes:
            node = node[0]
            version_start = node['versionStart']
            version_end = node['versionEnd']
            if cmp_version(version, version_start) != -1 and cmp_version(version, version_end) != 1:
                vul_products.append(node['id'])
        if vul_products:
            query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE"
            for vul_product in vul_products:
                query += " a.id='%s' OR"%vul_product
            query = query.strip("OR") + "RETURN n"
            nodes = self.gs.sendQuery(query)
            for node in nodes:
                node = node[0]
                # if node['id'] not in vuls:
                #     vuls[node['id']] = node
                cvss2 = json.loads(node['baseMetricV2'])
                if 'baseMetricV3' in node:
                    privilegesRequired = json.loads(node['baseMetricV3'])['cvssV3']['privilegesRequired']
                else:
                    privilegesRequired = "None"
                vul_report.loc[len(vul_report.index)] = [product, node['id'], node['description'], 
                                                    node['impact'], cvss2['cvssV2']['accessVector'], 
                                                    privilegesRequired, cvss2['impactScore'], cvss2['exploitabilityScore']]
        # self.vul_analyze(vul_report)
        # for product in vul_product:
        #     query = "MATCH (n:Vulnerability)-[]-(a:Platform) WHERE a.uri='%s' RETURN n"%product
        #     nodes = self.gs.sendQuery(query)
        #     for node in nodes:
        #         node = node[0]
        #         if node['id'] not in vuls:
        #             vuls[node['id']] = node
        return vul_report
    
    def vul_analyze(self, vul_report:pd.DataFrame):
        """Find related CAPEC, CWE, ATT&CK, CVSS and make a summary.

        Args:
            vul_report (pd.DataFrame): vul_report
        """        
        
        cwe_df = pd.DataFrame(columns=['CWE-ID', 'Name', 'Description', 'CVE', 'Count'])
        capec_df = pd.DataFrame(columns=['CAPEC-ID', 'Name', 'Description', 'CVE', 'Count'])
        
        for index, row in vul_report.iterrows():
            cve = row['CVE-ID']
            
            # Related CWE analysis
            query = "MATCH (n:Vulnerability)<-[:observed_example]-(m:Weakness) WHERE n.id='%s' RETURN m"%cve
            cwes = self.gs.sendQuery(query)
            if not cwes:
                cwe = self.cve2cwe.bert_predict(row['CVE-Description'])
                query = "MATCH (n:Weakness) WHERE n.id='%s' RETURN n"%cwe
                cwes = self.gs.sendQuery(query)
            for cwe in cwes:
                cwe = cwe[0]
                if cwe['id'] in cwe_df['CWE-ID'].values:
                    cwe_df.loc[cwe_df['CWE-ID'] == cwe['id'], 'Count'] += 1
                    cwe_df.loc[cwe_df['CWE-ID'] == cwe['id'], 'CVE'].values[0].append(cve)
                else:
                    cwe_df.loc[len(cwe_df.index)] = [cwe['id'], cwe['name'], cwe['description'], [cve], 1] 
            # Related CAPEC analysis
            capecs = self.cve2capec.calculate_similarity(row['CVE-Description'])
            for _, capec in capecs[0: 5].iterrows():
                if capec['id'] in capec_df['CAPEC-ID'].values:
                    capec_df.loc[capec_df['CAPEC-ID'] == capec['id'], 'Count'] += 1
                    capec_df.loc[capec_df['CAPEC-ID'] == capec['id'], 'CVE'].values[0].append(cve)
                else:
                    capec_df.loc[len(capec_df.index)] = [capec['id'], capec['name'], capec['description'], [cve], 1]
            # CVSS analysis
        print(1)
            
    def __find_vul_nodes(self, nodes):
        l1 = set() # level1, system root
        l2 = set() # level2, system user
        l3 = set() # level3, application, system CIA
        l4 = set() # not vulnerable nodes
        _nodes = tqdm(nodes)
        _nodes.set_description("FINDING VULNERABILITIES")
        for key in nodes:
            product = nodes[key]['product']
            version = nodes[key]['version']
            _nodes.set_postfix(product=product)
            vul_report = self.vul_find(product, version)
            
            if vul_report.empty:
                l4.add(key)
                neighbors = [n for n in self.G.neighbors(key)]
                l4.update(neighbors)
                continue
            
            app_code_exec = vul_report.loc[vul_report['CVE-Impact'] == "Application arbitrary code execution"]
            app_privilege = vul_report.loc[vul_report['CVE-Impact'] == "Gain application privilege"]
            system_code_exec = vul_report.loc[vul_report['CVE-Impact'] == "System arbitrary code execution"]
            cia_impact = vul_report.loc[vul_report['CVE-Impact'] == "System CIA loss"]
            user_privilege = vul_report.loc[vul_report['CVE-Impact'] == "Gain user privilege"]
            root_privilege = vul_report.loc[vul_report['CVE-Impact'] == "Gain root privilege"]
            privilege_escalation = vul_report.loc[vul_report['CVE-Impact'] == "Privilege escalation"]
            
            # System root
            if  not user_privilege.empty and not privilege_escalation.empty or not root_privilege.empty:
                l1.add(key)
                neighbors = [n for n in self.G.neighbors(key)]
                l1.update(neighbors)
            
            # System user
            elif not user_privilege.empty:
                l2.add(key)
                neighbors = [n for n in self.G.neighbors(key)]
                l2.update(neighbors)
            
            else:
                if not system_code_exec.empty:
                    l3.add(key)
                    neighbors = [n for n in self.G.neighbors(key)]
                    l3.update(neighbors)
                else:
                    l3.add(key)
                    neighbors = [n for n in self.G.neighbors(key) if n in self.graph['node_type']["entry"]]
                    l3.update(neighbors)
                    
        l4 = l4 - l3 - l2 - l1
        l3 = l3 - l2 - l1
        l2 = l2 - l1
        return {'root': list(l1), 'user': list(l2), 'other': list(l3), 'no': list(l4)}
                    
                
                
                # if vuls:
                #     vul_nodes.append(key)
                #     neighbors = [n for n in self.G.neighbors(key)]
                #     vul_nodes.extend(neighbors)    
    
    def analyze(self):
        node_type = self.graph['node_type']
        
        # Find vulnerabilities
        nodes = {}
        nodes.update(node_type['software'])
        nodes.update(node_type['hardware'])
        nodes.update(node_type['os'])
        result = self.__find_vul_nodes(nodes)
        # self.__find_vul_nodes(node_type['hardware'], vul_nodes)
        # self.__find_vul_nodes(node_type['os'], vul_nodes)
        
        DG = self.new_graph(result)
        nt = Network()
        nt.from_nx(DG)
        nt.show('tmp/dg.html')
        # redraw the original graph
        self.redraw(result)
        
        
                    
        
        nt = Network()
        nt.from_nx(self.G)
        nt.show('nx.html')
        return {
            'nodes': nt.nodes,
            'edges': nt.edges
        }