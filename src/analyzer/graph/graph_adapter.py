import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

import networkx as nx
import json, re, uuid
import matplotlib.pyplot as plt
from ipaddress import ip_network, ip_address
from ontologies.modeling import *
from ontologies.constants import *
from analyzer.utils.generate_atomic_attack import convert_cve_to_atomic_attack

class GraphAdapter:
    """convert different source of graphs into networkx graph for analyzing
    """    
    def __init__(self, source):
        """_summary_

        Args:
            source (_type_): available options: pyvis
        """        
        if source == "pyvis":
            self.adpater = PyvisAdapter()
        elif source == "flan":
            self.adpater = FlanAdapter()

    def convert(self, graph_file) -> nx.DiGraph:
        return self.adpater.convert(graph_file)

class PyvisAdapter:
    """convert pyvis graph
    """    
    def convert(self, pyvis_graph: dict):
        nodes = []
        for node in pyvis_graph['nodes']:
            id = node['id']
            tmp = {"os": [], "software": [], "hardware": [], "firmware": [], "cve": []}
            for component, products in node['component'].items():
                if component == "cve":
                    for cve in products:
                        tmp[component].append(cve)
                else:
                    for _, product in products.items():
                        tmp[component].append(self.gen_tuple(product))
                        
            node.update(tmp)
            del(node['component'])
            del(node['id'])
            nodes.append((node['name'], node))
        # Edges
        edges = []
        for edge in pyvis_graph['edges']:
            if 'from' in edge and 'to' in edge:
                src = edge.pop('src')
                dest = edge.pop('dst')
                edges.append((src, dest, edge))
                if edge['edge_type'] == "undirected":
                    edges.append((src, dest, edge))
        
        converted_graph = nx.DiGraph()
        converted_graph.add_nodes_from(nodes)
        converted_graph.add_edges_from(edges)
        return converted_graph

    def gen_tuple(product):
        name = product['product']
        name = name.replace(" ", "_")
        return (name, product['version'], product['access'], product['privilege'])
    
class FlanAdapter:
    """convert flan scan results in json format to networkx graph
    """    
    cidr_pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$')
    cpe_pattern = re.compile(r'cpe:[^)]+')
    product_pattern = re.compile(r'^[^(]*')
    cve_pattern = re.compile(r'CVE-[0-9]+-[0-9]+')

    def convert(self, json_report: dict):
        converted_graph = nx.DiGraph()
        nodes: list[PhysicalNode|LogicalNode] = []
        edges: list[Relation] = []
        target_ips: list = json_report['ips']
        cidrs = []
        hosts: dict[str, LogicalNode] = {}

        scan_node = LogicalNode("scan-node")
        nodes.append(scan_node)

        for ip in target_ips:
            if self.is_valid_cidr(ip):
                nodes.append(LogicalNode(ip))
                cidrs.append(ip)
                edges.append(Relation("network", scan_node.name, ip, ACCESS_ADJACENT, ["access:access"]))

        vulnerable_services: dict = json_report['vulnerable']
        self.process_services(vulnerable_services, hosts, nodes, edges, scan_node, cidrs)

        not_vulnerable_services: dict = json_report['not_vulnerable']
        self.process_services(not_vulnerable_services, hosts, nodes, edges, scan_node, cidrs)
        
        networkx_nodes, networkx_edges = [], []
        for node in nodes:
            networkx_nodes.append((node.name, node.__dict__))
        for edge in edges:
            if edge.bidirectional:
                networkx_edges.append((edge.dst, edge.src, edge.__dict__))   
            networkx_edges.append((edge.src, edge.dst, edge.__dict__))
        converted_graph.add_nodes_from(networkx_nodes)
        converted_graph.add_edges_from(networkx_edges)
        return converted_graph

    def process_services(self, services: dict, 
                         hosts: list[LogicalNode], nodes: list[PhysicalNode|LogicalNode], edges: list[Relation],
                         scan_node: PhysicalNode, cidrs: list):
        for product, product_info in services.items():
            product_name = self.product_pattern.findall(product)[0]
            vulnerabilities = []
            if 'vulnerabilities' in product_info:
                vulnerabilities = product_info['vulnerabilities']
            locations = product_info['locations']
            for host_ip, host_ports in locations.items():
                host_cidr = self.in_cidr(host_ip, cidrs)
                if host_ip not in hosts:
                    hosts[host_ip] = LogicalNode(host_ip)
                    expose_node = LogicalNode(f"{host_ip}:expose")
                    nodes.append(expose_node)
                    nodes.append(hosts[host_ip])
                    # if host_ip in cidr network, connect expose and host with cidr node
                    # else, connect with scan node
                    if host_cidr:
                        edges.append(Relation("network", host_cidr, f"{host_ip}:expose", ACCESS_ADJACENT, ["access:access"]))
                        edges.append(Relation("network", host_ip, host_cidr, ACCESS_ADJACENT, ["access:access"]))
                    else:
                        edges.append(Relation("network", scan_node.name, f"{host_ip}:expose", ACCESS_ADJACENT, ["access:access"]))
                        edges.append(Relation("network", host_ip, scan_node.name, ACCESS_ADJACENT, ["access:access"]))
                        
                service_name = f"{host_ip}:{product_name}"
                service_node = PhysicalNode(service_name, atomic_attacks=[])
                # convert vulnerabilities to atomic attacks
                for vulnerability in vulnerabilities:
                    cve_id = self.cve_pattern.findall(vulnerability['name'])
                    if cve_id:
                        cve_id = cve_id[0]
                        service_node.atomic_attacks.append(convert_cve_to_atomic_attack(cve_id).__dict__)
                
                edges.append(Relation("network", host_ip, service_node.name, ACCESS_ADJACENT, ["user:access", "root:root"]))
                edges.append(Relation("network", service_node.name, host_ip, ACCESS_ADJACENT, ["user:access", "root:root", "none:none"]))
                edges.append(Relation("network", f"{host_ip}:expose", service_node.name, ACCESS_ADJACENT))
                nodes.append(service_node)

    def in_cidr(self, ip: str, cidrs: []) -> str:
        for cidr in cidrs:
            if ip_address(ip) in ip_network(cidr):
                return cidr
        return ""
    
    def is_valid_cidr(self, cidr):
        return bool(self.cidr_pattern.match(cidr))

if __name__ == "__main__":
    fa = FlanAdapter()
    with open('data/report_2024.02.05-08.31.json', 'r') as f:
        report = json.load(f)
    converted_graph = fa.convert(report)
    pos = nx.spring_layout(converted_graph)
    nx.draw(converted_graph, with_labels=True, pos=pos)
    plt.show()