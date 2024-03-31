import networkx as nx
import re
from ipaddress import ip_network, ip_address
from ontologies.modeling import *
from ontologies.constants import *
from utils import CVE_PATTERN

class FlanAdapter:
    """convert flan scan results in json format to networkx graph
    """    
    cidr_pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$')
    cpe_pattern = re.compile(r'cpe:[^)]+')
    product_pattern = re.compile(r'^[^(]*')

    def __init__(self, atomic_converter) -> None:
        self.atomic_converter = atomic_converter

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
                    cve_id = CVE_PATTERN.findall(vulnerability['name'])
                    if cve_id:
                        cve_id = cve_id[0]
                        atomic = self.atomic_converter.find_by_id(cve_id)
                        if atomic:
                            service_node.atomic_attacks.append(atomic.__dict__)
                
                edges.append(Relation("network", host_ip, service_node.name, ACCESS_ADJACENT, ["user:access", "root:root"]))
                edges.append(Relation("network", service_node.name, host_ip, ACCESS_ADJACENT, ["user:access", "root:root", "none:none"]))
                edges.append(Relation("network", f"{host_ip}:expose", service_node.name, ACCESS_ADJACENT))
                nodes.append(service_node)

    def in_cidr(self, ip: str, cidrs: list) -> str:
        for cidr in cidrs:
            if ip_address(ip) in ip_network(cidr):
                return cidr
        return ""
    
    def is_valid_cidr(self, cidr):
        return bool(self.cidr_pattern.match(cidr))