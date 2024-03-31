import networkx as nx
import json, re, uuid
import matplotlib.pyplot as plt
from ipaddress import ip_network, ip_address
from ontologies.modeling import *
from ontologies.constants import *
from analyzer.utils.generate_atomic_attack import convert_cve_to_atomic_attack
from utils import CVE_PATTERN
from analyzer.atomic_convert.neo4j_converter import Neo4jAtomicConverter
import abc

class GraphAdapter:
    """convert different source of graphs into networkx graph for analyzing
    """    
    @abc.abstractmethod
    def convert(self, graph_file) -> nx.DiGraph:
        pass