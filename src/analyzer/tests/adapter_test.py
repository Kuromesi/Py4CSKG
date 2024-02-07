import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from analyzer.graph.graph_adapter import FlanAdapter
from analyzer.analyzer import ModelAnalyzer
import networkx as nx
import matplotlib.pyplot as plt

def test_flan_adapter():
    fa = FlanAdapter()
    with open('data/reports/report_2024.02.07-12.32.json', 'r') as f:
        report = json.load(f)
    converted_graph = fa.convert(report)
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml")
    
    attack_graph = ma.analyze(converted_graph)
    pos = ma.generate_layout(converted_graph)

    paths = ma.generate_attack_path(attack_graph, "scan-node:access", "172.30.0.4:none", kind="all")
    ma.print_path(attack_graph, paths)

if __name__ == '__main__':
    test_flan_adapter()