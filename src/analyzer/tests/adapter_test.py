import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from analyzer.graph.GraphAdapter import FlanAdapter
from analyzer.analyzer import ModelAnalyzer
import networkx as nx
import matplotlib.pyplot as plt

def test_flan_adapter():
    fa = FlanAdapter()
    with open('data/report_2023.12.14-06.08.json', 'r') as f:
        report = json.load(f)
    converted_graph = fa.convert(report)
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml")
    
    model = ma.analyze(converted_graph)
    ma.analyze_attack_path(model, "scan-node:access", "172.22.164.35:none")

if __name__ == '__main__':
    test_flan_adapter()