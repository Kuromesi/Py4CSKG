import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

import networkx as nx
import matplotlib.pyplot as plt
from analyzer import new_flan_analyzer

def test_flan_analyzer():
    ma = new_flan_analyzer("src/analyzer/rules/experiment/rule.yaml")
    model = ma.load_model(model_path='data/reports/vul_env/report_2024.02.07-12.32.json', data_path='data/reports/vul_env/graph.yaml')

    attack_graph = ma.generate_attack_graph(model)
    paths = ma.generate_attack_path(attack_graph, "172.29.0.5:root", "172.30.0.3:access", kind="impact")
    ma.print_path(attack_graph, paths)
    ma.plot_attack_graph(model, attack_graph)
    ma.plot_attack_path(model, attack_graph, paths[0])

if __name__ == '__main__':
    test_flan_analyzer()