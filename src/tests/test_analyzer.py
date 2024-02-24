import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

import networkx as nx
import matplotlib.pyplot as plt
from analyzer import new_flan_analyzer

def test_flan_analyzer():
    ma = new_flan_analyzer("src/analyzer/rules/experiment/rule.yaml")
    # model = ma.load_model(model_path=['data/reports/vul_env/report_2024.02.07-12.32.json'], data_path='data/reports/vul_env/graph.yaml')
    model = ma.load_model(model_path=['shared/analyzer/lab/report.json'])

    attack_graph = ma.generate_attack_graph(model)
    paths = ma.generate_attack_path(attack_graph, "scan-node:root", "192.168.9.18:access", kind="shortest")
    ma.print_path(attack_graph, paths)
    ma.plot_vis_graph(attack_graph, graph_type="attack")
    ma.plot_vis_graph(model, graph_type="model")
    ma.plot_vis_attack_path(attack_graph, paths)

if __name__ == '__main__':
    test_flan_analyzer()