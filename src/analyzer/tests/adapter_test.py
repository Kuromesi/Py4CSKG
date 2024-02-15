import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from analyzer.graph.graph_adapter import FlanAdapter
from analyzer.analyzer import ModelAnalyzer
from analyzer.extensions.extension import FlanAnalyzerExtension
import networkx as nx
import matplotlib.pyplot as plt
from analyzer.graph_editor import GraphEditor

def test_flan_adapter():
    # fa = FlanAdapter()
    # with open('data/reports/report_2024.02.07-12.32.json', 'r') as f:
    #     report = json.load(f)
    # converted_graph = fa.convert(report)
    gd = GraphEditor()
    extension = FlanAnalyzerExtension(gd)
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml", extension)
    model = ma.load_model(model_path='data/reports/vul_env/report_2024.02.07-12.32.json', data_path='data/reports/vul_env/graph.yaml')
    # nx.draw(model, with_labels=True)
    # plt.show()
    attack_graph = ma.generate_attack_graph(model)
    # pos = ma.generate_layout(converted_graph)

    paths = ma.generate_attack_path(attack_graph, "172.29.0.5:root", "172.30.0.3:access", kind="impact")
    ma.print_path(attack_graph, paths)

if __name__ == '__main__':
    test_flan_adapter()