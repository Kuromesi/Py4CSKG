import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

from utils.Logger import logger
from analyzer.utils.load_rule import load_rule
from analyzer.utils.knowledge_query import KGQuery
from ontologies.modeling import *
from ontologies.cve import *
from analyzer.extensions.extension import AnalyzerExtension
from analyzer.graph.graph_editor import GraphEditor

SHORTEST_PATH = "shortest"
MAX_IMPACT_PATH = "impact"
ALL_PATH = "all"
class ModelAnalyzer:
    def __init__(self, rule_path, extension: AnalyzerExtension, graph_editor: GraphEditor, **kwargs) -> None:
        self.rules = load_rule(rule_path)
        self.extension = extension
        self. graph_editor = graph_editor
    
    def load_model(self, data_path="", **kwargs):
        model = self.extension.load_model(**kwargs)
        if data_path:
            self.graph_editor.edit_graph(model, data_path)
        self.extension.analyze_model(model)
        return model

    def generate_attack_path(self, model: nx.DiGraph, src: str, dst: str, kind="shortest"):
        try:
            if kind == MAX_IMPACT_PATH:
                heaviest_path = max((path for path in nx.all_simple_paths(model, src, dst)),
                        key=lambda path: nx.path_weight(model, path, weight="score"))
                return [heaviest_path]
            elif kind == SHORTEST_PATH:
                shortest_path = nx.shortest_path(model, src, dst, weight="weight")
                return [shortest_path]
            elif kind == ALL_PATH:
                return nx.all_simple_paths(model, src, dst)
        except Exception as e:
            print(e)

    def generate_attack_graph(self, model: nx.DiGraph) -> nx.DiGraph:
        new_model = nx.DiGraph()
        nodes, edges = [], []
        internal_transitions = self.rules.transitions
        for node_name, node_prop in model.nodes(data=True):
            for trans in internal_transitions:
                edges.append((f"{node_name}:{trans[0]}", f"{node_name}:{trans[1]}", {'weight': 0, 'score': 0}))
            # atomic_attacks: dict[str, AtomicAttack] = node_prop['classified_atomic_attacks']
            for src_name, _, edge_prop in model.in_edges(node_name, data=True):
                transitions = edge_prop['transitions']
                for trans in transitions:
                    trans_src, trans_dst = trans.split(":")
                    edges.append((f"{src_name}:{trans_src}", f"{node_name}:{trans_dst}", {'weight': 0, 'score': 0}))
                access = edge_prop['access']
                atomic_attack = self.extension.get_max_pos_atomic_attack(node_name, access, "none")
                if atomic_attack is None:
                    continue
                src_status = f"{src_name}:{self.rules.prerequisites[atomic_attack.require]}"
                dst_status = f"{node_name}:{self.rules.exploit_transitions[atomic_attack.gain]}"
                edges.append((src_status, dst_status, {'weight': 1, 'score': atomic_attack.score, 'exploit': atomic_attack}))
        new_model.add_edges_from(edges)
        
        return new_model
    
    def plot_attack_graph(self, model: nx.DiGraph, attack_graph: nx.DiGraph):
        pos = self.generate_layout(model)
        nx.draw(attack_graph, pos, with_labels=True, node_color="#8adacf", font_size=15, font_family="Times New Roman", font_weight="bold")
        plt.show()
    
    def plot_attack_path(self, model: nx.DiGraph, attack_graph, attack_path: list[str]):
        pos = self.generate_layout(model)
        nx.draw(attack_graph, pos, with_labels=True, node_color="#8adacf", font_size=15, font_family="Times New Roman", font_weight="bold")
        nx.draw_networkx_nodes(attack_graph, pos, nodelist=attack_path, node_color="#ff0000")
        plt.show()
    
    def generate_layout(self, model: nx.DiGraph, seed: int=1) -> dict[str, np.ndarray]:
        pos = nx.spring_layout(model, seed=seed)
        distance = 0.035
        status_pos = {}
        properties = self.rules.properties
        for node, node_pos in pos.items():
            node_root = f"{node}:root"
            node_user = f"{node}:user"
            node_access = f"{node}:access"
            node_none = f"{node}:none"

            root_pos = np.array([node_pos[0], node_pos[1] + distance / 2])
            user_pos = np.array([node_pos[0] - distance, node_pos[1]])
            access_pos = np.array([node_pos[0] - 2 * distance, node_pos[1] - distance])
            none_pos = np.array([node_pos[0] - 2 * distance, node_pos[1] + distance])

            status_pos[node_root] = root_pos
            status_pos[node_user] = user_pos
            status_pos[node_access] = access_pos
            status_pos[node_none] = none_pos

        return status_pos

    def print_path(self, model, paths):
        idx = 1
        if not paths:
            print("No attack path found.")
            return
        for path in paths:
            print(f"Attack path[{idx}]")
            print("\t" + " --> ".join(path))
            idx += 1
            length_total = nx.path_weight(model, path, weight="weight")
            score_total = nx.path_weight(model, path, weight="score")
            
            print("Exploits")
            for i in range(len(path) - 1):
                edge_attrib = model.edges[path[i], path[i + 1]]
                if 'exploit' in edge_attrib:    
                    print(f"\t{path[i]} --> {path[i + 1]} # {edge_attrib['exploit'].name}")

            print("Summary")
            print(f"\tlength: {length_total}, score of path is: {score_total}")