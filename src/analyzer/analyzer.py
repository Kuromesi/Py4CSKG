import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import os

from pyvis.network import Network
from utils.Logger import logger
from analyzer.utils.load_rule import load_rule
from ontologies.modeling import *
from ontologies.cve import *
from analyzer.extensions.extension import AnalyzerExtension
from analyzer.graph.graph_editor import GraphEditor

SHORTEST_PATH = "shortest"
MAX_IMPACT_PATH = "impact"
ALL_PATH = "all"
class ModelAnalyzer:
    def __init__(self, rule_path: str, extension: AnalyzerExtension, graph_editor: GraphEditor, **kwargs) -> None:
        self.rules = load_rule(rule_path)
        self.extension = extension
        self.graph_editor = graph_editor
    
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
                return list(nx.all_simple_paths(model, src, dst))
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
                # edges.append((src_status, dst_status, {'weight': 1, 'score': atomic_attack.score, 'exploit': atomic_attack}))
                edges.append((src_status, dst_status, {'weight': 1, 'score': atomic_attack.score, 'exploit': atomic_attack.name}))
        new_model.add_edges_from(edges)
        
        return new_model
    
    def plot_matplotlib_attack_graph(self, model: nx.DiGraph, attack_graph: nx.DiGraph):
        pos = self.generate_layout(model)
        nx.draw(attack_graph, pos, with_labels=True, node_color="#8adacf", font_size=15, font_family="Times New Roman", font_weight="bold")
        plt.show()
    
    def plot_matplotlib_attack_path(self, model: nx.DiGraph, attack_graph, attack_path: list[str]):
        pos = self.generate_layout(model)
        nx.draw(attack_graph, pos, with_labels=True, node_color="#8adacf", font_size=15, font_family="Times New Roman", font_weight="bold")
        nx.draw_networkx_nodes(attack_graph, pos, nodelist=attack_path, node_color="#ff0000")
        plt.show()

    def plot_vis_graph(self, graph: nx.DiGraph, graph_type="model", out_dir="."):
        graph = graph.copy()
        for node, attrib in graph.nodes(data=True):
            attrib['color'] = "#8adacf"
        for edge in graph.edges(data=True):
            edge[2]['smooth'] = False
            edge[2]['color'] = "#8adacf"
        network = Network(cdn_resources="in_line", directed=True)
        if graph_type == "model":
            attrib = graph.nodes["scan-node"]
            attrib['color'] = "#ff0000"
            graph_name = "model_graph.html"
        elif graph_type == "attack":
            graph_name = "attack_graph.html"
        network.from_nx(graph)
        graph_html = network.generate_html(graph_name)
        with open(os.path.join(out_dir, graph_name), "w") as f:
            f.write(graph_html)

    def plot_vis_attack_path(self, attack_graph: nx.DiGraph, attack_paths: list[list[str]], out_dir=".", plot_all=False):
        if not attack_paths:
            logger.error("no attack path found")
        if plot_all:
            attack_graph = attack_graph.copy()
            for node, attrib in attack_graph.nodes(data=True):
                attrib['color'] = "#8adacf"
            for edge in attack_graph.edges(data=True):
                edge[2]['smooth'] = False
                edge[2]['color'] = "#8adacf"
                edge[2]['arrows'] = ""
            for attack_path in attack_paths:
                for node, attrib in attack_graph.nodes(data=True):
                    if node in attack_path:
                        attrib['color'] = "#ff0000"
                for i in range(len(attack_path) - 1):
                    edge_attrib = attack_graph.edges[attack_path[i], attack_path[i + 1]]
                    edge_attrib['arrows'] = "to"
                    edge_attrib['color'] = "#ff0000"
        else:
            attack_graph = nx.DiGraph()
            edges = []
            for attack_path in attack_paths:
                for i in range(len(attack_path) - 1):
                    edges.append((attack_path[i], attack_path[i + 1], {'arrows': 'to', 'color': '#ff0000', 'smooth': False}))
            attack_graph.add_edges_from(edges)
            for node, attrib in attack_graph.nodes(data=True):
                attrib['color'] = "#ff0000" 
        
        start = attack_graph.nodes[attack_paths[0][0]]
        start['shape'] = "diamond"
        start['color'] = "#ffff00"
        end = attack_graph.nodes[attack_paths[0][-1]]
        end['shape'] = "star"
        end['color'] = "#ffff00"
        network = Network(cdn_resources="in_line", directed=True)
            
        # turn buttons on
        # network.show_buttons()
        network.from_nx(attack_graph)
        graph_name = f"attack_path_{attack_paths[0][0]}-{attack_paths[0][-1]}.html"
        graph_html = network.generate_html(graph_name)
        with open(os.path.join(out_dir, graph_name), "w") as f:
            f.write(graph_html)
    
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
        print(f"SOURCE: {path[0][0]} DESTINATION: {paths[0][-1]}")
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
                    print(f"\t{path[i]} --> {path[i + 1]} # {edge_attrib['exploit']}")

            print("Summary")
            print(f"\tlength: {length_total}, score of path is: {score_total}")