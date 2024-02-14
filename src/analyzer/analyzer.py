import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

from utils.Logger import logger
from analyzer.utils.load_rule import load_rule
from analyzer.utils.knowledge_query import KGQuery
from ontologies.modeling import *
from ontologies.cve import *
from service.GDBSaver import GDBSaver
from analyzer.extension import AnalyzerExtension

SHORTEST_PATH = "shortest"
MAX_IMPACT_PATH = "impact"
ALL_PATH = "all"
class ModelAnalyzer:
    def __init__(self, rule_path, extension: AnalyzerExtension) -> None:
        self.rules = load_rule(rule_path)
        # self.kg = KGQuery(GDBSaver())
        self.extension = extension
    
    def load_model(self, **kwargs):
        return self.extension.load_model(**kwargs)
    
    def analyze(self, model: nx.DiGraph):
        # self.analyze_vul(model)
        vul_graph = self.generate_attack_graph(model)
        return vul_graph

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

    def analyze_vul(self, model: nx.DiGraph):
        for node_name, node_prop in model.nodes(data=True):
            vuls: list[CVEEntry] = []
            atomic_attacks: list[AtomicAttack] = []
            if 'os' in node_prop:
                for product in node_prop['os']:
                    vuls.extend(self.kg.find_vuls(product['name'], product['version']))
                for product in node_prop['software']:
                    vuls.extend(self.kg.find_vuls(product['name'], product['version']))
                for product in node_prop['firmware']:
                    vuls.extend(self.kg.find_vuls(product['name'], product['version']))
                for product in node_prop['hardware']:
                    vuls.extend(self.kg.find_vuls(product['name'], product['version']))
                for vul in vuls:
                    atomic_attacks.append(AtomicAttack(vul.id, vul.access, vul.impact, vul.score, "None"))
            for atomic in node_prop["atomic_attacks"]:
                atomic_attacks.append(AtomicAttack(atomic['name'], atomic['access'], atomic['gain'], atomic['score'], atomic['require']))
            classified_atomic_attacks = self.analyze_atomic_attacks(atomic_attacks)
            node_prop["classified_atomic_attacks"] = classified_atomic_attacks

    def analyze_atomic_attacks(self, atomic_attacks: list[AtomicAttack]) -> dict[str, AtomicAttack]:
        classified_atomic_attacks: dict[str, AtomicAttack] = {
            ACCESS_PHYSICAL: None,
            ACCESS_LOCAL: None,
            ACCESS_ADJACENT: None,
            ACCESS_NETWORK: None,
        }
        for atomic_attack in atomic_attacks:
            access = atomic_attack.access
            if classified_atomic_attacks[access] is None:
                classified_atomic_attacks[access] = atomic_attack
            else:
                if cmp_atomic_attack(atomic_attack, classified_atomic_attacks[access]) > 0:
                    classified_atomic_attacks[access] = atomic_attack
        for access_idx in range(len(ACCESS_ORDER)):
            access = ACCESS_ORDER[access_idx]
            for lower_access in ACCESS_ORDER[access_idx + 1: ]:
                if classified_atomic_attacks[lower_access] is None:
                    continue
                if classified_atomic_attacks[access] is None \
                    or cmp_atomic_attack(classified_atomic_attacks[lower_access], classified_atomic_attacks[access]) > 0:
                    classified_atomic_attacks[access] = classified_atomic_attacks[lower_access]
        for access in [ACCESS_NETWORK, ACCESS_ADJACENT]:
            if classified_atomic_attacks[access] is None:
                continue
            if classified_atomic_attacks[access].gain in [PRIV_ROOT, PRIV_USER]:
                if classified_atomic_attacks[ACCESS_LOCAL] != classified_atomic_attacks[access]:
                    classified_atomic_attacks[access] = AtomicAttack(
                        f"{classified_atomic_attacks[access]}->{classified_atomic_attacks[ACCESS_LOCAL]}",
                        access, classified_atomic_attacks[access].gain,
                        classified_atomic_attacks[access].score + classified_atomic_attacks[ACCESS_LOCAL].score,
                        "None"
                    )
        return classified_atomic_attacks
    
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