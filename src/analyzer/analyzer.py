import networkx as nx
import matplotlib.pyplot as plt

from utils.Logger import logger
from analyzer.utils.load_rule import load_rule
from analyzer.utils.knowledge_query import KGQuery
from knowledge_graph.Ontology.CVE import *
from analyzer.ontologies.ontology import AtomicAttack
from service.GDBSaver import GDBSaver

def cmp_atomic_attack(a: AtomicAttack, b: AtomicAttack):
    impact = cmp_impact(a.gain, b.gain)
    if impact == 0:
        if a.score > b.score:
            return 1
        elif a.score == b.score:
            return 0
        else:
            return -1
    return impact

def get_weight(model: nx.DiGraph, path: list, weight: str) -> float:
    return nx.path_weight(model, path, weight=weight)

class ModelAnalyzer:
    def __init__(self, rule_path) -> None:
        self.rules = load_rule(rule_path)
        self.kg = KGQuery(GDBSaver())
    
    def analyze(self, model: nx.DiGraph):
        self.analyze_vul(model)
        vul_graph = self.analyze_status(model)
        return vul_graph

    def analyze_attack_path(self, model: nx.DiGraph, src: str, dst: str, weight="weight"):
        try:
            if weight == "score":
                heaviest_path = max((path for path in nx.all_simple_paths(model, src, dst)),
                        key=lambda path: get_weight(model, path, "score"))
                self.print_path([heaviest_path])
                length_total = nx.path_weight(model, heaviest_path, weight="weight")
                score_total = nx.path_weight(model, heaviest_path, weight="score")
                print(f"length of path is: {length_total}")
                print(f"score of path is: {score_total}")
            else:
                shortest_path = nx.shortest_path(model, src, dst, weight=weight)
                self.print_path([shortest_path])
                length_total = nx.path_weight(model, shortest_path, weight="weight")
                score_total = nx.path_weight(model, shortest_path, weight="score")
                print(f"length of path is: {length_total}")
                print(f"score of path is: {score_total}")
        except Exception as e:
            print(e)

    def analyze_status(self, model: nx.DiGraph) -> nx.DiGraph:
        self.analyze_vul(model)
        new_model = nx.DiGraph()
        nodes, edges = [], []
        internal_transitions = self.rules.transitions
        for node_name, node_prop in model.nodes(data=True):
            for trans in internal_transitions:
                edges.append((f"{node_name}:{trans[0]}", f"{node_name}:{trans[1]}", {'weight': 0, 'score': 0}))
            atomic_attacks: dict[str, AtomicAttack] = node_prop['classified_atomic_attacks']
            for src_name, _, edge_prop in model.in_edges(node_name, data=True):
                transitions = edge_prop['transitions']
                for trans in transitions:
                    trans_src, trans_dst = trans.split(":")
                    edges.append((f"{src_name}:{trans_src}", f"{node_name}:{trans_dst}", {'weight': 0, 'score': 0}))
                access = edge_prop['access']
                if atomic_attacks[access] is None:
                    continue
                src_status = f"{src_name}:{self.rules.prerequisites[atomic_attacks[access].require]}"
                dst_status = f"{node_name}:{self.rules.exploit_transitions[atomic_attacks[access].gain]}"
                edges.append((src_status, dst_status, {'weight': 1, 'score': atomic_attacks[access].score, 'exploit_name': atomic_attacks[access].name}))
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
    
    def print_path(self, paths):
        idx = 1
        print("Attack path: ")
        for path in paths:
            print(f"\t[{idx}] " + " --> ".join(path))
            idx += 1