import json, abc
import networkx as nx
from networkx import DiGraph

from analyzer.utils.knowledge_query import KGQuery
from analyzer.graph_adapters.flan_adpter import FlanAdapter
from ontologies.modeling import *
from ontologies.cve import *
from ontologies.modeling import AtomicAttack

class AnalyzerExtension:
    @abc.abstractmethod
    def load_model(self, **kwargs) -> nx.DiGraph:
        """Return processed system model

        Returns:
            nx.DiGraph: system model
        """        
        pass

    @abc.abstractmethod
    def analyze_model(self, model: nx.DiGraph):
        """Convert products info to atomic attacks
        """        
        pass
    
    @abc.abstractmethod
    def get_max_pos_atomic_attack(self, node_name: str, access: str, require: str) -> AtomicAttack:
        """Return the most likely happens AtomicAttack to occur under the current node_name, access, and require conditions.

        Args:
            node_name (str): current node_name
            access (str): access
            require (str): require

        Returns:
            AtomicAttack: most likely happens AtomicAttack
        """        
        pass


class FlanAnalyzerExtension(AnalyzerExtension):
    def __init__(self, atomic_converter):
        self.classified_atomic_attacks: dict[str, dict[str, dict[str, AtomicAttack]]] = {}
        self.flan_adapter = FlanAdapter(atomic_converter)

    def load_model(self, **kwargs) -> nx.DiGraph:
        model_paths = kwargs['model_path']
        model = nx.DiGraph()
        for model_path in model_paths:
            with open(model_path, 'r') as f:
                report = json.load(f)
            model = nx.compose(model, self.flan_adapter.convert(report))
        return model
    
    def analyze_model(self, model: nx.DiGraph):
        for node_name, node_prop in model.nodes(data=True):
            atomic_attacks: list[AtomicAttack] = []
            if 'atomic_attacks' in node_prop:
                for atomic in node_prop["atomic_attacks"]:
                    atomic_attacks.append(AtomicAttack(atomic['name'], atomic['access'], atomic['gain'], atomic['score'], atomic['require']))
            self.classify_atomic_attacks(node_name, atomic_attacks)


    def classify_atomic_attacks(self, node_name, atomic_attacks: list[AtomicAttack]):
        classified_atomic_attacks: dict[str, dict[str, AtomicAttack]] = {
            ACCESS_PHYSICAL: {"none": None},
            ACCESS_LOCAL: {"none": None},
            ACCESS_ADJACENT: {"none": None},
            ACCESS_NETWORK: {"none": None},
        }
        for atomic_attack in atomic_attacks:
            access = atomic_attack.access
            if classified_atomic_attacks[access]['none'] is None:
                classified_atomic_attacks[access]['none'] = atomic_attack
            else:
                if cmp_atomic_attack(atomic_attack, classified_atomic_attacks[access]['none']) > 0:
                    classified_atomic_attacks[access]['none'] = atomic_attack
        for access_idx in range(len(ACCESS_ORDER)):
            access = ACCESS_ORDER[access_idx]
            for lower_access in ACCESS_ORDER[access_idx + 1: ]:
                if classified_atomic_attacks[lower_access]['none'] is None:
                    continue
                if classified_atomic_attacks[access]['none'] is None \
                    or cmp_atomic_attack(classified_atomic_attacks[lower_access]['none'], classified_atomic_attacks[access]['none']) > 0:
                    classified_atomic_attacks[access]['none'] = classified_atomic_attacks[lower_access]['none']
        for access in [ACCESS_NETWORK, ACCESS_ADJACENT]:
            if classified_atomic_attacks[access]['none'] is None:
                continue
            if classified_atomic_attacks[access]['none'].gain in [PRIV_ROOT, PRIV_USER]:
                if classified_atomic_attacks[ACCESS_LOCAL]['none'] != classified_atomic_attacks[access]['none']:
                    classified_atomic_attacks[access]['none'] = AtomicAttack(
                        f"{classified_atomic_attacks[access]['none'].name}->{classified_atomic_attacks[ACCESS_LOCAL]['none'].name}",
                        access, classified_atomic_attacks[access]['none'].gain,
                        classified_atomic_attacks[access]['none'].score + classified_atomic_attacks[ACCESS_LOCAL]['none'].score,
                        "None"
                    )
        self.classified_atomic_attacks[node_name] = classified_atomic_attacks

    def get_max_pos_atomic_attack(self, node_name, access, require) -> AtomicAttack:
        return self.classified_atomic_attacks[node_name][access][require]
    
class OnlyForTestExtension(AnalyzerExtension):
    def __init__(self) -> None:
        self.classified_atomic_attacks: dict[str, dict[str, dict[str, AtomicAttack]]] = {}

    def load_model(self, **kwargs) -> DiGraph:
        model = kwargs['model']
        return model
    
    def analyze_model(self, model: DiGraph):
        for node_name, node_prop in model.nodes(data=True):
            atomic_attacks: list[AtomicAttack] = []
            if 'atomic_attacks' in node_prop:
                for atomic in node_prop["atomic_attacks"]:
                    atomic_attacks.append(AtomicAttack(atomic['name'], atomic['access'], atomic['gain'], atomic['score'], atomic['require']))
            self.classify_atomic_attacks(node_name, atomic_attacks)
    
    def classify_atomic_attacks(self, node_name, atomic_attacks: list[AtomicAttack]):
        classified_atomic_attacks: dict[str, dict[str, AtomicAttack]] = {
            ACCESS_PHYSICAL: {"none": None},
            ACCESS_LOCAL: {"none": None},
            ACCESS_ADJACENT: {"none": None},
            ACCESS_NETWORK: {"none": None},
        }
        for atomic_attack in atomic_attacks:
            access = atomic_attack.access
            if classified_atomic_attacks[access]['none'] is None:
                classified_atomic_attacks[access]['none'] = atomic_attack
            else:
                if cmp_atomic_attack(atomic_attack, classified_atomic_attacks[access]['none']) > 0:
                    classified_atomic_attacks[access]['none'] = atomic_attack
        for access_idx in range(len(ACCESS_ORDER)):
            access = ACCESS_ORDER[access_idx]
            for lower_access in ACCESS_ORDER[access_idx + 1: ]:
                if classified_atomic_attacks[lower_access]['none'] is None:
                    continue
                if classified_atomic_attacks[access]['none'] is None \
                    or cmp_atomic_attack(classified_atomic_attacks[lower_access]['none'], classified_atomic_attacks[access]['none']) > 0:
                    classified_atomic_attacks[access]['none'] = classified_atomic_attacks[lower_access]['none']
        for access in [ACCESS_NETWORK, ACCESS_ADJACENT]:
            if classified_atomic_attacks[access]['none'] is None:
                continue
            if classified_atomic_attacks[access]['none'].gain in [PRIV_ROOT, PRIV_USER]:
                if classified_atomic_attacks[ACCESS_LOCAL]['none'] != classified_atomic_attacks[access]['none']:
                    classified_atomic_attacks[access]['none'] = AtomicAttack(
                        f"{classified_atomic_attacks[access]['none'].name}->{classified_atomic_attacks[ACCESS_LOCAL]['none'].name}",
                        access, classified_atomic_attacks[access]['none'].gain,
                        classified_atomic_attacks[access]['none'].score + classified_atomic_attacks[ACCESS_LOCAL]['none'].score,
                        "None"
                    )
        self.classified_atomic_attacks[node_name] = classified_atomic_attacks

    def get_max_pos_atomic_attack(self, node_name, access, require) -> AtomicAttack:
        return self.classified_atomic_attacks[node_name][access][require]