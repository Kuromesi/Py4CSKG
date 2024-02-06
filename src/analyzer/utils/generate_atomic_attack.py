from knowledge_graph.Ontology.CVE import *
from analyzer.ontologies.ontology import AtomicAttack

def convert_cve_to_atomic_attack(cve_id: str) -> AtomicAttack:
    atomic_attack = AtomicAttack("1", ACCESS_ADJACENT, "system cia loss", 1.0, "None")
    return atomic_attack
