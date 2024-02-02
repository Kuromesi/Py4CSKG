import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))


import networkx as nx
import matplotlib.pyplot as plt
from knowledge_graph.Ontology.CVE import *
import random

TRANSITION_ENUM = ["user", "root", "access"]
ACCESS_ENUM = [ACCESS_NETWORK, ACCESS_ADJACENT, ACCESS_LOCAL, ACCESS_PHYSICAL]
GAIN_ENUM = [PRIV_USER, PRIV_ROOT, CIA_LOSS]

def gen_random_atomic_attack() -> dict:
    return {
        "name": "vul_test",
        "access": gen_random_access(),
        "gain": gen_random_gain(),
        "require": "None",
        "score": gen_random_score()
    }

def gen_random_score() -> float:
    return random.uniform(5, 10)

def gen_random_gain() -> str:
    return random.sample(GAIN_ENUM, 1)[0]

def gen_random_access() -> str:
    return random.sample(ACCESS_ENUM, 1)[0]

def gen_random_transition() -> str:
    if random.randint(0, 10) < 2:
        src, dst = random.sample(TRANSITION_ENUM, 2)
        return f"{src}:{dst}"
    else:
        return ""
    
def gen_random_network(seed, size):
    G = nx.random_internet_as_graph(size, seed)
    DG = nx.DiGraph()
    nodes, edges = [], []
    for node in G.nodes:
        nodes.append((node, {
            "os": [],
            "firmware": [],
            "software": [],
            "hardware": [],
            "atomic": [gen_random_atomic_attack()]
        }))
    for src, dst in G.edges:
        trans = gen_random_transition()
        if trans != "":
            trans = [trans]
        edges.append((src, dst, {
            "access": gen_random_access(),
            "transitions": trans
        }))
        trans = gen_random_transition()
        if trans != "":
            trans = [trans]
        edges.append((dst, src, {
            "access": gen_random_access(),
            "transitions": trans
        }))
    DG.add_edges_from(edges)
    DG.add_nodes_from(nodes)

    # pos = nx.spring_layout(DG)
    # nx.draw(DG, pos, with_labels = True, node_size = 300)
    # plt.show()
    return DG

if __name__ == "__main__":
    gen_random_network(1)