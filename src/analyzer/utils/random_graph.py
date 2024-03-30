import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))


import networkx as nx
import matplotlib.pyplot as plt
from ontologies.cve import *
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
    
def gen_random_network(seed, size) -> nx.DiGraph:
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

def random_graph_to_mulval(model: nx.DiGraph):
    mulval = []
    atomic_attacks = []
    
    excluded = set()
    for node in nx.neighbors(model, 0):
        excluded.add(node)
    mulval.insert(0, "attackerLocated(host_0).")
    while True:
        target = random.randint(1, len(model.nodes) - 1)
        if target in excluded:
            continue
        if nx.has_path(model, 0, target):
            break

    mulval.insert(1, f"attackGoal(netAccess( host_{target}, _, _)).")
    mulval.append("")

    for node in model.nodes(data=True):
        for adjacent_node in nx.neighbors(model, node[0]):
            mulval.append(f"hacl(host_{node[0]}, host_{adjacent_node}, _, _).")
        atomic_attacks.append(node[1]['atomic'][0])
    
    
    mulval.append("")
    for i in range(len(atomic_attacks)):
        mulval.append(f"networkServiceInfo(host_{i} , service_{i}, _, service_{i}_port , service_{i}).")
    
    mulval.append("")
    for i in range(len(atomic_attacks)):
        mulval.append(f"vulExists(host_{i}, 'vul_{i}', service_{i}).")

    mulval.append("")
    for i in range(len(atomic_attacks)):
        atomic_attack = atomic_attacks[i]
        if atomic_attack['access'] == ACCESS_NETWORK or atomic_attack['access'] == ACCESS_ADJACENT:
            access = "remoteExploit"
        else:
            access = "localExploit"
        if atomic_attack['gain'] == CIA_LOSS:
            gain = "ciaLoss"
        else: 
            gain = "privEscalation"
        access = "remoteExploit"
        mulval.append(f"vulProperty('vul_{i}', {access}, privEscalation).")
    return mulval
        

if __name__ == "__main__":
    model = gen_random_network(100, 90)
    mulval = random_graph_to_mulval(model)
    mulval = [f"{line}\n" for line in mulval]
    with open('test.P', 'w') as f:
        f.writelines(mulval)