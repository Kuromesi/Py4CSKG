import pandas as pd
import json
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt
from utils.analyze import ModelAnalyzer

# df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
# t = df[0: 10]

# net = Network()
# for index, d in t.iterrows():
#     net.add_node(d['id'], des=d['description'], name=d['name'], title=d['id'])
# net.show('demo1.html')

def convert_pyvis(path):
    graph = json.load(open(path, 'r', encoding='utf-8'))
    # Nodes
    color_map = []
    nodes = []
    node_type = {}
    for node in graph['nodes']:
        color_map.append(node.pop('color'))
        id = node.pop('id')
        nodes.append((id, node))
        if node['type'] not in node_type:
            node_type[node['type']] = []
        node_type[node['type']].append(id)
        
    # Edges
    edges = []
    for edge in graph['edges']:
        if 'from' in edge and 'to' in edge:
            src = edge.pop('from')
            dest = edge.pop('to')
            edges.append((src, dest, edge))
    
    G = nx.Graph()    
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
    
    graph = {
        'graph': G,
        'node_type': node_type
        }
    
    nx.draw(G, node_color=color_map)
    plt.show()
    plt.savefig("./1.jpg")
    return graph
    

if __name__ == '__main__':
    path = "src/webapp/data/Demonstration_new/graph.json"
    # convert_pyvis(path)
    ma = ModelAnalyzer()
    # ma.vul_find("microsoft windows server 2008", "")
    graph = json.load(open(path))
    ma.convert_pyvis(graph)
    ma.analyze()