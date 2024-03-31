import networkx as nx

class PyvisAdapter:
    """convert pyvis graph
    """    
    def convert(self, pyvis_graph: dict):
        nodes = []
        for node in pyvis_graph['nodes']:
            id = node['id']
            tmp = {"os": [], "software": [], "hardware": [], "firmware": [], "cve": []}
            for component, products in node['component'].items():
                if component == "cve":
                    for cve in products:
                        tmp[component].append(cve)
                else:
                    for _, product in products.items():
                        tmp[component].append(self.gen_tuple(product))
                        
            node.update(tmp)
            del(node['component'])
            del(node['id'])
            nodes.append((node['name'], node))
        # Edges
        edges = []
        for edge in pyvis_graph['edges']:
            if 'from' in edge and 'to' in edge:
                src = edge.pop('src')
                dest = edge.pop('dst')
                edges.append((src, dest, edge))
                if edge['edge_type'] == "undirected":
                    edges.append((src, dest, edge))
        
        converted_graph = nx.DiGraph()
        converted_graph.add_nodes_from(nodes)
        converted_graph.add_edges_from(edges)
        return converted_graph

    def gen_tuple(product):
        name = product['product']
        name = name.replace(" ", "_")
        return (name, product['version'], product['access'], product['privilege'])