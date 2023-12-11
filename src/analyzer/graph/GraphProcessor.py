import networkx as nx
import json

def gen_tuple(product):
    name = product['product']
    name = name.replace(" ", "_")
    return (name, product['version'], product['access'], product['privilege'])

class GraphProcessor:
    def convert_pyvis(self, path:str):
        """Receive pyvis json format graph from frontend and convert it into networkx graph.

        Args:
            path (str): pyvis graph path
        """        
        # Nodes
        # color_map = []
        with open(path, "r") as f:
            graph = json.load(f)
        group = {}
        nodes = []
        node_dict = {}
        for node in graph['nodes']:
            # color_map.append(node.pop('color'))
            # id = node.pop('id')
            id = node['id']
            if node['group']:
                if node['group'] not in group:
                    group[node['group']] = []
                group[node['group']].append(id)
            
            tmp = {"os": [], "software": [], "hardware": [], "firmware": [], "cve": [], "entry": []}
            for component, products in node['component'].items():
                if component == "cve":
                    for cve in products:
                        tmp[component].append(cve)
                else:
                    for _, product in products.items():
                        tmp[component].append(gen_tuple(product))

            if "entry" in node:
                for entry in node['entry']:
                    tmp['entry'].append(entry)
            node.update(tmp)
            del(node['component'])
            del(node['id'])
            nodes.append((node['name'], node))
            node_dict.update({id: node})
        # Edges
        edges = []
        for edge in graph['edges']:
            if 'from' in edge and 'to' in edge:
                src = edge.pop('src')
                dest = edge.pop('dst')
                edges.append((src, dest, edge))
                if edge['edge_type'] == "undirected":
                    edges.append((src, dest, edge))
        
        G = nx.Graph()    
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)
        
        graph = {
            'graph': G,
            }
        return graph

    def get_neighbors(self, node, filter={}):
        """get neighbors of a node and do some filtering work
        e.g. get neighbors which are software

        Args:
            node (_type_): _description_
            filter (dict, optional): _description_. Defaults to {}.

        Returns:
            list: _description_
        """        
        neighbors = list(self.G.neighbors(node))
        if filter:
            for neighbor in neighbors:
                for key in filter:
                    if neighbor[key] not in filter[key]:
                        neighbors.remove(neighbor)
        return neighbors

    def redraw(self, result):
        """Redraw the original graph, change the node color and etc.

        Args:
            result (dict): _description_
        """        
        vul_node_attrs = {}
        for vul_node in result['root']:
            vul_node_attrs[vul_node] = {'color': "#ff0000"}
        for vul_node in result['user']:
            vul_node_attrs[vul_node] = {'color': "#ffff00"}
        for vul_node in result['other']:
            vul_node_attrs[vul_node] = {'color': "#ff9966"}
        nx.set_node_attributes(self.G, vul_node_attrs)

    def new_graph(self, result):
        DG = nx.DiGraph()
        nodes = []
        edges = []
        for node in result['root']:
            nodes.append((node, self.node_dict[node]))
            edge = [(n, node) for n in self.G.neighbors(node)]
            edges.extend(edge)
        for node in result['user']:
            nodes.append((node, self.node_dict[node]))
            edge = [(n, node) for n in self.G.neighbors(node)]
            edges.extend(edge)
        for node in result['other']:
            nodes.append((node, self.node_dict[node]))
            edge = [(n, node) for n in self.G.neighbors(node)]
            edges.extend(edge)
        DG.add_nodes_from(nodes)
        DG.add_edges_from(edges)
        return DG

if __name__ == "__main__":
    gp = GraphProcessor()
    with open("src/webapp/data/new_demo/graph.json", "r") as f:
        graph = json.load(f)
    gp.convert_pyvis(graph)