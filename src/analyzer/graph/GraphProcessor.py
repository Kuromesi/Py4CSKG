import networkx as nx

class GraphProcessor:
    def convert_pyvis(self, graph:dict):
        """Receive pyvis json format graph from frontend and convert it into networkx graph.

        Args:
            graph (dict): pyvis graph
        """        
        # Nodes
        color_map = []
        nodes = []
        node_type = {
            'software': {},
            'hardware': {},
            'os': {},
            'firmware': {},
            'component': {},
            'defender': {},
            'entry': {}
        }
        node_dict = {}
        for node in graph['nodes']:
            # color_map.append(node.pop('color'))
            # id = node.pop('id')
            color_map.append(node['color'])
            id = node['id']
            nodes.append((id, node))
            if node['type'] not in node_type:
                node_type[node['type']] = {}
            node_type[node['type']].update({id: node}) # Classified with corresponding ontologies
            node_dict.update({id: node})
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
        return graph
        # self.graph = graph
        # self.G = G
        # self.node_dict = node_dict

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
