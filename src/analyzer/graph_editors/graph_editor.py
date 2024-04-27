import yaml
import networkx as nx
from utils.Logger import logger
from typing import Optional, List
from pydantic import BaseModel

class EdgeProperties(BaseModel):
    name: Optional[str] = ""
    access: str
    transitions: Optional[List[str]] = []

class EdgeCreate(BaseModel):
    source: str
    destination: str
    bidirectional: Optional[bool] = False
    properties: EdgeProperties

class EdgeModify(BaseModel):
    target: str
    properties: EdgeProperties

class EdgeDelete(BaseModel):
    pass

class GraphEdge(BaseModel):
    create: List[EdgeCreate] = []
    modify: List[EdgeModify] = []
    delete: List[EdgeDelete] = []

class AtomicAttack(BaseModel):
    name: str
    score: float
    access: str
    require: str
    gain: str

class Product(BaseModel):
    product: str
    version: str

class NodeProperties(BaseModel):
    name: str
    des: Optional[str] = ""
    atomicAttacks: Optional[List[AtomicAttack]] = []


class NodeCreate(BaseModel):
    properties: NodeProperties

class NodeModify(BaseModel):
    target: str
    properties: NodeProperties

class NodeDelete(BaseModel):
    target: str

class GraphNode(BaseModel):
    create: List[NodeCreate] = []
    modify: List[NodeModify] = []
    delete: List[NodeDelete] = []

class GraphData(BaseModel):
    nodes: Optional[GraphNode]
    edges: Optional[GraphEdge]

class GraphEditor:
    
    def edit_graph(self, graph: nx.DiGraph, data: GraphData, skip_bad_data=True):

        if data.nodes:
            for modify in data.nodes.modify:
                target = modify.target
                if target not in graph.nodes:
                    if skip_bad_data:
                        logger.warning(f"Node {target} not found in graph. Skipping.")
                        continue
                    if not skip_bad_data:
                        raise ValueError(f"Node {target} not found in graph.")
                if modify.properties.name in graph.nodes:
                    if skip_bad_data:
                        logger.warning(f"Node {modify.properties.name} already exists in graph. Skipping.")
                        continue
                    if not skip_bad_data:
                        raise ValueError(f"Node {modify.properties.name} already exists in graph.")
                node = graph.nodes[target]
                node.update(modify.properties)
            for create in data.nodes.create:
                if create.properties.name in graph.nodes:
                    if skip_bad_data:
                        logger.warning(f"Node {create.properties.name} already exists in graph. Skipping.")
                        continue
                    if not skip_bad_data:
                        raise ValueError(f"Node {create.properties.name} already exists in graph.")
                graph.add_node(create.properties.name, **create.properties)
            for delete in data.nodes.delete:
                if delete.target not in graph.nodes:
                    if skip_bad_data:
                        logger.warning(f"Node {delete.target} not found in graph. Skipping.")
                        continue
                    if not skip_bad_data:
                        raise ValueError(f"Node {delete.target} not found in graph.")
                graph.remove_node(delete.target)
        if data.edges:
            for create in data.edges.create:
                if create.source not in graph.nodes or create.destination not in graph.nodes:
                    if skip_bad_data:
                        logger.warning(f"Edge {create.source} -> {create.destination} not found in graph. Skipping.")
                        continue
                    if not skip_bad_data:
                        raise ValueError(f"Edge {create.source} -> {create.destination} not found in graph.")
                graph.add_edge(create.source, create.destination, **create.properties.__dict__)
                if create.bidirectional:
                    graph.add_edge(create.destination, create.source, **create.properties.__dict__)

        
if __name__ == "__main__":
    model = nx.DiGraph()
    ge = GraphEditor()
    ge.edit_graph(model, "data/reports/vul_env/graph.yaml")
    with open("data/reports/vul_env/graph.yaml", 'r') as f:
        data = yaml.safe_load(f)
    test = GraphData(**data)
    if test.edges:
        print(1)
    print(test)