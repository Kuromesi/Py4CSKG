import json, os

def load_project(path: str) -> dict:
    with open(os.path.join(path, "nodes.json"), encoding='utf-8') as f:
        nodes = json.load(f)
    with open(os.path.join(path, "edges.json"), encoding='utf-8') as f:
        edges = json.load(f)
    return {'nodes': nodes, 'edges': edges}