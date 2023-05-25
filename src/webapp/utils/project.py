import json, os

def load_project(path: str) -> dict:
    with open(os.path.join(path, "graph.json"), 'r', encoding='utf-8') as f:
        graph = json.load(f)
    return graph