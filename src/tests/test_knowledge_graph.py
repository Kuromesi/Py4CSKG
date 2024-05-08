import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from knowledge_graph import KGBuilder

def test_traverse_all():
    kg_builder = KGBuilder()
    kg_builder.traverse_all()

if __name__ == '__main__':
    test_traverse_all()