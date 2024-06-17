import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from knowledge_graph import KGBuilder
import dotenv, os

dotenv.load_dotenv('src/tests/env/knowledge_graph.env')

def test_traverse_all():
    kg_builder = KGBuilder()
    path = os.getenv("BASE_PATH")
    kg_builder.traverse_all(path=path)

if __name__ == '__main__':
    test_traverse_all()