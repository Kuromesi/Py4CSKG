import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from dotenv import load_dotenv
import uvicorn

def test_mongo_client():
    load_dotenv('src/tests/env/mongo_db.env')
    load_dotenv('src/tests/env/mongo_client.env')
    from clients.mongo_client import app as mongo_app
    uvicorn.run(mongo_app, host="127.0.0.1", port=8000)

def test_ts_client():
    load_dotenv('src/tests/env/text_similarity.env')
    from clients.text_similarity_client import app as ts_app
    uvicorn.run(ts_app, host="127.0.0.1", port=8000)

def test_tc_client():
    load_dotenv('src/tests/env/text_classification.env')
    from clients.text_classification_client import app as tc_app
    uvicorn.run(tc_app, host="127.0.0.1", port=8000)

def test_updater_client():
    load_dotenv('src/tests/env/updater.env')
    from clients.data_updater_client import app as up_app
    uvicorn.run(up_app, host="127.0.0.1", port=8000)

def test_analyzer_client():
    load_dotenv('src/tests/env/mongo_db.env')
    from clients.analyzer_client import app as an_app
    uvicorn.run(an_app, host="127.0.0.1", port=8000)

def test_traversers_client():
    load_dotenv('src/tests/env/knowledge_graph.env')
    from clients.traversers_client import app as tra_app
    uvicorn.run(tra_app, host="127.0.0.1", port=8000)

if __name__ == "__main__":
    # test_tc_client()
    # test_ts_client()
    # test_mongo_client()
    # test_updater_client()
    # test_analyzer_client()
    test_traversers_client()