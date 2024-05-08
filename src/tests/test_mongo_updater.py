import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from dotenv import load_dotenv
from database.mongo_updater import MongoUpdater
from service.mongo_connector import new_mongo_connector

def test_full_update():
    uri = os.getenv("MONGO_URI")
    port = int(os.getenv("MONGO_PORT"))
    username = os.getenv("MONGO_USERNAME")
    password = os.getenv("MONGO_PASSWORD")
    connector = new_mongo_connector(uri, port, username, password)
    mu = MongoUpdater(connector)
    mu.update_cve("data/base_copy/cve")

if __name__ == '__main__':
    load_dotenv('src/tests/env/mongo_db.env')
    test_full_update()