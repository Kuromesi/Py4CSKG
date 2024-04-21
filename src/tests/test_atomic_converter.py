import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from analyzer.atomic_convert.mongo_converter import MongoAtomicConverter
from dotenv import load_dotenv

def test_mongo_converter_find_by_id():
    mongo_converter = MongoAtomicConverter()
    mongo_converter.find_by_id("CVE-2021-44228")

if __name__ == '__main__':
    load_dotenv('src/tests/env/mongo_db.env')
    test_mongo_converter_find_by_id()