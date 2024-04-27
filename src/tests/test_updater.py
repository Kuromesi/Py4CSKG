import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from dotenv import load_dotenv
from data_updater.updater import new_updater

load_dotenv('src/tests/env/updater.env')
updater = new_updater(os.getenv("BASE_PATH"))
def test_full_update():
    updater.update()

def test_update_attack():
    updater.update_attack()

def test_update_cved():
    updater.update_cve_details()

def test_update_cve():
    updater.update_cve()

if __name__ == '__main__':
    # test_update_cved()
    test_update_cve()
    # test_full_update()
