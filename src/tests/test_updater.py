import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from data_updater import Updater

def test_full_update():
    updater = Updater()
    updater.update()

def test_update_attack():
    updater = Updater()
    updater.update_attack()

def test_update_cved():
    updater = Updater()
    updater.update_cve_details()

if __name__ == '__main__':
    # test_update_cved()
    test_full_update()