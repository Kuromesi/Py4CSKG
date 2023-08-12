from data_updater.updaters.CVEDetailsUpdater import *
from data_updater.updaters.ATTACKUpdater import *
from data_updater.updaters.CVEUpdater import *
from data_updater.updaters.CWEUpdater import *
from data_updater.updaters.CAPECUpdater import *
from utils.Logger import logger
import os

class Updater():
    def __init__(self) -> None:
        self.check_path()

    def check_path(self):
        if not os.path.exists("./data/base"):
            os.makedirs("./data/base")
        if not os.path.exists("./data/base/cve"):
            os.makedirs("./data/base/cve")
        if not os.path.exists("./data/base/capec"):
            os.makedirs("./data/base/capec")
        if not os.path.exists("./data/base/cwe"):
            os.makedirs("./data/base/cwe")
        if not os.path.exists("./data/base/attack"):
            os.makedirs("./data/base/attack")
        if not os.path.exists("./data/base/cve_details"):
            os.makedirs("./data/base/cve_details")

    def update_cve_details(self):
        cdu = CVEDetailsUpdater()
        cdu.update()
    
    def update_attack(self):
        au = ATTACKUpdater()
        au.update()
    
    def update_cve(self):
        cveu = CVEUpdater()
        cveu.update()
    
    def update_cwe(self):
        cweu = CWEUpdater()
        cweu.update()
    
    def update_capec(self):
        capecu = CAPECUpdater()
        capecu.update()

    def update(self):
        """update attack -> cve -> cwe -> capec -> cve_details
        """        
        logger.info("Starting to update knowledge bases")
        self.update_attack()
        self.update_cve()
        self.update_cwe()
        self.update_capec()
        self.update_cve_details()
        logger.info("Updating knowledge bases finished")