from data_updater.updaters import *
from utils.Logger import logger
from utils.Config import config
import os

class Updater():
    def __init__(self) -> None:
        self.check_path()

    def check_path(self):
        base = config.get("KnowledgeGraph", "base_path")
        if not os.path.exists(os.path.join(base, "base")):
            os.makedirs(os.path.join(base, "base"))
        if not os.path.exists(os.path.join(base, "base/cve")):
            os.makedirs(os.path.join(base, "base/cve"))
        if not os.path.exists(os.path.join(base, "base/capec")):
            os.makedirs(os.path.join(base, "base/capec"))
        if not os.path.exists(os.path.join(base, "base/cwe")):
            os.makedirs(os.path.join(base, "base/cwe"))
        if not os.path.exists(os.path.join(base, "base/attack")):
            os.makedirs(os.path.join(base, "base/attack"))
        if not os.path.exists(os.path.join(base, "base/cve_details")):
            os.makedirs(os.path.join(base, "base/cve_details"))

    def update_cve_details(self) -> bool:
        cdu = CVEDetailsUpdater()
        try:
            cdu.update()
        except Exception as e:
            logger.error(f"failed to update cve details: {e}")
            return False
        return True
    
    def update_attack(self) -> bool:
        au = ATTACKUpdater()
        try:
            au.update()
        except Exception as e:
            logger.error(f"failed to update att&ck: {e}")
            return False
        return True
    
    def update_cve(self) -> bool:
        cveu = CVEUpdater()
        try:
            cveu.update()
        except Exception as e:
            logger.error(f"failed to update cve: {e}")
            return False
        return True
    
    def update_cwe(self) -> bool:
        cweu = CWEUpdater()
        try:
            cweu.update()
        except Exception as e:
            logger.error(f"failed to update cwe: {e}")
            return False
        return True
    
    def update_capec(self) -> bool:
        capecu = CAPECUpdater()
        try:
            capecu.update()
        except Exception as e:
            logger.error(f"failed to update capec: {e}")
            return False
        return True

    def update(self):
        """update attack -> cve -> cwe -> capec -> cve_details
        """        
        logger.info("Starting to update knowledge bases")
        total, failed = 5, 0
        failed_list = []
        if not self.update_attack():
            failed += 1
            failed_list.append("att&ck")
        if not self.update_cve():
            failed += 1
            failed_list.append("cve")
        if not self.update_cwe():
            failed += 1
            failed_list.append("cwe")
        if not self.update_capec():
            failed += 1
            failed_list.append("capec")
        if not self.update_cve_details():
            failed += 1
            failed_list.append("cve_details")
        logger.info(f"{total - failed}/{total} knowledge bases have been updated")
        if failed_list:
            failed_str = " ".join(failed_list)
            logger.info(f"failed to update knowledge bases: [{failed_str}]")