from data_updater.updaters import *
from utils.Logger import logger
from utils.Config import config
import os

class Updater():
    def __init__(self, base: str) -> None:
        self.base = base
        self.check_path()

    def check_path(self):
        # base = config.get("KnowledgeGraph", "base_path")
        base = self.base
        if not os.path.exists(os.path.join(base, "cve")):
            os.makedirs(os.path.join(base, "cve"))
        if not os.path.exists(os.path.join(base, "capec")):
            os.makedirs(os.path.join(base, "capec"))
        if not os.path.exists(os.path.join(base, "cwe")):
            os.makedirs(os.path.join(base, "cwe"))
        if not os.path.exists(os.path.join(base, "attack")):
            os.makedirs(os.path.join(base, "attack"))
        if not os.path.exists(os.path.join(base, "cve_details")):
            os.makedirs(os.path.join(base, "cve_details"))

    def update_cve_details(self) -> tuple[bool, str]:
        cdu = CVEDetailsUpdater()
        try:
            cdu.update(self.base)
        except Exception as e:
            logger.error(f"failed to update cve details: {e}")
            return False, f"failed to update cve details: {e}"
        return True, ""
    
    def update_attack(self) -> tuple[bool, str]:
        au = ATTACKUpdater()
        try:
            au.update(self.base)
        except Exception as e:
            logger.error(f"failed to update att&ck: {e}")
            return False, f"failed to update att&ck: {e}"
        return True, ""
    
    def update_cve(self) -> tuple[bool, str]:
        cveu = CVEUpdater()
        try:
            cveu.update(self.base)
        except Exception as e:
            logger.error(f"failed to update cve: {e}")
            return False, f"failed to update cve: {e}"
        return True, ""
    
    def update_cwe(self) -> tuple[bool, str]:
        cweu = CWEUpdater()
        try:
            cweu.update(self.base)
        except Exception as e:
            logger.error(f"failed to update cwe: {e}")
            return False, f"failed to update cwe: {e}"
        return True, ""
    
    def update_capec(self) -> tuple[bool, str]:
        capecu = CAPECUpdater()
        try:
            capecu.update(self.base)
        except Exception as e:
            logger.error(f"failed to update capec: {e}")
            return False, f"failed to update capec: {e}"
        return True, ""

    def update(self) -> tuple[bool, str]:
        """update attack -> cve -> cwe -> capec
        """        
        logger.info("Starting to update knowledge bases")
        total, failed = 4, 0
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
        # if not self.update_cve_details():
        #     failed += 1
        #     failed_list.append("cve_details")
        logger.info(f"{total - failed}/{total} knowledge bases have been updated")
        if failed_list:
            failed_str = " ".join(failed_list)
            logger.info(f"failed to update knowledge bases: [{failed_str}]")
            return f"failed to update knowledge bases: [{failed_str}]"
        return True, ""
def new_updater(base: str):
    return Updater(base)