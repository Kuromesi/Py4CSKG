from DataUpdater.updaters.CVEDetailsUpdater import *
from DataUpdater.updaters.ATTACKUpdater import *
from DataUpdater.updaters.CVEUpdater import *

class Updater():
    def update_cve_details(self):
        cdu = CVEDetailsUpdater()
        cdu.update()
    
    def update_attack(self):
        au = ATTACKUpdater()
        au.update()
    
    def update_cve():
        pass
    
    def update_cwe():
        pass
    
    def update_capec():
        pass

    def update_all(self):
        self.update_attack()
        self.update_cve()
        self.update_cwe()
        self.update_capec()
        self.update_cve_details()