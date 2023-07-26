from DataUpdater.updaters.utils import *
import shutil, os
from Logging.Logger import logger

class CWEUpdater():
    def update(self):
        logger.info("Starting to update CWE")
        path = "./data/base/cwe"
        cwe_url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
        try:
            download_and_unzip(cwe_url, path)
        except Exception as e:
            logger.error("Failed to request while updating cwe: %s"%e)
        shutil.move(os.path.join(path, "2000.xml"), os.path.join(path, "CWE.xml"))
