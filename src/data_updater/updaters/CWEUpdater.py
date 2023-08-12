from data_updater.updaters.utils import *
import shutil, os
from utils.Logger import logger
from utils.Config import config

class CWEUpdater():
    def update(self):
        logger.info("Starting to update CWE")
        base = config.get("DataUpdater", "base_path")
        path = os.path.join(base, "base/cwe")
        cwe_url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
        try:
            download_and_unzip(cwe_url, path)
        except Exception as e:
            logger.error("Failed to request while updating cwe: %s"%e)
        shutil.move(os.path.join(path, "2000.xml"), os.path.join(path, "CWE.xml"))
