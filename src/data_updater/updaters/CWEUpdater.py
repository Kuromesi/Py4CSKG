from data_updater.utils.utils import *
import shutil, os
from utils.Logger import logger
from utils.Config import config

class CWEUpdater():
    def update(self, base: str):
        logger.info("Starting to update CWE")
        # base = config.get("KnowledgeGraph", "base_path")
        path = os.path.join(base, "cwe")
        cwe_url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip"
        download_and_unzip(cwe_url, path)
        shutil.move(os.path.join(path, "2000.xml"), os.path.join(path, "CWE.xml"))
