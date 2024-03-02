from data_updater.utils.utils import *
import shutil, os
from utils.Logger import logger
from utils.Config import config


class CAPECUpdater():
    def update(self):
        logger.info("Starting to update CAPEC")
        base = config.get("KnowledgeGraph", "base_path")
        path = os.path.join(base, "base/capec")
        capec_url = "https://capec.mitre.org/data/xml/views/1000.xml.zip"
        download_and_unzip(capec_url, path=path)
        shutil.move(os.path.join(path, "1000.xml"), os.path.join(path, "CAPEC.xml"))

if __name__ == "__main__":
    capecu = CAPECUpdater()
    capecu.update()