from DataUpdater.updater import *
from KnowledgeGraph.KGBuilder import *
from utils.Logger import Logger
import os
os.environ['NUMEXPR_MAX_THREADS'] = '16'
DATA_PATH = "./data"
if __name__ == "__main__":
    # logger = Logger(logger_level="DEBUG")
    updater = Updater()
    # updater.update_attack()
    updater.update_cve_details()

    kg_builder = KGBuilder()
    kg_builder.to_csv_neo4j()