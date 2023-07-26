from DataUpdater.updater import *
from KnowledgeGraph.KGBuilder import *
from Logging.Logger import Logger
DATA_PATH = "./data"
if __name__ == "__main__":
    # logger = Logger(logger_level="DEBUG")
    # updater = Updater()
    # updater.update_attack()
    # updater.update()

    kg_builder = KGBuilder()
    kg_builder.to_csv_neo4j()