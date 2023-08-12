from data_updater.updater import *
from knowledge_graph.KGBuilder import *
from text_classification.TextClassification import CVE2CWE

import os
os.environ['NUMEXPR_MAX_THREADS'] = '16'
if __name__ == "__main__":
    # updater = Updater()
    # updater.update_attack()
    # updater.update_cve_details()

    # kg_builder = KGBuilder()
    # kg_builder.to_csv_neo4j()
    cve2cwe = CVE2CWE()
    cve2cwe.init_bert()
    cve2cwe.bert_predict("test")