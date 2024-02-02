import sys, json, os, re
import pandas as pd
import matplotlib.pyplot as plt
from knowledge_graph.Ontology.CVE import get_vul_type, PRIV_APP, PRIV_ROOT, PRIV_USER, CIA_LOSS, CODE_EXEC_CVED, GAIN_PRIV_CVED, CVEEntry




if __name__ == "__main__":
    precision_test(CVE_PATH)
    