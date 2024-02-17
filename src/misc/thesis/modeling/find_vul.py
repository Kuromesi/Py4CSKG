import os, sys, json

BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.join(BASE_DIR))

import pandas as pd

from analyzer.utils.knowledge_query import KGQuery
from service.GDBSaver import GDBSaver
from knowledge_graph.Ontology.CVE import PRIV_USER, PRIV_ROOT, CIA_LOSS

def find_vul_for_product(path):
    kg = KGQuery(GDBSaver())
    product_df = pd.read_csv(path)
    vul_df = pd.DataFrame(columns=['Product', 'CVE', 'Impact', 'Score'])
    for index, row in product_df.iterrows():
        product_name = row['product']
        version = row['version']
        cve_entries = kg.find_vuls(product_name, version)
        for cve_entry in cve_entries:
            vul_df.loc[len(vul_df.index)] = [product_name, cve_entry.id, cve_entry.impact, cve_entry.score]
    vul_df.to_csv('myData/thesis/graduation/experiment/vul_info.csv', index=False)

def vul_info_summary(path):
    df = pd.read_csv(path)
    summary = {}
    for index, row in df.iterrows():
        product = row['Product']
        if product not in summary:
            summary[product] = {
                CIA_LOSS: 0,
                PRIV_USER: 0,
                PRIV_ROOT: 0,
                "score": 0
            }
        impact = row['Impact']
        summary[product][impact] += 1
        summary[product]["score"] += row['Score']
    summary_df = pd.DataFrame(columns=['product', 'none', 'user', 'root', 'total', 'score'])
    for product, count_dict in summary.items():
        total = count_dict[CIA_LOSS] + count_dict[PRIV_ROOT] + count_dict[PRIV_USER]
        summary_df.loc[len(summary_df.index)] = [product, count_dict[CIA_LOSS], count_dict[PRIV_USER], count_dict[PRIV_ROOT], total, count_dict['score'] / total]
    summary_df.to_csv('myData/thesis/graduation/experiment/vul_info_summary.csv', index=False)

def vul_info_analyze(path):
    gdb = GDBSaver()
    df = pd.read_csv(path)
    summary = {}
    for index, row in df.iterrows():
        id = row["CVE"]
        product = row['Product']
        if product not in summary:
            summary[product] = {
                'cwe': {},
                'capec': {},
            }
        cwe_query = f"match (w:Weakness)-[]-(n:Vulnerability) where n.id=\"{id}\" return w.id"
        cwe_nodes = gdb.sendQuery(cwe_query)
        for node in cwe_nodes:
            cwe = node[0]
            if cwe not in summary[product]['cwe']:
                summary[product]['cwe'][cwe] = 0
            summary[product]['cwe'][cwe] += 1
        capec_query = f"match (t:Technique)-[]-(n:Vulnerability) where n.id=\"{id}\" return t.id"
        capec_nodes = gdb.sendQuery(capec_query)
        for node in capec_nodes:
            capec = node[0]
            if capec not in summary[product]['capec']:
                summary[product]['capec'][capec] = 0
            summary[product]['capec'][capec] += 1
    json.dump(summary, open('myData/thesis/graduation/experiment/vul_info_summary.json', 'w'), indent=4)

def cwe_capec_summary(path):
    cwe_df = pd.DataFrame(columns=['CWE', 'count'])
    capec_df = pd.DataFrame(columns=['CAPEC', 'count'])
    with open(path, 'r') as f:
        data = json.load(f)
    capec_dict = {}
    cwe_dict = {}
    for product in data:
        for cwe in data[product]['cwe']:
            if cwe not in cwe_dict:
                cwe_dict[cwe] = 0
            cwe_dict[cwe] += data[product]['cwe'][cwe]
        for capec in data[product]['capec']:
            if capec not in capec_dict:
                capec_dict[capec] = 0
            capec_dict[capec] += data[product]['capec'][capec]
    for cwe in cwe_dict:
        cwe_df.loc[len(cwe_df)] = [cwe, cwe_dict[cwe]]
    for capec in capec_dict:
        capec_df.loc[len(capec_df)] = [capec, capec_dict[capec]]
    cwe_df = cwe_df.sort_values(by='count', ascending=False)
    capec_df = capec_df.sort_values(by='count', ascending=False)
    cwe_df.to_csv('myData/thesis/graduation/experiment/cwe_summary.csv', index=False)
    capec_df.to_csv('myData/thesis/graduation/experiment/capec_summary.csv', index=False)
                  

if __name__ == '__main__':
    # find_vul_for_product('myData/thesis/graduation/experiment/vul_product.csv')
    # vul_info_summary('myData/thesis/graduation/experiment/vul_info.csv')
    # vul_info_analyze('myData/thesis/graduation/experiment/vul_info.csv')
    cwe_capec_summary('myData/thesis/graduation/experiment/vul_info_summary_bk.json')

