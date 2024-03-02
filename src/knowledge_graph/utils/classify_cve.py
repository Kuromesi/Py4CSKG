import json, os
import pandas as pd
from service.GDBSaver import GDBSaver
from utils.Config import config
from text_classification.TextClassification import TextClassification
from text_similarity.wsbert import TextSimilarity
from knowledge_graph.Ontology.ontology import *
from utils.Logger import logger
from tqdm import tqdm

MAX_CAPEC = 3
gdb = GDBSaver()
ts = TextSimilarity()
tc = TextClassification()
tc.init_bert()

def classify_cwe(des):
    return tc.bert_predict(des)

def classify_capec(des, filter) -> list[str]:
    capec_df = ts.calculate_similarity(des, filter)
    return capec_df['id'].tolist()[: MAX_CAPEC]

def get_related_capec(cve: str) -> list[str]:
    query = f"MATCH (v:Vulnerability)-[]-(w:Weakness)-[]-(p:Pattern) \
            WHERE v.id=\"{cve}\" \
            RETURN p.id"
    res = gdb.sendQuery(query)
    return [r[0] for r in res]

def classify_cve(cve: json):
    id = cve['CVE_data_meta']['ID']
    des = cve['description']['description_data'][0]['value']
    cwes = cve['problemtype']['problemtype_data'][0]['description']
    tmp = []
    for cwe in cwes:
        if cwe['value'] == "NVD-CWE-noinfo" or cwe['value'] == "NVD-CWE-Other":
            continue
        tmp.append(cwe['value'])
    cwes = tmp
    cwe_classified = False
    if not cwes:
        cwes.append(classify_cwe(des))
        cwe_classified = True  
    capecs = []
    if not cwe_classified:
        capecs += get_related_capec(id)
    capecs = classify_capec(des, capecs)
    return cwes if cwe_classified else [], capecs

def get_cve_list():
    base = config.get("DataUpdater", "base_path")
    path = os.path.join(base, "cve")
    cve_paths = os.listdir(path)
    not_included = ["CVE-Modified.json", "CVE-Recent.json", "cve.json"]
    base = config.get("KnowledgeGraph", "neo4j_path")
    
    for cve_path in cve_paths:
        if cve_path in not_included:
            continue
        df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        if os.path.splitext(cve_path)[1] == '.json':
            with open(os.path.join(path, cve_path), 'r') as f:
                cves = json.load(f)['CVE_Items']
            cves = tqdm(cves)
            cves.set_description("discovering relations")
            for cve in cves:
                id = cve['cve']['CVE_data_meta']['ID']
                cves.set_postfix(id=id)
                cwes, capecs = classify_cve(cve['cve'])
                for cwe in cwes:
                    df.loc[len(df.index)] = [cve['cve']['CVE_data_meta']['ID'], cwe, VULNERABILITY_WEAKNESS_REL]
                for capec in capecs:
                    df.loc[len(df.index)] = [capec, cve['cve']['CVE_data_meta']['ID'], TECHNIQUE_VULNERABILITY_REL]
        df.to_csv(os.path.join(base, f'neo4j/relations/{os.path.splitext(cve_path)[0]}_added_rel.csv'), index=False)


if __name__ == "__main__":
    get_cve_list()


    