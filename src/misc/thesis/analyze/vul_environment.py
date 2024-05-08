


import os, re, sys, json
import pandas as pd

BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.join(BASE_DIR))
from service.GDBSaver import GDBSaver
from knowledge_graph.Ontology.CVE import get_vul_type, PRIV_USER, PRIV_ROOT, GAIN_PRIV_CVED
from utils import CVE_PATTERN

regs = [re.compile(r".*gain.*privilege.*"), 
             re.compile(r".*escalat.*"), 
             re.compile(r".*(obtain|gain|as).*(user|administra|root).*"),
             re.compile(r".*hijack.*authenticat.*"),
             re.compile(r".*(create|modify|append|read).*arbitrary.*"),
             re.compile(r".*execut.*"),
             re.compile(r".*takeover.*")]

def get_all_folders(path):
   folders = []
   for item in os.listdir(path):
       item_path = os.path.join(path, item)
       if os.path.isdir(item_path):
           folders.append(item_path)
           folders.extend(get_all_folders(item_path))
   return folders

def get_paths(path):
    gdb = GDBSaver()
    paths = get_all_folders(path)
    cves = [CVE_PATTERN.findall(p)[0] for p in paths if CVE_PATTERN.match(p)]
    cves = list(set(cves))
    df = pd.DataFrame(columns=["id", "impact", "description"])
    for cve in cves:
        query = f"MATCH (n:Vulnerability) WHERE n.id = '{cve}' RETURN n"
        node = gdb.sendQuery(query)
        if not node:
            continue
        while isinstance(node, list):
            node = node[0]
        df.loc[len(df.index)] = [cve, node["impact"], node["description"]]
    df.to_csv("./vulenv_impact.csv", index=False)

def get_vul_env_impact(path):
    gdb = GDBSaver()
    paths = get_all_folders(path)
    cves = [CVE_PATTERN.findall(p)[0] for p in paths if CVE_PATTERN.match(p)]
    cves = list(set(cves))
    df = pd.DataFrame(columns=["id", "access", "impact", "description"])
    for cve in cves:
        query = f"MATCH (n:Vulnerability) WHERE n.id = '{cve}' RETURN n"
        node = gdb.sendQuery(query)
        if not node:
            continue
        while isinstance(node, list):
            node = node[0]
        if node["id"] == "CVE-2020-7247":
            print(1)
        print(node["id"])
        des = node["description"]
        cvss2 = json.loads(node['baseMetricV2'])
        cvss3 = json.loads(node['baseMetricV3'])
        if node["impact"] in []:
            impact = node["impact"]
        else:
            cved_impact = node["cved_impact"].split(", ")
            if is_gain_privileges(des) and GAIN_PRIV_CVED not in cved_impact:
                cved_impact.append(GAIN_PRIV_CVED)
            if "Directory Traversal" in cved_impact:
                cved_impact.append(GAIN_PRIV_CVED)
            try:
                impact = get_vul_type(cvss2, cvss3, cved_impact)
            except:
                print(node["id"])
                continue
        if cvss2:
            access = cvss2["cvssV2"]["accessVector"]
        else:
            access = cvss3["cvssV3"]["attackVector"]
        df.loc[len(df.index)] = [cve, access, impact, node["description"]]
    df.sort_values(by="impact", ascending=False, inplace=True)
    df.to_csv("./vulenv_impact.csv", index=False)

def is_gain_privileges(text) -> bool:
    text = text.lower()
    for reg in regs:
        if reg.match(text):
            return True
    return False


if __name__ == "__main__":
    get_vul_env_impact("/home/kuromesi/MyCOde/github.com/vulhub")