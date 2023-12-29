import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.join(BASE_DIR))

import json, os, re
import pandas as pd
import matplotlib.pyplot as plt
from knowledge_graph.Ontology.CVE import get_vul_type, PRIV_APP, PRIV_ROOT, PRIV_USER, CIA_LOSS, CODE_EXEC_CVED, GAIN_PRIV_CVED

SKIP_FILES = ['CVE-Modified.json', 'CVE-Recent.json', 'product.csv', 'cve.json', 'CVE-2023.json']
YEAR_REG = re.compile(r'CVE-(\d+).json')
SAVE_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.csv"
FIG_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.png"
IMPACT_PATH = "data/base/cve_details/impact.json"
CVE_PATH = "data/base/cve"

regs = [re.compile(r".*gain.*privilege.*"), 
             re.compile(r".*escalat.*"), 
             re.compile(r".*(obtain|gain|as).*(user|administra|root).*"),
             re.compile(r".*hijack.*authenticat.*"),
             re.compile(r".*(create|modify|append|read).*arbitrary.*"),
             re.compile(r".*execut.*"),
             re.compile(r".*takeover.*")]

def precision_test(path):
    with open(IMPACT_PATH, 'r') as f:
        impact_all = json.load(f)
    total_entry, false_entry, all_entry, user_entry, all_false_entry, user_false_entry = 0, 0, 0, 0, 0, 0
    for file in os.listdir(path):
        if file in SKIP_FILES:
            continue
        file = os.path.join(path, file)
        summary, spec = read_json(file, impact_all)
        total_entry += summary[0]
        false_entry += summary[1]
        all_entry += spec[0]
        user_entry += spec[1]
        all_false_entry += spec[2]
        user_false_entry += spec[3]
    print([total_entry, false_entry])
    print([all_entry, user_entry, all_false_entry, user_false_entry])
#     [4798, 288]
# [3103, 1695, 212, 76]

def read_json(path, impact_all):
    with open(path, 'r') as f:
        data = json.load(f)
    cve_items = data['CVE_Items']
    total_entry, false_entry, all_entry, user_entry, all_false_entry, user_false_entry = 0, 0, 0, 0, 0, 0
    for entry in cve_items:
        cve_id = entry['cve']['CVE_data_meta']['ID']
        impact = entry['impact']
        if "baseMetricV2" not in impact:
            continue

        cvss_v2 = impact['baseMetricV2']
        all = cvss_v2['obtainAllPrivilege']
        user = cvss_v2['obtainUserPrivilege']
        gain_privileges = user + all
        
        if gain_privileges:
            if cve_id not in impact_all:
                continue
            cved_impact = impact_all[cve_id]
            total_entry += 1
            if all:
                all_entry += 1
            elif user:
                user_entry += 1
            des = entry['cve']['description']['description_data'][0]['value']
            if is_code_exec(des) and CODE_EXEC_CVED not in impact:
                cved_impact.append(CODE_EXEC_CVED)
            if is_gain_privileges(des) and GAIN_PRIV_CVED not in impact:
                cved_impact.append(GAIN_PRIV_CVED)
            if "Directory Traversal" in cved_impact:
                cved_impact.append(GAIN_PRIV_CVED)

            vul_type = get_vul_type(cvss2=cvss_v2, impact=cved_impact)
            if all:
                if vul_type == PRIV_ROOT:
                    continue
                all_false_entry += 1
            
            if user:
                if vul_type == PRIV_USER:
                    continue
                user_false_entry += 1
            false_entry += 1
                
    return [(total_entry, false_entry), (all_entry, user_entry, all_false_entry, user_false_entry)]
        
def is_code_exec(text) -> bool:
    if "execution" in text.lower() or "execute" in text.lower():
        return True
    return False

def is_gain_privileges(text) -> bool:
    text = text.lower()
    for reg in regs:
        if reg.match(text):
            return True
    return False


if __name__ == "__main__":
    precision_test(CVE_PATH)
    