import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.join(BASE_DIR))

import json, os, re
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix
from matplotlib import rcParams
from knowledge_graph.Ontology.CVE import get_vul_type, PRIV_APP, PRIV_ROOT, PRIV_USER, CIA_LOSS, CODE_EXEC_CVED, GAIN_PRIV_CVED

SKIP_FILES = ['CVE-Modified.json', 'CVE-Recent.json', 'product.csv', 'cve.json', 'CVE-2023.json']
YEAR_REG = re.compile(r'CVE-(\d+).json')
SAVE_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.csv"
FIG_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.png"
IMPACT_PATH = "data/base_copy/cve_details/impact.json"
CVE_PATH = "data/base_copy/cve"

pred = []
test = []
total_cia = 500
test_cia = 0
flag = True

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
    files = os.listdir(path)
    files.sort()
    for file in files:
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
    global pred, test, total_cia, flag, test_cia
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

        if total_cia > 0 and not (user or all):
            total_cia -= 1
            if total_cia == 0:
                flag = False

        gain_privileges = user + all + flag
        
        if gain_privileges:
            if user or all:
                if cve_id not in impact_all:
                    continue
                cved_impact = impact_all[cve_id]
            else:
                cved_impact = impact_all[cve_id] if cve_id in impact_all else []
            
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
            if vul_type == PRIV_ROOT:
                pred.append("root")
            elif vul_type == PRIV_USER:
                pred.append("user")
            else:
                pred.append("cia")
            if all:
                test.append("root")
                if vul_type != PRIV_ROOT:
                    all_false_entry += 1
                
            elif user:
                test.append("user")
                if vul_type != PRIV_USER:
                    user_false_entry += 1
            else:
                test.append("cia")
                test_cia += 1
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

def plot_confusion_matrix(confusion_matrix):
    proportion = []
    length = len(confusion_matrix)
    print(length)
    for i in confusion_matrix:
        for j in i:
            temp = j / (np.sum(i))
            proportion.append(temp)
    # print(np.sum(confusion_matrix[0]))
    # print(proportion)
    pshow = []
    for i in proportion:
        pt = "%.2f%%" % (i * 100)
        pshow.append(pt)
    proportion = np.array(proportion).reshape(length, length)  # reshape(列的长度，行的长度)
    pshow = np.array(pshow).reshape(length, length)

    # print(pshow)
    config = {
        "font.family": 'Times New Roman',  # 设置字体类型
    }
    rcParams.update(config)
    plt.figure(figsize=(6, 5), dpi=1000)

    plt.imshow(proportion, interpolation='nearest', cmap=plt.cm.Blues)  # 按照像素显示出矩阵
    # (改变颜色：'Greys', 'Purples', 'Blues', 'Greens', 'Oranges', 'Reds','YlOrBr', 'YlOrRd',
    # 'OrRd', 'PuRd', 'RdPu', 'BuPu','GnBu', 'PuBu', 'YlGnBu', 'PuBuGn', 'BuGn', 'YlGn')
    # plt.title('confusion_matrix')
    plt.colorbar()
    tick_marks = np.arange(3)
    classes = ["root", "user", "other"]
    tick_size = 12
    number_size = 10
    plt.xticks(tick_marks, classes, fontsize=tick_size)
    plt.yticks(tick_marks, classes, fontsize=tick_size)
    iters = np.reshape([[[i, j] for j in range(length)] for i in range(length)], (confusion_matrix.size, 2))
    for i, j in iters:
        if (i == j):
            plt.text(j, i - 0.12, format(confusion_matrix[i, j]), va='center', ha='center', fontsize=number_size, color='white',
                    weight=5)  # 显示对应的数字
            plt.text(j, i + 0.12, pshow[i, j], va='center', ha='center', fontsize=number_size, color='white')
        else:
            plt.text(j, i - 0.12, format(confusion_matrix[i, j]), va='center', ha='center', fontsize=number_size)  # 显示对应的数字
            plt.text(j, i + 0.12, pshow[i, j], va='center', ha='center', fontsize=number_size)

    plt.ylabel('True', fontsize=16)
    plt.xlabel('Predict', fontsize=16)
    plt.tight_layout()
    plt.savefig('myData/thesis/graduation/analyze/confusion_matrix.pdf')
    # plt.show()

if __name__ == "__main__":
    # precision_test(CVE_PATH)
    # mat = confusion_matrix(test, pred)
    # print(mat)
    mat = [[ 2891, 0, 212 ],
           [ 2, 1619, 74 ],
           [ 13, 21, 465]]
    plot_confusion_matrix(np.array(mat))

    