import json, os, re
import pandas as pd
import matplotlib.pyplot as plt

SKIP_FILES = ['CVE-Modified.json', 'CVE-Recent.json', 'product.csv', 'cve.json', 'CVE-2023.json']
YEAR_REG = re.compile(r'CVE-(\d+).json')
SAVE_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.csv"
FIG_PATH = "myData/thesis/graduation/analyze/false_privilege_entries.png"


def plot_graph():
    df = pd.read_csv(SAVE_PATH)
    width = 0.4
    plt.rcParams['font.sans-serif'] = ['SimHei']
    # plt.rc('font', family='Times New Roman')

    year = df['year'].tolist()
    x_year = year.copy()
    total = df['total'].tolist()
    false = df['false'].tolist()
    plt.figure(figsize=(9, 3.2))
    for i in range(len(year)):
        year[i] -= width / 2
    plt.bar(year, total, width=width, label='CVE总数', color='white', alpha=1, edgecolor='k')
    for i in range(len(year)):
        year[i] += width
    plt.bar(year, false, width=width, label='错误描述的CVE数量', color='k', alpha=0.5, edgecolor='k')
    plt.legend()
    plt.xticks(x_year, rotation=300)
    plt.savefig(FIG_PATH, dpi=1000, bbox_inches='tight')
    # plt.show()

def count_false_privilege_entries(path):
    df = pd.DataFrame(columns=["year", "total", "false"])
    for file in os.listdir(path):
        if file in SKIP_FILES:
            continue
        file = os.path.join(path, file)
        df.loc[len(df.index)] = read_json(file)
    df.sort_values(by="year", inplace=True)
    df.to_csv(SAVE_PATH, index=False)

def read_json(path) -> list[int, int]:
    year = int(YEAR_REG.findall(path)[0])
    with open(path, 'r') as f:
        data = json.load(f)
    cve_items = data['CVE_Items']
    total_entry, false_entry = 0, 0
    for entry in cve_items:
        cve = entry['cve']
        impact = entry['impact']
        if "baseMetricV2" not in impact:
            continue

        cvss_v2 = impact['baseMetricV2']
        all = cvss_v2['obtainAllPrivilege']
        user = cvss_v2['obtainUserPrivilege']
        other = cvss_v2['obtainOtherPrivilege']
        gain_privileges = user + other + all
        des = cve['description']['description_data'][0]['value']
        
        if is_code_exec(des) or is_gain_privileges(des):
            total_entry += 1
            if not gain_privileges:
                false_entry += 1
    return [year, total_entry, false_entry]
        
def is_code_exec(text) -> bool:
    if "execution" in text.lower() or "execute" in text.lower():
        return True
    return False

def is_gain_privileges(text) -> bool:
    if "privilege" in text.lower():
        return True
    return False


if __name__ == "__main__":
    plot_graph()
    # count_false_privilege_entries("data/base/cve")
    