


import os, re, sys
import pandas as pd

BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.join(BASE_DIR))
from service.GDBSaver import GDBSaver

CVE = re.compile(r".*(CVE-[0-9]{4}-[0-9]{4,}).*")

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
    cves = [CVE.findall(p)[0] for p in paths if CVE.match(p)]
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


if __name__ == "__main__":
    get_paths("/home/kuromesi/MyCOde/github.com/vulhub")