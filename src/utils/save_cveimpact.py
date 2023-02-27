import pandas as pd
from service.GDBSaver import *
from tqdm import tqdm 

def save_cveimpact():
    gs = GDBSaver()
    query = "MATCH (n:Vulnerability) RETURN n"
    nodes = gs.sendQuery(query)
    df = pd.DataFrame(columns=['CVE-ID', 'Impact'])
    nodes = tqdm(nodes)
    for node in nodes:
        node = node[0]
        nodes.set_postfix(id=node['id'])
        df.loc[len(df.index)] = [node['id'], node['impact']]
    df.to_csv('data/CVEImpact.csv', index=False)