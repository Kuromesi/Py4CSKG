from service.GDBSaver import GDBSaver
import pandas as pd
import json

THRESHOLD = 100
gdb = GDBSaver()
visited = set()

class CWENode():
    cve = 0

with open('./myData/thesis/cwe_count.csv') as f:
    df = pd.read_csv(f)
cwe_dict = dict(zip(df['CWE-ID'], df['COUNT']))
new_tree = {}
cwe_count = {}

def traverse(node_id:str, parent_id:str) -> int:
    if node_id in visited:
        return 0
    query = "MATCH (n:Weakness) WHERE n.id=\"%s\" MATCH (n)<-[:ChildOf]-(a) RETURN a"%node_id
    nodes = gdb.sendQuery(query)
    cve = cwe_dict[node_id]
    for node in nodes:
        id = node[0].get('id')
        cve += traverse(id, parent_id)

    visited.add(node_id)
    new_tree[node_id] = parent_id
    return cve



def traverseCWE():
    df = pd.DataFrame(columns=['name', 'count'])
    # Pillar
    query = "MATCH (n:Weakness) WHERE n.id=\"CWE-1000\" MATCH (n)-[:Has_Member]-(a) RETURN a"
    pillars = gdb.sendQuery(query)
    for pillar in pillars:
        id = pillar[0].get('id')
        print(id)
        query = "MATCH (n:Weakness) WHERE n.id=\"%s\" MATCH (n)<-[:ChildOf]-(a) RETURN a"%id
        bases = gdb.sendQuery(query)
        for base in bases:
            base_id = base[0].get('id')
            print(base_id)
            cwe_count[base_id] = traverse(base_id, base_id)
            df.loc[len(df.index)] = [base_id, cwe_count[base_id]]
    df = df.sort_values(by='count', ascending=False)
    df.to_csv('./myData/thesis/cwe_count_base.csv', index=False)
    with open('./myData/thesis/base_dict.json', 'w') as f:
        json.dump(new_tree, f)
        


