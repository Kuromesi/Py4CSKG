import pandas as pd
import json
from pyvis.network import Network

def create_cve2net(df, cve, n=10):
    df = df[0: n]
    net = Network()
    size = 30
    net.add_node("Query", des=cve, title=cve, color='#ff0066', size=size+10)
    count = 0
    for index, row in df.iterrows():
        this_size = size - size / n * count
        net.add_node(row['id'], description=row['description'], name=row['name'], title=row['name'], similarity=row['similarity'], size=this_size)
        net.add_edge("Query", row['id'])
        count += 1
    return {'nodes': net.nodes, 'edges': net.edges}

if __name__ == '__main__':
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    create_cve2net(df, "123")