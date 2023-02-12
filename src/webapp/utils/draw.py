import pandas as pd
import json
from pyvis.network import Network

def create_cve2net(df, cve, n=10):
    df = df[0: n]
    net = Network()
    net.add_node("Query", des=cve, title=cve, color='#ff0066')
    for index, row in df.iterrows():
        net.add_node(row['id'], des=row['description'], name=row['name'], title=row['name'])
        net.add_edge("Query", row['id'])
    return {'nodes': net.nodes, 'edges': net.edges}

if __name__ == '__main__':
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    create_cve2net(df, "123")