import pandas as pd
import json
from pyvis.network import Network


df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
t = df[0: 10]

net = Network()
for index, d in t.iterrows():
    net.add_node(d['id'], des=d['description'], name=d['name'], title=d['id'])
net.show('demo1.html')