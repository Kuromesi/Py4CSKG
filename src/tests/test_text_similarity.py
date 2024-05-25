import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

import pandas as pd
from text_similarity import TextSimilarity
# from service import gdb

def test_wsbert_capec():
    def filter(x):
        return "CAPEC" in x
    func = lambda x: "CAPEC" in x
    ts = TextSimilarity("myData/thesis/graduation/modeling/tmp.csv", "data/deep/embeddings/query.npy", "./data/deep/trained_models/BERTBiLSTMCRF79")
    df = ts.calculate_similarity("The Net Direct client for Linux before 6.0.5 in Nortel Application Switch 2424, VPN 3050 and 3070, and SSL VPN Module 1000 extracts and executes files with insecure permissions, which allows local users to exploit a race condition to replace a world-writable file in /tmp/NetClient and cause another user to execute arbitrary code when attempting to execute this client, as demonstrated by replacing /tmp/NetClient/client.", func)
    print(df)

def test_wsbert():
    ts = TextSimilarity()
    # res = gdb.sendQuery(f"match (n:Vulnerability)-[]-(w:Weakness)-[]-(p:Technique) where n.id='CVE-2018-1000861' return p.id")
    df = ts.calculate_similarity("ftp server")
    print(df)

def test_batch_similarity():
    ts = TextSimilarity()
    df = pd.DataFrame(columns=['query', 'id', 'name'])
    texts = [
        "ftp server", "web server", "mail merver", "scada monitor", "workstation", "database server",
        "WIFI module", "Imagery Module", "NMEA GPS", "FCS Radio Module", "Pressure sensor"
    ]
    def filter(x):
        return x == "CAPEC-120"
    for text in texts:
        tmp_df = ts.calculate_similarity(text)
        for i in range(len(tmp_df)):
            df.loc[len(df.index)] = [text, tmp_df.iloc[i]['id'], tmp_df.iloc[i]['name']]
    df.to_csv("myData/thesis/graduation/modeling/query.csv", index=False)

if __name__ == '__main__':
    test_wsbert_capec()