import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

import pandas as pd
from text_similarity import TextSimilarity
from service import gdb

def test_wsbert():
    ts = TextSimilarity()
    res = gdb.sendQuery(f"match (n:Vulnerability)-[]-(w:Weakness)-[]-(p:Technique) where n.id='CVE-2018-1000861' return p.id")
    df = ts.calculate_similarity("A code execution vulnerability exists in the Stapler web framework used by Jenkins 2.153 and earlier, LTS 2.138.3 and earlier in stapler/core/src/main/java/org/kohsuke/stapler/MetaClass.java that allows attackers to invoke some methods on Java objects by accessing crafted URLs that were not intended to be invoked this way.", filter=res[0])
    print(df)

def test_batch_similarity():
    ts = TextSimilarity()
    df = pd.DataFrame(columns=['query', 'id', 'name'])
    texts = [
        "ftp server", "web server", "mail merver", "scada monitor", "workstation", "database server",
        "WIFI module", "Imagery Module", "NMEA GPS", "FCS Radio Module", "Pressure sensor"
    ]
    for text in texts:
        tmp_df = ts.calculate_similarity(text)
        for i in range(len(tmp_df)):
            df.loc[len(df.index)] = [text, tmp_df.iloc[i]['id'], tmp_df.iloc[i]['name']]
    df.to_csv("myData/thesis/graduation/modeling/query.csv", index=False)

if __name__ == '__main__':
    test_wsbert()