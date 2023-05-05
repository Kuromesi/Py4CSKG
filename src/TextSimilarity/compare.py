from CVE2CAPEC import *
import pandas as pd
from tqdm import tqdm

class Compare:
    def __init__(self) -> None:
        self.df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
        self.ts = TextSimilarity(self.df)
        self.ts.init_ner()
        self.ts.init_weight(self.df)
        
        self.tis = TFIDFSimilarity()
    
    def diff(self, df1, df2, rows=5):
        set1 = set()
        set2 = set()
        same_df = pd.merge(df1[0: rows], df2[0: rows], on = ['id'], how = 'inner')
        return len(same_df.index)
    
    def compare(self, cves):
        rows = 5
        rate = 0.6
        count = 0
        sum_ = 0
        cves = tqdm(cves)
        cves.set_description("Calculating similarities...")
        for cve in cves:
            ts_res = self.ts.calculate_similarity(cve)
            tis_res = self.tis.calculate_similarity(cve)
            same = self.diff(ts_res, tis_res, rows)
            sum_ += same
            if same >= rows * rate:
                count += 1
        print(sum_)
        return count

def loadcves(path):
    df = pd.read_csv(path)
    cves = df['des'].to_list()
    return cves

def loadcves1():
    capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    cve_df = pd.read_csv('./myData/learning/CVE2CAPEC/cve_nlp.csv', index_col=0)
    
    cves = []
    true = []
    true_des = []
    for i in range(len(capec_df.index)):
        cur = literal_eval(capec_df['cve'].loc[i])
        true += [capec_df['id'].loc[i]] * len(cur)
        true_des += [capec_df['name'].loc[i]] * len(cur)
        cves += cur
    query = cve_df.loc[cves]['des'].to_list()
    return query

if __name__ == '__main__':
    compare = Compare()
    # cves = ["eQ-3 Homematic CCU2 2.47.20 and CCU3 3.47.18 with the E-Mail AddOn through 1.6.8.c installed allow Remote Code Execution by unauthenticated attackers with access to the web interface via the save.cgi script for payload upload and the testtcl.cgi script for its execution."]
    # cves = loadcves('data/CTINER/NER.csv')
    cves = loadcves1()
    count = compare.compare(cves)
    print(count)