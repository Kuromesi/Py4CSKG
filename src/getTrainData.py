"""
Collect CVE description for NER 
"""
import pandas as pd
import pandas as pd
import numpy as np
from tqdm import tqdm, trange
from NER.predict import *
from service.GDBSaver import *

class GetTrainData():
    def __init__(self) -> None:
        self.ner = NERPredict()
        self.df = pd.DataFrame(columns=['id', 'des', 'NER'])
        self.gs = GDBSaver()

    def find(self):
        query = "MATCH (n:Vulnerability) RETURN n ORDER BY rand() LIMIT 200"
        results = self.gs.sendQuery(query)
        results = tqdm(results)
        results.set_description("Processing CVE...")
        for res in results:
            res = res[0]
            id = res['id']
            results.set_postfix(id=id)
            des = res['description']
            ner_res = self.ner.predict(des)
            self.df.loc[len(self.df.index)] = [id, des, ner_res['res']]
            
        self.df.to_csv('./myData/learning/CVE2CAPEC/NER.csv', index=False)
        
        
    
if __name__ == '__main__':
    gtd = GetTrainData()
    gtd.find()
    