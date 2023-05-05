import os, sys
from tqdm import tqdm
import pandas as pd
import numpy as np
from service.GDBSaver import *
from utils.NLP import *
import json
from NER.predict import *
from tqdm import tqdm, trange

def id2label(rootPath, subPath):
    path = os.path.join(rootPath, 'classification.labels')
    with open(path, 'r') as f:
        labels = f.readlines()
    
    path = os.path.join(rootPath, subPath)
    with open(path, 'r') as f:
        lines = f.readlines()
    text = []
    for line in lines:
        line = line.split(' , ')
        la = line[0].split('|')
        txt = ""
        for l in la:
            txt += labels[int(l)].strip() + "|"
        txt = txt.strip('|')
        txt = txt.strip()
        txt += " , " + line[1]
        txt = txt.strip()
        text.append(txt)
    
    path = os.path.join(rootPath, 'original.txt')
    with open(path, 'w') as f:
        for line in text:
            f.write(line + "\n")

def label2id_base(rootPath, subPath):
    '''
    Only train base abstaction level data.
    '''
    df = pd.read_csv('./myData/thesis/cwe_count_base.csv')
    df = df[df['count'].astype(int) > 100]['name']
    label = df.tolist()
    with open('./myData/thesis/base_dict.json', 'r') as f:
        cwe_dict = json.load(f)

    path = os.path.join(rootPath, subPath)
    with open(path, 'r') as f:
        print("------Reading files------")
        lines = f.readlines()
    text = []
    for line in lines:
        t = line.split(' , ')
        la = t[0].split('|')
        if len(la) > 1:
            continue
        des = t[1]
        txt = ""
        if la[0] not in cwe_dict:
            continue
        id = cwe_dict[la[0]]
        if id not in label:
            continue    
        txt += str(label.index(id))
        txt += " , " + des
        txt = txt.strip()
        text.append(txt)
    path = os.path.join(rootPath, 'classification.train')
    with open(path, 'w') as f:
        print("------Writing files------")
        for line in text:
            f.write(line + "\n")
    path = os.path.join(rootPath, 'classification_base.labels')
    with open(path, 'w') as f:
        print("------Writing labels------")
        for la in label:
            f.write(la + "\n")

def label2id(rootPath, subPath):
    path = os.path.join(rootPath, subPath)
    label = set()
    with open(path, 'r') as f:
        print("------Reading files------")
        texts = f.readlines()
    
    for line in texts:
        label.update(tuple(line.split(' , ')[0].split('|')))
    label = list(label)
    text = []
    for line in texts:
        t = line.split(' , ')
        la = t[0].split('|')
        des = t[1]
        txt = ""
        for l in la:
            txt += str(label.index(l)) + "|"
        txt = txt.strip('|')
        txt += " , " + des
        txt = txt.strip()
        text.append(txt)
    path = os.path.join(rootPath, 'classification.train')
    with open(path, 'w') as f:
        print("------Writing files------")
        for line in text:
            f.write(line + "\n")
    path = os.path.join(rootPath, 'classification.labels')
    with open(path, 'w') as f:
        print("------Writing labels------")
        for la in label:
            f.write(la + "\n")

def preProcess(rootPath, subPath):
    path = os.path.join(rootPath, subPath)
    with open(path, 'r') as f:
        print("------Processing file------")
        text = []
        for line in f:
            line = line.split(' , ')
            labels = line[0].split('|')
            txt = ""
            for la in labels:
                la = la.split('.')[0]
                txt += la + "|"
            txt = txt.strip('|')
            txt += " , " + line[1]
            txt = txt.strip()
            text.append(txt)
    path = os.path.join(rootPath, "classification.proc")
    with open(path, 'w') as f:
        print("------Writing files------")
        for line in text:
            f.write(line + "\n")

def pandsConvert(rootPath, subPath):
    print('------Converting csv------')
    path = os.path.join(rootPath, subPath)
    gdb = GDBSaver()
    df = pd.read_csv(path)
    text = []
    keys = ['Uncategorized', 'Exploitation Technique', 'Secondary Impact', 'Primary Impact']

    for idx, row in df.iterrows():
        print(row['CVE ID'])
        txt = ""
        techniques = []
        for key in keys:
            if not pd.isnull(row[key]):
                techniques.extend(row[key].split('; '))
        if len(techniques) == 0:
            continue
        for te in techniques:
            txt += te.strip() + "|"
        txt = txt.strip("|")
        txt += " , "
        query = "MATCH (n) WHERE n.id='%s' RETURN n"%row['CVE ID']
        try:
            node = gdb.sendQuery(query)[0]
            des = node[0].get('des')
            des = des.replace('\n', "")
            txt += des
            text.append(txt)
        except:
            print("current node not recorded")
    path = os.path.join(rootPath, "cve.train")
    with open(path, 'w') as f:
        print("------Writing files------")
        for line in text:
            f.write(line + "\n")

def doNlp(rootPath, subPath):
    path = os.path.join(rootPath, subPath)
    text = []
    nlp = NLP()
    with open(path, 'r') as f:
        ftqdm = tqdm(f)
        for line in ftqdm:
            line = line.split(' , ')
            label = line[0]
            des = nlp.proc(line[1])
            if des:
                line = label + " , " + des
                text.append(line)
    path = os.path.join(rootPath, "classfication.nlp")
    with open(path, 'w') as f:
        for line in text:
            f.write(line + "\n")
    
def remove_stopwords(rootPath, subPath):
    path = os.path.join(rootPath, subPath)
    text = []
    nlp = NLP()
    with open(path, 'r') as f:
        ftqdm = tqdm(f)
        for line in ftqdm:
            line = line.split(' , ')
            label = line[0]
            des = nlp.remove_stopwords(line[1])
            if des:
                line = label + " , " + des
                text.append(line.strip())
    path = os.path.join(rootPath, "classfication.nostopwords")
    with open(path, 'w') as f:
        for line in text:
            f.write(line + "\n")
            
def toML(path, save_path):
    '''
    Convert current tain file to Machine Learning format
    '''
    
    text = []
    i = 0
    j = 0
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            i += 1
            line = line.split(' , ')
            if len(line[0].split('|')) == 1:
                text.append([line[0], line[1].strip()])
                j += 1


    df = pd.DataFrame(text, columns=['label', 'text'])
    df.to_csv(save_path, index=False)

    print("Number of full dataset: %d"%i)
    print("Number of used dataset: %d"%j)

def summarize_cve2cwe():
    '''
    Count the number of cve linked/unlinked with cwe per year.
    '''
    gdb = GDBSaver()
    year = range(1999, 2022)
    df = pd.DataFrame(columns=['year', 'total', 'linked'])
    for y in year:
        query = "MATCH (n:Vulnerability) WHERE n.id CONTAINS \"CVE-%d\" RETURN COUNT(n)"%y
        res = gdb.sendQuery(query)
        cve_total = res[0][0]
        cve_linked = set()
        query = "MATCH path=(n:Vulnerability)-[]-(b:Weakness) WHERE n.id CONTAINS \"CVE-%d\" RETURN path"%y
        # query = "MATCH (n:Vulnerability) WHERE n.id CONTAINS \"CVE-%d\" RETURN n"%y
        path = gdb.sendQuery(query)
        for p in path:
            id = p[0].start_node.get('id')
            # id = node[0].get('id')
            print(id)
            # query = "MATCH path=(n:Vulnerability)-[]-(b:Weakness) WHERE n.id=\"%s\" RETURN path"%id
            # path = gdb.sendQuery(query)
            cve_linked.add(id)
        df.loc[len(df.index)] = [y, cve_total, len(cve_linked)]
    df.to_csv('./myData/thesis/cve2cwe.csv', index=False)

def find_weakness():
    '''
    Count linked CVE records per CWE record.
    '''
    gdb = GDBSaver()
    print("------Finding CWE -> CVE------")
    query = "MATCH (n:Weakness) RETURN n"
    nodes = gdb.sendQuery(query)
    df = pd.DataFrame(columns=['CWE-ID', 'COUNT'])
    for node in nodes:
        print(node[0].get('id'))
        query = "MATCH (n:Weakness) WHERE n.id=\"%s\" MATCH path=(n)-[]-(b:Vulnerability) RETURN count(path)"%node[0].get('id')
        count = gdb.sendQuery(query)[0][0]
        df.loc[len(df.index)] = [node[0].get('id'), count]
    df = df.sort_values(by='COUNT', ascending=False)
    df.to_csv('./myData/thesis/cwe_count.csv', index=False)

def count_words():
    df = pd.read_csv("./myData/learning/CVE2CAPEC/result_weight.csv")
    cves = df['cve_des'].tolist()
    with open('./myData/learning/CVE2CAPEC/temp.txt', 'w') as f:
        f.writelines(cves)
        
class GetTrainData():
    """Collect CVE description for NER 
    """    
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
        