import os, sys
from tqdm import tqdm
import pandas as pd
import numpy as np
from service.GDBSaver import *
from utils.NLP import *

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
            
    
