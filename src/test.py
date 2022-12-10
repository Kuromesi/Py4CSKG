import spacy
from utils.NLP import NLP
import numpy as np
from utils.PathFinder import *
from utils.CVEExtractor import *
from utils.utils import *

spacy.prefer_gpu()

def cosine_distance(x, y):
    return np.dot(x, y.T) / (np.linalg.norm(x) * np.linalg.norm(y))

# nlp = spacy.load('./data/v3/output/model-best')
# txt = "An Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting') weakness in J-web of Juniper Networks Junos OS leads to buffer overflows, segment faults, or other impacts, which allows an attacker to modify the integrity of the device and exfiltration information from the device without authentication. The weakness can be exploited to facilitate cross-site scripting (XSS), cookie manipulation (modifying session cookies, stealing cookies) and more. This weakness can also be exploited by directing a user to a seemingly legitimate link from the affected site. The attacker requires no special access or permissions to the device to carry out such attacks. This issue affects: Juniper Networks Junos OS: 18.1 versions prior to 18.1R3-S11; 18.2 versions prior to 18.2R3-S5; 18.3 versions prior to 18.3R2-S4, 18.3R3-S3; 18.4 versions prior to 18.4R2-S5, 18.4R3-S3; 19.1 versions prior to 19.1R2-S2, 19.1R3-S2; 19.2 versions prior to 19.2R1-S5, 19.2R2; 19.3 versions prior to 19.3R3; 19.4 versions prior to 19.4R1-S3, 19.4R2, 19.4R3; 20.1 versions prior to 20.1R1-S2, 20.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 18.1R1."


# tmp = nlp(txt)
# for ent in tmp.ents:
#     print(ent.text, ent.label_)


# nlp = spacy.load('en_core_web_lg')
# text = nlp("this is a test")
# t1 = nlp.vocab['integer'].vector + nlp.vocab['truncation'].vector + nlp.vocab['test'].vector + nlp.vocab['cat'].vector
# t2 = nlp.vocab['root'].vector + nlp.vocab['privilege'].vector + nlp.vocab['escalation'].vector
# cat = nlp.vocab['check']
# dog = nlp.vocab['validate']
# sim = dog.similarity(cat)
# t = cat
# t = np.dot(t, t.T)
# dis = cosine_distance(t1, t2)
# c = np.linalg.norm(cat)
# t.sum()

# for token in text:
#     print (token.vector)

# with open("./data/train.txt", 'r') as f:
#         text = f.read()
# sentencizer = spacy.load('en_core_web_sm')
# text = sentencizer(text)
# text = list(text.sents)
# model = Word2Vec(text, vector_size=150, window=3, min_count=1)
# print(list(model.wv.key_to_index))
# print(model.wv[' name'])
# print(model.wv['overflow'])




# nlp = NLP()
# nodes = nlp.node_extractor()

# nlp = NLP()
# nlp.cluster()

# pf = PathFinder()
# pf.find_weakness()
# pf.summary(if_nlp=False)

# extract('data/attack/enterprise.xml')

# pf = TechniquePathFinder()
# pf.find()
# pf.summary()

# pf = WeaknessPathFinder()
# pf.find()
# pf.summary()

# pandsConvert("myData/attack2cve", "Att&ckToCveMappings.csv")
# preProcess("myData/attack2cve", "cve.train")
# label2id("myData/attack2cve", "classification.proc")
# preProcess("myData/CVE2Technique", "classification.txt")
# label2id("myData/CVE2Technique", "classification.proc")
label2id("myData/CVE2CWE", "classification.txt")

# doNlp('myData/CVE2Technique', 'classification.train')