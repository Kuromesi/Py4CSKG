import spacy
from utils.NLP import NLP
import numpy as np
from utils.PathFinder import *
from utils.CVEExtractor import *
from utils.utils import *
from models.trainer import Trainer

# spacy.prefer_gpu()

def cosine_distance(x, y):
    return np.dot(x, y.T) / (np.linalg.norm(x) * np.linalg.norm(y))

# nlp = spacy.load('./myData/ATTACKLabel/output/model-best')
# txt = "For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files), misplaced certificate files (i.e. [MASK]), or directly from the Windows certificate store via various crypto APIs."


# tmp = nlp(txt)
# for ent in tmp.ents:
#     print(ent.text, ent.label_)
# trainer = Trainer()

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
# label2id("myData/CVE2CWE", "classification.txt")
# doNlp('myData/CVE2CWE', 'classification.train')

# doNlp('myData/CVE2Technique', 'classification.train')
# toML('myData/learning/CVE2CWE/cve.train', 'myData/learning/CVE2CWE/cve.csv')
res = pd.read_csv('./myData/learning/result.csv')
res.loc[len(res.index)] = ['1', '2', '3', '4', '5']
print(1)