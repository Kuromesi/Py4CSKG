import spacy
from gensim.models import Word2Vec
from utils.NLP import NLP
import numpy as np

spacy.prefer_gpu()

def cosine_distance(x, y):
    return np.dot(x, y.T) / (np.linalg.norm(x) * np.linalg.norm(y))

# nlp = spacy.load('./data/v1\output\model-best')
# txt = "In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with the ability to access functionality not properly constrained by ACLs can obtain sensitive information and possibly compromise the entire application. Such an attacker can access resources that must be available only to users at a higher privilege level, can access management sections of the application, or can run queries for data that they otherwise not supposed to."
# tmp = nlp(txt)
# for ent in tmp.ents:
#         print(ent.text, ent.label_)


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

nlp = NLP()
nlp.cluster()

