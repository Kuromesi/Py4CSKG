import spacy
# from gensim.models import Word2Vec
from misc.NLP import NLP
from utils.Cluster import Cluster
import numpy as np

# spacy.prefer_gpu()

# nlp = NLP()
# nlp.rdb.r.select(5)
# nlp.rdb.r.flushdb()
# nodes = nlp.node_extractor()

# nlp = NLP()
# nlp.findCluster()

# nlp = NLP()
# nlp.createCluster()

cls = Cluster()
cls.findCluster()
cls.createCluster()