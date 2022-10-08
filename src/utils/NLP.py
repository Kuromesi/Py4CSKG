import spacy
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver

class NLP:

    def __init__(self):
        self.nlp = spacy.load('./data/v1\output\model-best')
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
        self.nlp = spacy.load('./data/v1\output\model-best')

    def process(self, txt):
        return self.nlp(txt)

    def node_extractor(self):
        query = "MATCH (n:Vulnerability) RETURN n"
        nodes = self.gdb.sendQuery(query)
