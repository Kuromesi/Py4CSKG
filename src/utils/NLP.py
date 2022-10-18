from re import L
import re
import spacy
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver

class NLP:

    def __init__(self):
        # self.nlp = spacy.load('./data/v1\output\model-best')
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
        spacy.prefer_gpu()
        # Self trained model
        self.nlp = spacy.load('./data/v1\output\model-best')
        # Official model
        self.nlpo = spacy.load('en_core_web_trf')

    def process(self, txt):
        return self.nlp(txt)

    def node_extractor(self):
        query = "MATCH (n:Vulnerability) RETURN n"
        nodes = self.gdb.sendQuery(query)
        for node in nodes:
            des = node[0].get('des')
            src_id = node[0].id
            txt = self.nlp(des)
            for ent in txt.ents:
                node_dict = {}
                ent_text = self.nlpo(ent.text)
                tmp = ""
                for token in ent_text:
                    if token.lemma_.lower() not in self.nlpo.Defaults.stop_words:
                        tmp += token.lemma_.lower() + " "
                tmp = tmp.strip()
                node_des = tmp
                if not self.rdb.checkNode(node_des):
                    node_dict['des'] = node_des
                    node_dict['prop'] = ent.label_
                    node_dict['type'] = ent.label_
                    dest_id = self.gdb.addNode(node_dict)
                    self.rdb.saveNodeId(node_des, dest_id)
                else:
                    dest_id = int(self.rdb.getNode(node_des))    
                rel = 'has_' + ent.label_
                if not self.gdb.checkRelation(src_id, dest_id, rel):
                    self.gdb.addRelation(src_id, dest_id, rel)
                print(tmp)
        return nodes
    
    def cluster(self):
        query = "MATCH (n:cons) RETURN n"
        nodes = self.gdb.sendQuery(query)
        self.rdb.select_database(4)
        for node in nodes:
            des = node[0].get('des')
            id = node[0].id
            if (self.rdb.checkSet('visited', id)):
                continue
            self.rdb.addSet('visited', id)
            query = "MATCH (n:cons) WHERE "
            words = des.split(" ")
            if (len(words) < 2):
                continue
            for word in words:
                query += "n.des CONTAINS \"%s\" AND "%word
            query = query.strip("AND ")
            query += " RETURN n"
            related_nodes = self.gdb.sendQuery(query)
            if len(related_nodes) == 1:
                continue
            for related_node in related_nodes:
                related_id = related_node[0].id
                if (self.rdb.checkNode(related_id)):
                    for temp in self.rdb.getNode(related_id):
                        self.rdb.appendList(id, temp)
                    self.rdb.removeKey(related_id)
                self.rdb.addSet('visited', related_id)
                self.rdb.appendList(id, related_id)
                
            
    
    def test(self):
        query = "MATCH (n:Vulnerability) WHERE n.id=\"CVE-2021-0215\" RETURN n"
        node = self.gdb.sendQuery(query)
        des = node[0][0].get('des')
        text = self.nlp(des)
        for ent in text.ents:
            print(ent.text, ent.label_)

if __name__=="__main__":
    nlp = NLP()
    