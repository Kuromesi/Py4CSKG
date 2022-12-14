from re import L
import re
import spacy
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from sklearn.cluster import DBSCAN
from sklearn import datasets

class NLP:

    def __init__(self):
        # self.nlp = spacy.load('./data/v1\output\model-best')
        self.gdb = NLPGDBSaver()
        self.rdb = RDBSaver()
        spacy.prefer_gpu()
        # Self trained model
        self.nlp = spacy.load('./data/v3/output/model-best')
        # Official model
        self.nlpo = spacy.load('en_core_web_trf')

    def _punc_remove(self, query):
        query = query.replace("'", "")
        query = query.replace("-", " ")
        query = query.replace("(", " ")
        query = query.replace(")", " ")
        query = query.strip()
        query = query.replace("\\", "")
        return query
    
    def node_extractor(self):
        '''
        Extract consequences and vulnerabilities from CVE descriptions.
        '''
        query = "MATCH (n:Vulnerability) RETURN n"
        nodes = self.gdb.sendQuery(query)
        for node in nodes:
            des = node[0].get('des')
            des = des.split("CVSS 3.1 Base Score")[0]
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
                node_des = self._punc_remove(node_des)
                if (len(node_des) <= 2 or node_des == " "):
                    continue
                if not self.rdb.checkNode(node_des):
                    node_dict['des'] = node_des
                    node_dict['type'] = ent.label_
                    node_dict['ori'] = ent.text
                                        
                    dest_id = self.gdb.addNode(node_dict)
                    self.rdb.saveNodeId(node_des, dest_id)
                else:
                    dest_id = int(self.rdb.getNode(node_des))    
                rel = 'has_' + ent.label_
                if not self.gdb.checkRelation(src_id, dest_id, rel):
                    self.gdb.addRelation(src_id, dest_id, rel)
                print(tmp)
        return nodes

    def test(self):
        query = "MATCH (n:Vulnerability) WHERE n.id=\"CVE-2021-0215\" RETURN n"
        node = self.gdb.sendQuery(query)
        des = node[0][0].get('des')
        text = self.nlp(des)
        for ent in text.ents:
            print(ent.text, ent.label_)

    def proc(self, text):
        text = self.nlp(text)
        line = ""
        for ent in text.ents:
            if ent.label_ == "vul":
                line += ent.text + " "
        return line.strip()

class NLPGDBSaver(GDBSaver):
    
    def __init__(self):
        super().__init__()
        
    def _exec1(self, tx, kvpairs):
        query = "CREATE(n:%s) "%kvpairs['type']
        result = tx.run(query +
                        "SET n.type = $type "
                        "SET n.des = $des "
                        "SET n.ori = $ori "
                        "RETURN id(n)", type=kvpairs['type'], des=kvpairs['des'], ori=kvpairs['ori'])
        try:
            return result.single()[0]
        except:
            return 0
        
    def addNode(self, kvpairs):
        with self.driver.session() as session:
            nodeid = session.write_transaction(self._exec1, kvpairs)
        return nodeid

if __name__=="__main__":
    nlp = NLP()
    