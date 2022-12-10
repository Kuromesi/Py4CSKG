from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
import spacy

class PathFinder():
    def __init__(self):
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
        
    def __find_tactic(self):
        print("------Finding Tactic -> Technique------")
        query = "MATCH path=(a:Tactic)-[]-(b:Technique) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            self.rdb.addSet(end_id, start_id)
        
    def __find_technique(self):
        print("------Finding Technique -> CAPEC------")
        query = "MATCH path=(a:Technique)-[]-(b:Pattern) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
        
    def __find_pattern(self):
        print("------Finding CAPEC -> CWE------")
        query = "MATCH path=(a:Pattern)-[]-(b:Weakness) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            self.rdb.select_database(6)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
            self.rdb.select_database(5)

    def __find_weakness(self):
        print("------Finding CWE -> CVE------")
        query = "MATCH path=(a:Weakness)-[]-(b:Vulnerability) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            tactics = self.rdb.r.smembers(start_id)
            self.rdb.select_database(6)
            for tactic in tactics:
                self.rdb.addSet(end_id, tactic)
            self.rdb.select_database(5)
            
    def summary(self, if_nlp=False):
        print("------Generating Summary------")
        self.rdb.select_database(6) #change this to 6
        keys = self.rdb.r.keys()
        if if_nlp:
            nlp = spacy.load('data/v3/output/model-best')
            # nlpo = spacy.load('en_core_web_trf')
        with open ('data/tactics_capec.txt', 'r') as f:
            tacs = f.read()
            tacs = tacs.split('\n')
        with open('data/classification4.txt', 'w') as f:
            i = 0
            for key in keys:
                i += 1
                key = key.decode('utf-8')
                print("Proccessing %i/%i --- %s"%(i, len(keys), key))
                line = ""
                tactics = self.rdb.r.smembers(key)
                for tac in tactics:
                    line += str(tacs.index(tac.decode('utf-8'))) + "|"
                line = line.strip("|")
                line += " , "
                query = "MATCH (n) WHERE n.id='%s' RETURN n"%key
                node = self.gdb.sendQuery(query)[0]
                des = node[0].get('des')
                des = des.replace('\n', "")
                if if_nlp:
                    des = nlp(des)
                    if (len(des.ents) == 0):
                        continue
                    for ent in des.ents:
                        # if not ent.label_ == 'cons':
                        #     continue
                        line += ent.text + " "
                        # ent_text = nlpo(ent.text)
                        # for token in ent_text:
                            # if token.lemma_.lower() not in nlpo.Defaults.stop_words and not token.is_punct:
                                # line += token.lemma_.lower() + " "
                    line = line.strip()
                else:
                    line += des
                    line = line.strip()
                f.write(line + "\n")

    def find(self):
        self.rdb.select_database(6)
        self.rdb.r.flushdb()
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_tactic()
        self.__find_technique()
        self.__find_pattern()
        self.__find_weakness()

    def find_capec(self):
        self.rdb.select_database(6)
        self.rdb.r.flushdb()
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_tactic()
        self.__find_technique()

    def find_technique(self):
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_tactic()

    def find_weakness(self):
        self.rdb.select_database(6)
        self.rdb.r.flushdb()
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_tactic()
        self.__find_technique()
        self.__find_pattern()

class TechniquePathFinder():
    def __init__(self):
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
        
    def __find_technique(self):
        print("------Finding Technique -> CAPEC------")
        query = "MATCH path=(a:Technique)-[]-(b:Pattern) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            self.rdb.addSet(end_id, start_id)
        
    def __find_pattern(self):
        print("------Finding CAPEC -> CWE------")
        query = "MATCH path=(a:Pattern)-[]-(b:Weakness) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            techniques = self.rdb.r.smembers(start_id)
            for tech in techniques:
                self.rdb.addSet(end_id, tech)

    def __find_weakness(self):
        print("------Finding CWE -> CVE------")
        query = "MATCH path=(a:Weakness)-[]-(b:Vulnerability) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            techniques = self.rdb.r.smembers(start_id)
            self.rdb.select_database(6)
            for tech in techniques:
                self.rdb.addSet(end_id, tech)
            self.rdb.select_database(5)
            
    def summary(self):
        print("------Generating Summary------")
        self.rdb.select_database(6) #change this to 6
        keys = self.rdb.r.keys()
        with open('myData/CVE2Technique/classification.txt', 'w') as f:
            i = 0
            for key in keys:
                i += 1
                key = key.decode('utf-8')
                print("Proccessing %i/%i --- %s"%(i, len(keys), key))
                line = ""
                techniques = self.rdb.r.smembers(key)
                for tech in techniques:
                    line += tech.decode('utf-8') + "|"
                line = line.strip("|")
                line += " , "
                query = "MATCH (n) WHERE n.id='%s' RETURN n"%key
                node = self.gdb.sendQuery(query)[0]
                des = node[0].get('des')
                des = des.replace('\n', "")
                line += des
                line = line.strip()
                f.write(line + "\n")

    def find(self):
        self.rdb.select_database(6)
        self.rdb.r.flushdb()
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_technique()
        self.__find_pattern()
        self.__find_weakness()
        
class WeaknessPathFinder():
    def __init__(self):
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()

    def __find_weakness(self):
        print("------Finding CWE -> CVE------")
        query = "MATCH path=(a:Weakness)-[]-(b:Vulnerability) RETURN path"
        results = self.gdb.sendQuery(query)
        for res in results:
            start_id = res[0].start_node.get('id')
            end_id = res[0].end_node.get('id') 
            print("%s -> %s"%(start_id, end_id))
            self.rdb.addSet(end_id, start_id)
            
    def summary(self):
        print("------Generating Summary------")
        self.rdb.select_database(5)
        keys = self.rdb.r.keys()
        with open('myData/CVE2CWE/classification.txt', 'w') as f:
            i = 0
            for key in keys:
                i += 1
                key = key.decode('utf-8')
                print("Proccessing %i/%i --- %s"%(i, len(keys), key))
                line = ""
                weaknesses = self.rdb.r.smembers(key)
                for weak in weaknesses:
                    line += weak.decode('utf-8') + "|"
                line = line.strip("|")
                line += " , "
                query = "MATCH (n) WHERE n.id='%s' RETURN n"%key
                node = self.gdb.sendQuery(query)[0]
                des = node[0].get('des')
                des = des.replace('\n', "")
                line += des
                line = line.strip()
                f.write(line + "\n")

    def find(self):
        self.rdb.select_database(5)
        self.rdb.r.flushdb()
        self.__find_weakness()
