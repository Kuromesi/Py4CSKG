# from service.GDBSaver import GDBSaver
# from service.RDBSaver import RDBSaver
from bs4 import BeautifulSoup
import pandas as pd

class XmlTraverser: 
    def init(self): 
        self.ds = GDBSaver()
        self.rs = RDBSaver()
        self.root = None
    
    def write_to_file(self, src, dest, relation):
        pass

    def get_value(self, ele, tag):
        value = ""
        tag = ele.find(tag)
        if tag:
            value = tag.get_text().strip()
        return value

    def string_proc(self, string):
        string = string.replace("\n", "")
        string = string.strip()
        return string

    def traverse(self):
        pass



class CAPECTraverser(XmlTraverser):
    def __init__(self, path: str):
        self.TYPE = "Pattern"
        with open(path, 'r', encoding='utf-8') as f:
            self.soup = BeautifulSoup(f, 'xml')
        # self.ds = GDBSaver()
        # self.rs = RDBSaver()

    def traverse(self):
        df = pd.DataFrame(columns=['id', 'name', 'description'])
        # Find views
        views = self.soup.find_all("View")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type1 = view.name
                name = view["Name"]
                src = "CAPEC-" + view["ID"]
                print(src)
                objective = view.Objective.get_text().strip()
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type1,
                    "prop": self.TYPE,
                    "des": objective,
                    "url": src
                }
                df.loc[len(df.index)] = [src, name, objective] #kuro
        
                # Save node
                # srcID = self.ds.addNode(node_prop)
                
                # Find members
                members = view.Members
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            # self.rs.saveRDF(src, dest, relation)
        
        # Find categories
        categories = self.soup.find_all("Category")
        for category in categories:
            if category["Status"] != "Deprecated":
                # Find categories properties
                type = category.name
                name = category["Name"]
                src = "CAPEC-" + category["ID"]
                print(src)
                objective = category.Summary.get_text().strip()
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "url": src
                }
                df.loc[len(df.index)] = [src, name, objective] #kuro
                # Save node
                # srcID = self.ds.addNode(node_prop)
                # Find members
                members = category.Relationships
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            # self.rs.saveRDF(src, dest, relation)

        # Find attack patterns
        atkpts = self.soup.find_all("Attack_Pattern")
        for atkpt in atkpts:
            if atkpt["Status"] != "Deprecated":
                # Find attack patterns properties
                type = atkpt['Abstraction']
                name = atkpt["Name"]
                src = "CAPEC-" + atkpt["ID"]
                print(src)
                
                description = self.get_value(atkpt, "Description") 
                extended_des = self.get_value(atkpt, "Extended_Description")
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "description": description,
                    "extended_description": extended_des,
                    "url": src
                }
                df.loc[len(df.index)] = [src, name, self.get_value(atkpt, "Description")] #kuro

                # Save node
                # srcID = self.ds.addNode(node_prop)

                # Related attack patterns
                related_attack_patterns = atkpt.Related_Attack_Patterns
                if related_attack_patterns:
                    for related_attack_pattern in related_attack_patterns.children:
                        if related_attack_pattern != "\n":
                            dest = "CAPEC-" + related_attack_pattern["CAPEC_ID"]
                            relation = related_attack_pattern['Nature']
                            # self.rs.saveRDF(src, dest, relation)

                # Related Weaknesses
                related_weaknesses = atkpt.Related_Weaknesses
                if related_weaknesses:
                    for related_weakness in related_weaknesses.children:
                        if related_weakness != "\n":
                            dest = "CWE-" + related_weakness['CWE_ID']
                            relation = related_weakness.name
                            # self.rs.saveRDF(src, dest, relation)
        df.to_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv', index=False)       

class CWETraverser(XmlTraverser):
    def __init__(self, path: str):
        self.TYPE = "Weakness"
        with open(path, "r") as file:
            self.soup = BeautifulSoup(file, "xml")
    
    def traverse(self):
        srcID, destID = None, None
        
        # Find views
        views = self.soup.find_all("View")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type = view.name
                name = view["Name"]
                src = "CWE-" + view["ID"]
                objective = view.Objective.text
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "url": src
                }
                # Save node
                srcID = self.ds.addNode(node_prop)

                #Find members
                members = view.Members
                if members is not None:
                    for member in members.children:
                        dest = "CWE-" + member["CWE_ID"]
                        relation = member.name
                        self.rs.saveRDF(src, dest, relation)
                # Find categories
                categories = self.soup.find_all("Category")
                for view in categories:
                    if view["Status"] != "Deprecated":
                        # Find categories properties
                        type = view.name
                        name = view["Name"]
                        src = "CWE-" + view["ID"]
                        objective = view.Summary.text
                        node_prop = {
                            "id": src,
                            "name": name,
                            "type": type,
                            "prop": self.TYPE,
                            "des": objective,
                            "url": src
                        }
                        # Save node
                        srcID = self.ds.addNode(node_prop)
                        # Find members
                        members = view.Relationships
                        if members is not None:
                            for member in members.children:
                                dest = "CWE-" + member["CWE_ID"]
                                relation = member.name
                                self.rs.saveRDF(src, dest, relation)
                                
                # Find weaknesses
                weaknesses = self.soup.find_all("Weakness")
                for weakness in weaknesses:
                    if weakness["Status"] != "Deprecated":
                        # Find weakness properties
                        type = weakness.name
                        name = weakness["Name"]
                        src = "CWE-" + weakness["ID"]
                        objective = weakness.Description.text
                        node_prop = {
                            "id": src,
                            "name": name,
                            "type": type,
                            "prop": self.TYPE,
                            "des": objective,
                            "url": src
                        }
                        # Save node
                        srcID = self.ds.addNode(node_prop)
                        
                # Find members
                members = weakness.Relationships
                if members is not None:
                    for member in members.children:
                        dest = "CWE-" + member["CWE_ID"]
                        relation = member.name
                        self.rs.saveRDF(src, dest, relation)

if __name__ == "__main__":
    capect = CAPECTraverser('data/CAPEC.xml')
    capect.traverse()