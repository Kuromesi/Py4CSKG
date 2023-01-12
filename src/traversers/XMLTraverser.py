# from service.GDBSaver import GDBSaver
# from service.RDBSaver import RDBSaver
from bs4 import BeautifulSoup

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
                type = atkpt.name
                name = atkpt["Name"]
                src = "CAPEC-" + atkpt["ID"]
                print(src)
                description = self.get_value(atkpt, "Description") + self.get_value(atkpt, "Extended_Description")
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": description,
                    "url": src
                }
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

if __name__ == "__main__":
    capect = CAPECTraverser('data/CAPEC.xml')
    capect.traverse()