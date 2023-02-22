from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from bs4 import BeautifulSoup
import pandas as pd
import re
import json
from tqdm import tqdm

CVE = re.compile(r'CVE-\d*-\d*')

class XmlTraverser: 
    ds = GDBSaver()
    rs = RDBSaver()
    def init(self): 
        
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
        # df = pd.DataFrame(columns=['id', 'name', 'description', 'cve'])
        # Find views
        views = self.soup.find_all("View")
        views = tqdm(views)
        views.set_description("TRAVERSING VIEWS")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type1 = view.name
                name = view["Name"]
                src = "CAPEC-" + view["ID"]
                # print(src)
                views.set_postfix(id=src)
                objective = view.Objective.get_text().strip()
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type1,
                    "prop": self.TYPE,
                    "des": objective,
                    "complete": str(view)
                }
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)

                # full_card = str(view)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')
                # self.rs.saveRDF(src, )
                
                # df.loc[len(df.index)] = [src, name, objective, CVE.findall(t)] #kuro

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
        categories = tqdm(categories)
        categories.set_description("TRAVERSING CATEGORIES")
        for category in categories:
            if category["Status"] != "Deprecated":
                # Find categories properties
                type = category.name
                name = category["Name"]
                src = "CAPEC-" + category["ID"]
                categories.set_postfix(id=src)
                # print(src)
                objective = category.Summary.get_text().strip()
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "complete": str(category)
                }
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)
                # full_card = str(category)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')
                
                # df.loc[len(df.index)] = [src, name, objective, CVE.findall(t)] #kuro
                # Save node
                # srcID = self.ds.addNode(node_prop)
                # Find members
                members = category.Relationships
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            self.rs.saveRDF(src, dest, relation)

        # Find attack patterns
        atkpts = self.soup.find_all("Attack_Pattern")
        atkpts = tqdm(atkpts)
        atkpts.set_description("TRAVERSING ATTACK PATTERNS")
        for atkpt in atkpts:
            if atkpt["Status"] != "Deprecated":
                # Find attack patterns properties
                type = atkpt['Abstraction']
                name = atkpt["Name"]
                src = "CAPEC-" + atkpt["ID"]
                atkpts.set_postfix(id=src)
                # print(src)
                
                description = self.get_value(atkpt, "Description") 
                extended_des = self.get_value(atkpt, "Extended_Description")
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "description": description,
                    "extended_description": extended_des,
                    "complete": str(atkpt)
                }
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)
                # full_card = str(atkpt)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')

                # df.loc[len(df.index)] = [src, name, self.get_value(atkpt, "Description"), CVE.findall(t)] #kuro

                # Save node
                # srcID = self.ds.addNode(node_prop)

                # Related attack patterns
                related_attack_patterns = atkpt.Related_Attack_Patterns
                if related_attack_patterns:
                    for related_attack_pattern in related_attack_patterns.children:
                        if related_attack_pattern != "\n":
                            dest = "CAPEC-" + related_attack_pattern["CAPEC_ID"]
                            relation = related_attack_pattern['Nature']
                            self.rs.saveRDF(src, dest, relation)

                # Related Weaknesses
                related_weaknesses = atkpt.Related_Weaknesses
                if related_weaknesses:
                    for related_weakness in related_weaknesses.children:
                        if related_weakness != "\n":
                            dest = "CWE-" + related_weakness['CWE_ID']
                            relation = related_weakness.name
                            self.rs.saveRDF(src, dest, relation)
        # df.to_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv', index=False)       

class CWETraverser(XmlTraverser):
    def __init__(self, path: str):
        self.TYPE = "Weakness"
        with open(path, "r", encoding='utf-8') as file:
            self.soup = BeautifulSoup(file, "xml")
    
    def traverse(self):
        srcID, destID = None, None
        
        # Find views
        views = self.soup.find_all("View")
        views = tqdm(views)
        views.set_description("TRAVERSING VIEWS")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type = view.name
                name = view["Name"]
                src = "CWE-" + view["ID"]
                views.set_postfix(id=src)
                objective = view.Objective.text
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "complete": str(view)
                }
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)

                # full_card = str(view)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')
                
                # Save node
                # srcID = self.ds.addNode(node_prop)

                #Find members
                members = view.Members
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            self.rs.saveRDF(src, dest, relation)

        # Find categories
        categories = self.soup.find_all("Category")
        categories = tqdm(categories)
        categories.set_description("TRAVERSING CATEGORIES")
        for view in categories:
            if view["Status"] != "Deprecated":
                # Find categories properties
                type = view.name
                name = view["Name"]
                src = "CWE-" + view["ID"]
                categories.set_postfix(id=src)
                objective = view.Summary.text
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "complete": str(view)
                }
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)
                
                # full_card = str(view)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')
                
                # Save node
                # srcID = self.ds.addNode(node_prop)
                # Find members
                members = view.Relationships
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            self.rs.saveRDF(src, dest, relation)
                            
        # Find weaknesses
        weaknesses = self.soup.find_all("Weakness")
        weaknesses = tqdm(weaknesses)
        weaknesses.set_description("TRAVERSING WEAKNESSES")
        for weakness in weaknesses:
            if weakness["Status"] != "Deprecated":
                # Find weakness properties
                type = weakness.name
                name = weakness["Name"]
                src = "CWE-" + weakness["ID"]
                weaknesses.set_postfix(id=src)
                objective = weakness.Description.text
                node_prop = {
                    "id": src,
                    "name": name,
                    "type": type,
                    "prop": self.TYPE,
                    "des": objective,
                    "complete": str(weakness)
                }
                
                # Save node
                srcID = self.ds.addNode(node_prop)
                self.rs.saveNodeId(node_prop['id'], srcID)
                
                # full_card = str(weakness)
                # card_attrs = {}
                # card_attrs['id'] = src + "-FullCard"
                # card_attrs['des'] = full_card
                # card_attrs['prop'] = "FullCard"
                # full_cardID = self.ds.addNode(card_attrs)
                # self.rs.saveNodeId(card_attrs['id'], full_cardID)
                # self.rs.saveRDF(node_prop['id'], card_attrs['id'], 'Has_FullCard')
          
            # Find members
            members = weakness.Relationships
            if members is not None:
                for member in members.children:
                    if member != "\n":
                        dest = "CWE-" + member["CWE_ID"]
                        relation = member.name
                        self.rs.saveRDF(src, dest, relation)

class ATTACKTraverser(XmlTraverser):

    def __init__(self, path: str, tactic_url: str):
        self.TYPE = "Vulnerability"
        self.tactic_url = tactic_url
        self.ds = GDBSaver()
        self.rs = RDBSaver()
        with open(path, "r", encoding='utf-8') as file:
            self.soup = BeautifulSoup(file, "xml")

    def traverse(self):
        self.tactic_traverse(self.tactic_url)
        technique = tqdm(self.soup.find_all('Technique'))
        technique.set_description("TRAVERSING ATT&CK TECHNIQUES")
        for tech in technique:
            technique.set_postfix(id=tech['id'])
            attrs = {}
            attrs['id'] = self.string_proc(tech['id'])
            attrs['name'] = self.string_proc(tech['name'])
            attrs['des'] = self.string_proc(tech.next)
            attrs['type'] = 'Technique'
            attrs['prop'] = 'Technique'
            attrs['complete'] = str(tech)
            if tech.find('Platforms'):
                attrs['platforms'] = self.string_proc(tech.find('Platforms').text)
            if tech.find('Permissions_Required'):
                attrs['permissions_required'] = self.string_proc(tech.find('Permissions_Required').text)
            if tech.find('Effective_Permissions'):
                attrs['effective_permissions'] = self.string_proc(tech.find('Effective_Permissions').text)
            if tech.find('Impact_Type'):
                attrs['impact_type'] = self.string_proc(tech.find('Impact_Type').text)
            # Add the node to the graph database
            srcID = self.ds.addNode(attrs)
            self.rs.saveNodeId(attrs['id'], srcID)
            if tech.get('id') and '.' in tech.get('id'):
                techId = attrs['id'].split('.')[0]
                self.rs.saveRDF(techId, attrs['id'], "Has_SubTechnique")

            # Find tactics
            tactics = tech.find('Tactics')
            if not tactics:
                tactics = tech.find('Tactic')
            tactic = tactics.text.split(', ')
            for tac in tactic:
                # Save RDF
                self.rs.saveRDF(tac.strip(), attrs['id'], 'Has_Technique')
            
            # Find capec
            capec = tech.find('CAPEC_ID')
            if capec:
                capec = capec.text.split(', ')
                for cap in capec:
                    self.rs.saveRDF(cap.strip(), attrs['id'], 'In_CAPEC')

            # full_card = str(tech)
            # card_attrs = {}
            # card_attrs['id'] = attrs['id'] + "-FullCard"
            # card_attrs['des'] = full_card
            # card_attrs['prop'] = "FullCard"
            # destID = self.ds.addNode(card_attrs)
            # self.rs.saveNodeId(card_attrs['id'], destID)
            # self.rs.saveRDF(attrs['id'], card_attrs['id'], 'Has_FullCard')

    def tactic_traverse(self, json_url):
        with open(json_url, 'r', encoding='utf-8') as f:
            root_node = json.load(f)
        for name in root_node:
            print(name)
            if not self.rs.checkNode(name):
            # if True:
                cur = root_node[name]
                id = cur['id']
                contents = cur["contents"]
                attrs = {"id": id, "type": "Tactic", "contents": contents, "name": name, "url": id, "prop": "Tactic"}
                src_id = self.ds.addNode(attrs)
                self.rs.saveNodeId(attrs["name"], src_id)

if __name__ == "__main__":
    # capect = CAPECTraverser('data/CAPEC.xml')
    # capect.traverse()
    attackt = ATTACKTraverser('data/ATTACK_Enterprise.xml', 'data/tactic.json')
    attackt.traverse()
    # cwet = CWETraverser('data/CWE.xml')
    # cwet.traverse()