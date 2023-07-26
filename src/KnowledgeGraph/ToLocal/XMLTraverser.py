from bs4 import BeautifulSoup
import pandas as pd
import re
import json
from tqdm import tqdm
from Logging.Logger import logger
from DataUpdater.updaters.utils import *

CVE = re.compile(r'CVE-\d*-\d*')

class XmlTraverser: 
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

    def traverse(self):
        pass

class CAPECTraverser(XmlTraverser):
    def __init__(self, path: str):
        self.TYPE = "Pattern"
        with open(path, 'r', encoding='utf-8') as f:
            self.soup = BeautifulSoup(f, 'xml')
        self.vc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'complete'])
        self.pt_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'extended_description', 'type', 'complete'])
        self.misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'description'])
        self.rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])

    def traverse(self):
        # df = pd.DataFrame(columns=['id', 'name', 'description', 'cve'])
        # Find views
        logger.info("Starting to traverse CAPEC")
        views = self.soup.find_all("View")
        views = tqdm(views)
        views.set_description("TRAVERSING VIEWS")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type1 = view.name
                name = view["Name"]
                src = "CAPEC-" + view["ID"]
                views.set_postfix(id=src)
                objective = view.Objective.get_text().strip()
                self.pt_df.loc[len(self.pt_df.index)] = [src, self.TYPE, name, objective, "", type1, str(view)]
                
                # Find members
                members = view.Members
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]
        
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
                objective = category.Summary.get_text().strip()
                self.pt_df.loc[len(self.pt_df.index)] = [src, self.TYPE, name, objective, "", type1, str(category)]

                # Find members
                members = category.Relationships
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]

        # Find attack patterns
        atkpts = self.soup.find_all("Attack_Pattern")
        atkpts = tqdm(atkpts)
        atkpts.set_description("TRAVERSING ATTACK PATTERNS")
        for atkpt in atkpts:
            if atkpt["Status"] != "Deprecated":
                # Find attack patterns properties
                type1 = atkpt['Abstraction']
                name = atkpt["Name"]
                src = "CAPEC-" + atkpt["ID"]
                atkpts.set_postfix(id=src)
                # print(src)
                
                description = self.get_value(atkpt, "Description") 
                extended_des = self.get_value(atkpt, "Extended_Description")
                self.pt_df.loc[len(self.pt_df.index)] = [src, self.TYPE, name, description, extended_des, type1, str(atkpt)]


                # Related attack patterns
                related_attack_patterns = atkpt.Related_Attack_Patterns
                if related_attack_patterns:
                    for related_attack_pattern in related_attack_patterns.children:
                        if related_attack_pattern != "\n":
                            dest = "CAPEC-" + related_attack_pattern["CAPEC_ID"]
                            relation = related_attack_pattern['Nature']
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]

                # Related Weaknesses
                related_weaknesses = atkpt.Related_Weaknesses
                if related_weaknesses:
                    for related_weakness in related_weaknesses.children:
                        if related_weakness != "\n":
                            dest = "CWE-" + related_weakness['CWE_ID']
                            relation = related_weakness.name
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]
                            
                # Find mitigations
                mitigations = atkpt.find('Mitigations')
                if mitigations:
                    mitigation_uri = "Mitigation:" + src
                    des = mitigations.text.strip()
                    self.misc_df.loc[len(self.misc_df.index)] = [mitigation_uri, "Mitigation", des]
                    self.rel_df.loc[len(self.rel_df.index)] = [src, mitigation_uri, "Has_Mitigation"]

                # Find indicators
                indicators = atkpt.find_all('Indicator')
                count = 1
                for indicator in indicators:
                    id = "Indicator:" + src + ".%d"%count
                    des = indicator.text.strip()
                    indicator_node = {'id': id, 'description': des, 'prop': "IOC"}
                    self.misc_df.loc[len(self.misc_df.index)] = [id, "IOC", des]
                    self.rel_df.loc[len(self.rel_df.index)] = [src, id, "Has_IOC"]
                    count += 1    
        self.pt_df.to_csv('data/neo4j/nodes/capec_pt.csv', index=False)
        self.misc_df.to_csv('data/neo4j/nodes/capec_misc.csv', index=False)
        self.rel_df.to_csv('data/neo4j/relations/capec_rel.csv', index=False)

class CWETraverser(XmlTraverser):
    def __init__(self, path: str):
        self.TYPE = "Weakness"
        with open(path, "r", encoding='utf-8') as file:
            self.soup = BeautifulSoup(file, "xml")
        self.wk_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'complete'])
        self.rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        self.misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'description'])
    
    def traverse(self):
        logger.info("Starting to traverse CWE")
        srcID, destID = None, None
        
        # Find views
        views = self.soup.find_all("View")
        views = tqdm(views)
        views.set_description("TRAVERSING VIEWS")
        for view in views:
            if view["Status"] != "Deprecated":
                # Find view properties
                type1 = view.name
                name = view["Name"]
                src = "CWE-" + view["ID"]
                views.set_postfix(id=src)
                objective = view.Objective.text
                self.wk_df.loc[len(self.wk_df.index)] = [src, self.TYPE, name, objective, type1, str(view)]

                #Find members
                members = view.Members
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]

        # Find categories
        categories = self.soup.find_all("Category")
        categories = tqdm(categories)
        categories.set_description("TRAVERSING CATEGORIES")
        for view in categories:
            if view["Status"] != "Deprecated":
                # Find categories properties
                type1 = view.name
                name = view["Name"]
                src = "CWE-" + view["ID"]
                categories.set_postfix(id=src)
                objective = view.Summary.text
                self.wk_df.loc[len(self.wk_df.index)] = [src, self.TYPE, name, objective, type1, str(view)]

                # Find members
                members = view.Relationships
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]
                            
        # Find weaknesses
        weaknesses = self.soup.find_all("Weakness")
        weaknesses = tqdm(weaknesses)
        weaknesses.set_description("TRAVERSING WEAKNESSES")
        for weakness in weaknesses:
            if weakness["Status"] != "Deprecated":
                # Find weakness properties
                type1 = weakness.name
                name = weakness["Name"]
                src = "CWE-" + weakness["ID"]
                weaknesses.set_postfix(id=src)
                objective = weakness.Description.text
                self.wk_df.loc[len(self.wk_df.index)] = [src, self.TYPE, name, objective, type1, str(weakness)]
          
            # Find members
            members = weakness.Relationships
            if members is not None:
                for member in members.children:
                    if member != "\n":
                        dest = "CWE-" + member["CWE_ID"]
                        relation = member.name
                        self.rel_df.loc[len(self.rel_df.index)] = [src, dest, relation]
                        
            # Find mitigations
            mitigations = weakness.find_all('Mitigation')
            if mitigations:
                count = 1
                for mitigation in mitigations:
                    id = mitigation['Mitigation_ID'] if 'Mitigation_ID' in mitigation else "Mitigation:" + src + ".%d"%count
                    count += 1
                    des = str(mitigation)
                    self.misc_df.loc[len(self.misc_df.index)] = [id, "Mitigation", des]
                    self.rel_df.loc[len(self.rel_df.index)] = [src, id, "Has_Mitigation"]
        self.wk_df.to_csv('data/neo4j/nodes/cwe_wk.csv', index=False)
        self.misc_df.to_csv('data/neo4j/nodes/cwe_misc.csv', index=False)
        self.rel_df.to_csv('data/neo4j/relations/cwe_rel.csv', index=False) 
        
class ATTACKTraverser(XmlTraverser):
    def __init__(self, path="data/base/attack/enterprise.xml", tactic_url='data/attack/enterprise_tactic.json'):
        self.TYPE = "Technique"
        self.tactic_url = tactic_url
        with open(path, "r", encoding='utf-8') as file:
            self.soup = BeautifulSoup(file, "xml")
        self.tech_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'platforms', 'permissions_required', 'effective_permissions', 'impact_type','complete'])
        self.rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        self.misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description'])

    def traverse(self):
        logger.info("Starting to traverse ATT&CK")
        self.tactic_traverse(self.tactic_url)
        technique = tqdm(self.soup.find_all('Technique'))
        technique.set_description("TRAVERSING ATT&CK TECHNIQUES")
        for tech in technique:
            technique.set_postfix(id=tech['id'])
            attrs = {}
            attrs['id'] = text_proc(tech['id'])
            attrs['name'] = text_proc(tech['name'])
            attrs['des'] = text_proc(tech.next)
            attrs['type'] = 'SubTechnique' if "." in attrs['id'] else "Technique"
            attrs['prop'] = self.TYPE
            attrs['complete'] = str(tech)
            attrs['platforms'] = text_proc(tech.find('Platforms').text) if tech.find('Platforms') else ""
            attrs['permissions_required'] = text_proc(tech.find('Permissions_Required').text) if tech.find('Permissions_Required') else ""   
            attrs['effective_permissions'] = text_proc(tech.find('Effective_Permissions').text) if tech.find('Effective_Permissions') else ""
            attrs['impact_type'] = text_proc(tech.find('Impact_Type').text) if tech.find('Impact_Type') else ""
                
            self.tech_df.loc[len(self.tech_df.index)] = [
                attrs['id'], "Technique", attrs['name'], attrs['des'], attrs['type'], attrs['platforms'], 
                attrs['permissions_required'], attrs['effective_permissions'], attrs['impact_type'], attrs['complete']
                ]
            
            # Add the node to the graph database
            
            if tech.get('id') and '.' in tech.get('id'):
                techId = attrs['id'].split('.')[0]
                self.rel_df.loc[len(self.rel_df.index)] = [techId, attrs['id'], "Has_SubTechnique"]

            # Find tactics
            tactics = tech.find('Tactics')
            if not tactics:
                tactics = tech.find('Tactic')
            tactic = tactics.text.split(', ')
            for tac in tactic:
                # Save RDF
                self.rel_df.loc[len(self.rel_df.index)] = [self.root_node[tac.strip()]['id'], attrs['id'], "Has_Technique"]
            
            # Find capec
            capec = tech.find('CAPEC_ID')
            if capec:
                capec = capec.text.split(', ')
                for cap in capec:
                    self.rel_df.loc[len(self.rel_df.index)] = [cap.strip(), attrs['id'], "In_CAPEC"]
                    
            # Find examples
            examples = tech.find_all('Example')
            if examples:
                for example in examples:
                    id = example['id']
                    name = example['name']
                    # group_type = "Software" if id[0] == "S" else "Group"
                    self.misc_df.loc[len(self.misc_df.index)] = [id, "Threats", name, ""]
                    uri = id + ":" +attrs['id']
                    des = text_proc(example.next)
                    self.misc_df.loc[len(self.misc_df.index)] = [uri, "Procedure", "", des]
                    self.rel_df.loc[len(self.rel_df.index)] = [id, uri, "Has_Procedure"]
                    self.rel_df.loc[len(self.rel_df.index)] = [uri, attrs['id'], "Utilize"]
                
            # Find mitigations
            mitigations = tech.find_all('Mitigation')
            if mitigations:
                for mitigation in mitigations:
                    id = mitigation['id']
                    name = mitigation['name']
                    des = text_proc(mitigation.text)
                    self.misc_df.loc[len(self.misc_df.index)] = [id, "Mitigation", name, des]
                    self.rel_df.loc[len(self.rel_df.index)] = [attrs['id'], id, "Has_Mitigation"]
                    
            # Find detections
            detections = tech.find_all('Detection')
            if detections:
                for detection in detections:
                    id = detection['id']
                    name = detection['name']
                    des = text_proc(detection.text)
                    self.misc_df.loc[len(self.misc_df.index)] = [id, "IOC", name, des]
                    self.rel_df.loc[len(self.rel_df.index)] = [attrs['id'], id, "Has_IOC"]
                        
        self.tech_df.to_csv('data/neo4j/nodes/attack_tech.csv', index=False)
        self.misc_df.to_csv('data/neo4j/nodes/attack_misc.csv', index=False)
        self.rel_df.to_csv('data/neo4j/relations/attack_rel.csv', index=False) 

    def tactic_traverse(self, json_url):
        with open(json_url, 'r', encoding='utf-8') as f:
            self.root_node = json.load(f)
        for name in self.root_node:
            print(name)
            # if True:
            cur = self.root_node[name]
            id = cur['id']
            description = cur["description"]
            self.misc_df.loc[len(self.misc_df.index)] = [id, "Tactic", name, description]

if __name__ == "__main__":
    # capect = CAPECTraverser('data/CAPEC/CAPEC.xml')
    # capect.traverse()
    attackt = ATTACKTraverser('data/attack/enterpriseN.xml', 'data/attack/tactic.json')
    attackt.traverse()
    # cwet = CWETraverser('data/CWE/CWE.xml')
    # cwet.traverse()