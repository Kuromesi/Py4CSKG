from bs4 import BeautifulSoup
import pandas as pd
import re, os, json
import sys
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from tqdm import tqdm
from utils.Logger import logger
from data_updater.utils.utils import *
from utils.MultiTask import MultiTask
from utils.Config import config
from knowledge_graph.Ontology.ontology import *

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
    def __init__(self):
        pass

    def traverse(self):
        # df = pd.DataFrame(columns=['id', 'name', 'description', 'cve'])
        # Find views
        logger.info("Starting to traverse CAPEC")
        base = config.get("KnowledgeGraph", "base_path")
        path = os.path.join(base, "base/capec/CAPEC.xml")
        with open(path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'xml')
        vc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'complete'])
        pt_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'extended_description', 'type', 'complete'])
        misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'description'])
        rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        capec_cve_df = pd.DataFrame(columns=['id', 'name', 'description', 'cve'])
        views = soup.find_all("View")
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
                pt_df.loc[len(pt_df.index)] = [src, CAPEC_TYPE, name, objective, "", type1, str(view)]
                
                # Find members
                members = view.Members
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            rel_df.loc[len(rel_df.index)] = [src, dest, relation]   
                
                # For textsimlarity
                examples = view.find_all("Example")
                cves = []
                if examples:
                    examples = str(examples)
                    cves = CVE.findall(examples)
                    for cve in cves:
                        rel_df.loc[len(rel_df.index)] = [src, cve, "Has_Example"]
                capec_cve_df.loc[len(capec_cve_df.index)] = [src, name, objective, cves]            
        
        # Find categories
        categories = soup.find_all("Category")
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
                pt_df.loc[len(pt_df.index)] = [src, CAPEC_TYPE, name, objective, "", type1, str(category)]

                # Find members
                members = category.Relationships
                if members:
                    for member in members.children:
                        if member != "\n":
                            dest = "CAPEC-" + member["CAPEC_ID"]
                            relation = member.name
                            rel_df.loc[len(rel_df.index)] = [src, dest, relation]
                
                # For textsimlarity
                examples = category.find_all("Example")
                cves = []
                if examples:
                    examples = str(examples)
                    cves = CVE.findall(examples)
                    for cve in cves:
                        rel_df.loc[len(rel_df.index)] = [src, cve, "Has_Example"]
                capec_cve_df.loc[len(capec_cve_df.index)] = [src, name, objective, cves]

        # Find attack patterns
        atkpts = soup.find_all("Attack_Pattern")
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
                pt_df.loc[len(pt_df.index)] = [src, CAPEC_TYPE, name, description, extended_des, type1, str(atkpt)]


                # Related attack patterns
                related_attack_patterns = atkpt.Related_Attack_Patterns
                if related_attack_patterns:
                    for related_attack_pattern in related_attack_patterns.children:
                        if related_attack_pattern != "\n":
                            dest = "CAPEC-" + related_attack_pattern["CAPEC_ID"]
                            relation = related_attack_pattern['Nature']
                            rel_df.loc[len(rel_df.index)] = [src, dest, relation]

                # Related Weaknesses
                related_weaknesses = atkpt.Related_Weaknesses
                if related_weaknesses:
                    for related_weakness in related_weaknesses.children:
                        if related_weakness != "\n":
                            dest = "CWE-" + related_weakness['CWE_ID']
                            rel_df.loc[len(rel_df.index)] = [src, dest, TECHNIQUE_WEAKNESS_REL]
                            
                # Find mitigations
                mitigations = atkpt.find('Mitigations')
                if mitigations:
                    mitigation_uri = "Mitigation:" + src
                    des = mitigations.text.strip()
                    misc_df.loc[len(misc_df.index)] = [mitigation_uri, MITIGATION_TYPE, des]
                    rel_df.loc[len(rel_df.index)] = [mitigation_uri, src, MITIGATE_REL]

                # Find indicators
                indicators = atkpt.find_all('Indicator')
                count = 1
                for indicator in indicators:
                    id = "Indicator:" + src + ".%d"%count
                    des = indicator.text.strip()
                    indicator_node = {'id': id, 'description': des, 'prop': "IOC"}
                    misc_df.loc[len(misc_df.index)] = [id, INDICATOR_TYPE, des]
                    rel_df.loc[len(rel_df.index)] = [id, src, INDICATE_TECHNIQUE_REL]
                    count += 1    

                # For texsimilarity
                examples = atkpt.find_all("Example")
                cves = []
                if examples:
                    examples = str(examples)
                    cves = CVE.findall(examples)
                    for cve in cves:
                        rel_df.loc[len(rel_df.index)] = [src, cve, "Has_Example"]
                capec_cve_df.loc[len(capec_cve_df.index)] = [src, name, description, cves]
        
                # Find related ATT&CK
                taxonomies = atkpt.find_all('Taxonomy_Mapping')
                if taxonomies:
                    for taxonomy in taxonomies:
                        if taxonomy.attrs['Taxonomy_Name'] != "ATTACK":
                            continue
                        entry = "T" + taxonomy.find_all("Entry_ID")[0].text.strip()
                        rel_df.loc[len(rel_df.index)] = [src, entry, CAPEC_ATTACK_REL]

        base = config.get("KnowledgeGraph", "base_path")
        pt_df.drop_duplicates()
        pt_df.to_csv(os.path.join(base, 'neo4j/nodes/capec_pt.csv'), index=False)
        misc_df.drop_duplicates()
        misc_df.to_csv(os.path.join(base, 'neo4j/nodes/capec_misc.csv'), index=False)
        rel_df.drop_duplicates()
        rel_df.to_csv(os.path.join(base, 'neo4j/relations/capec_rel.csv'), index=False)
        if not os.path.exists:
            os.mkdir(os.path.join(base, "capec"))
        # base = config.get("DeepLearning", "base_path")
        # capec_cve_df.to_csv(os.path.join(base, "capec/capec.csv"), index=False)


class CWETraverser(XmlTraverser):
    def __init__(self):
        self.TYPE = "Weakness"
    
    def traverse(self):
        base = config.get("KnowledgeGraph", "base_path")
        path = os.path.join(base, "base/cwe/CWE.xml")
        with open(path, "r", encoding='utf-8') as file:
            soup = BeautifulSoup(file, "xml")
        wk_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'complete'])
        rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'description'])
        logger.info("Starting to traverse CWE")
        
        # Find views
        views = soup.find_all("View")
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
                wk_df.loc[len(wk_df.index)] = [src, CWE_TYPE, name, objective, type1, str(view)]

                #Find members
                members = view.Members
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            rel_df.loc[len(rel_df.index)] = [src, dest, relation]

        # Find categories
        categories = soup.find_all("Category")
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
                wk_df.loc[len(wk_df.index)] = [src, CWE_TYPE, name, objective, type1, str(view)]

                # Find members
                members = view.Relationships
                if members is not None:
                    for member in members.children:
                        if member != "\n":
                            dest = "CWE-" + member["CWE_ID"]
                            relation = member.name
                            rel_df.loc[len(rel_df.index)] = [src, dest, relation]
                            
        # Find weaknesses
        weaknesses = soup.find_all("Weakness")
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
                wk_df.loc[len(wk_df.index)] = [src, CWE_TYPE, name, objective, type1, str(weakness)]
          
            # Find members
            members = weakness.Relationships
            if members is not None:
                for member in members.children:
                    if member != "\n":
                        dest = "CWE-" + member["CWE_ID"]
                        relation = member.name
                        rel_df.loc[len(rel_df.index)] = [src, dest, relation]
                        
            # Find mitigations
            mitigations = weakness.find_all('Mitigation')
            if mitigations:
                count = 1
                for mitigation in mitigations:
                    id = mitigation['Mitigation_ID'] if 'Mitigation_ID' in mitigation else "Mitigation:" + src + ".%d"%count
                    count += 1
                    des = str(mitigation)
                    misc_df.loc[len(misc_df.index)] = [id, MITIGATION_TYPE, des]
                    rel_df.loc[len(rel_df.index)] = [id, src, MITIGATE_REL]
        base = config.get("KnowledgeGraph", "base_path")
        wk_df.drop_duplicates()
        wk_df.to_csv(os.path.join(base, 'neo4j/nodes/cwe_wk.csv'), index=False)
        misc_df.drop_duplicates()
        misc_df.to_csv(os.path.join(base, 'neo4j/nodes/cwe_misc.csv'), index=False)
        rel_df.drop_duplicates()
        rel_df.to_csv(os.path.join(base, 'neo4j/relations/cwe_rel.csv'), index=False) 
        
class ATTACKTraverser(XmlTraverser):
    def __init__(self):
        self.TYPE = "Technique"

    def traverse(self):
        names = ["enterprise", "mobile", "ics"]
        base = config.get("KnowledgeGraph", "base_path")
        mt = MultiTask()
        mt.create_pool(8)
        base = os.path.join(base, "base/attack")
        tasks = [(os.path.join(base, "%s_tactic.json"%name), os.path.join(base, "%s.xml"%name), name) for name in names]
        mt.apply_task(self.traverse_single, tasks)
        mt.delete_pool()

    def traverse_single(self, tactic_path, technique_path, kind):
        logger.info("Starting to traverse ATT&CK: %s"%technique_path)
        tech_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description', 'type', 'platforms', 'permissions_required', 'effective_permissions', 'impact_type','complete'])
        rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        misc_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'name', 'description'])
        
        # traverse tactics
        with open(tactic_path, 'r', encoding='utf-8') as f:
            root_node = json.load(f)
        for name in root_node:
            # if True:
            cur = root_node[name]
            id = cur['id']
            description = cur["description"]
            misc_df.loc[len(misc_df.index)] = [id, TACTIC_TYPE, name, description]

        with open(technique_path, "r", encoding='utf-8') as file:
            soup = BeautifulSoup(file, "xml")
        technique = soup.find_all('Technique')
        # technique.set_description("TRAVERSING ATT&CK TECHNIQUES")
        for tech in technique:
            # technique.set_postfix(id=tech['id'])
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
                
            tech_df.loc[len(tech_df.index)] = [
                attrs['id'], ATTACK_TYPE, attrs['name'], attrs['des'], attrs['type'], attrs['platforms'], 
                attrs['permissions_required'], attrs['effective_permissions'], attrs['impact_type'], attrs['complete']
                ]
            
            # Add the node to the graph database
            
            if tech.get('id') and '.' in tech.get('id'):
                techId = attrs['id'].split('.')[0]
                rel_df.loc[len(rel_df.index)] = [techId, attrs['id'], "Has_SubTechnique"]

            # Find tactics
            tactics = tech.find('Tactics')
            if not tactics:
                tactics = tech.find('Tactic')
            tactic = tactics.text.split(', ')
            for tac in tactic:
                # Save RDF
                rel_df.loc[len(rel_df.index)] = [attrs['id'], root_node[tac.strip()]['id'], TECHNIQUE_TACTIC_REL]
            
            # Find capec
            # capec = tech.find('CAPEC_ID')
            # if capec:
            #     capec = capec.text.split(', ')
            #     for cap in capec:
            #         rel_df.loc[len(rel_df.index)] = [cap.strip(), attrs['id'], "In_CAPEC"]
                    
            # Find examples
            examples = tech.find_all('Example')
            if examples:
                for example in examples:
                    id = example['id']
                    name = example['name']
                    # group_type = "Software" if id[0] == "S" else "Group"
                    misc_df.loc[len(misc_df.index)] = [id, THREAT_TYPE, name, ""]
                    uri = id + ":" +attrs['id']
                    des = text_proc(example.next)
                    misc_df.loc[len(misc_df.index)] = [uri, PROCEDURE_TYPE, "", des]
                    rel_df.loc[len(rel_df.index)] = [id, uri, THREAT_PROCEDURE_REL]
                    rel_df.loc[len(rel_df.index)] = [uri, attrs['id'], PROCEDURE_TECHNIQUE_REL]
                
            # Find mitigations
            mitigations = tech.find_all('Mitigation')
            if mitigations:
                for mitigation in mitigations:
                    id = mitigation['id'] + ":%s"%attrs['id']
                    name = mitigation['name']
                    des = text_proc(mitigation.text)
                    misc_df.loc[len(misc_df.index)] = [id, MITIGATION_TYPE, name, des]
                    rel_df.loc[len(rel_df.index)] = [id, attrs['id'], MITIGATE_REL]
                    
            # Find detections
            detections = tech.find_all('Detection')
            if detections:
                for detection in detections:
                    id = detection['id'] + ":%s"%attrs['id']
                    name = detection['name']
                    des = text_proc(detection.text)
                    misc_df.loc[len(misc_df.index)] = [id, INDICATOR_TYPE, name, des]
                    rel_df.loc[len(rel_df.index)] = [id, attrs['id'], INDICATE_TECHNIQUE_REL]
        base = config.get("KnowledgeGraph", "base_path")
        tech_df = tech_df.drop_duplicates()
        tech_df.to_csv(os.path.join(base, 'neo4j/nodes/attack_tech_%s.csv'%kind), index=False)
        misc_df = misc_df.drop_duplicates()
        misc_df.to_csv(os.path.join(base, 'neo4j/nodes/attack_misc_%s.csv'%kind), index=False)
        rel_df = rel_df.drop_duplicates()
        rel_df.to_csv(os.path.join(base, 'neo4j/relations/attack_rel_%s.csv'%kind), index=False) 

if __name__ == "__main__":
    capect = CAPECTraverser()
    capect.traverse()
    attackt = ATTACKTraverser()
    attackt.traverse()
    cwet = CWETraverser('data/CWE/CWE.xml')
    cwet.traverse()