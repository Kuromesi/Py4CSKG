import sys, os

from utils.MultiTask import MultiTask
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

import json
import pandas as pd
from tqdm import tqdm 
from utils.version_compare import *
from utils.Logger import logger
from utils.Config import config
from knowledge_graph.Ontology.ontology import *
from knowledge_graph.Ontology.CVE import get_vul_type, CIA_LOSS

type_dict = {
    'a': "Software",
    'o': "OS",
    'h': "Hardware"
}

class CVETraverser():
    def __init__(self) -> None:
        self.type = "Vulnerability"
        # self.impact = pd.read_csv('./data/base/cve/CVEImpact.csv', index_col=0)

    def find_kv(self):
        pass

    def cpe_version(self, cpe):
        cpe23uri = ""
        if 'versionStartIncluding' in cpe:
            cpe23uri = cpe['cpe23Uri'] + ":" + cpe['versionStartIncluding']
        elif 'versionStartExcluding' in cpe:
            cpe23uri = cpe['cpe23Uri'] + ":" + cpe['versionStartExcluding']
        else:
            cpe23uri = cpe['cpe23Uri'] + ":*"
        if 'versionEndIncluding' in cpe:
            cpe23uri += ":" + cpe['versionEndIncluding']
        elif 'versionEndExcluding' in cpe:
            cpe23uri += ":" + cpe['versionEndExcluding']
        else:
            cpe23uri += ":*"
        cpe23uri += ":T" if cpe['vulnerable'] else ":F"
        return cpe23uri
    
    def _get_cpe(self, nodes, cve_id):
        result = []
        for node in nodes:
            operator = node['operator']
            if operator == "AND":
                l = []
                r = []
                if len(node['children']) > 0:
                    children = node['children']
                    left = children[0]['cpe_match']
                    try:
                        if len(children) > 1:
                            right = children[1]['cpe_match']
                            if not children[0]['cpe_match'][0]['vulnerable']:
                                left = children[1]['cpe_match']
                                right = children[0]['cpe_match']
                            for platform in right:
                                r.append(self.cpe_version(platform))
                            r = self.cpe_summary(r)   
                        for platform in left:
                                l.append(self.cpe_version(platform))
                        l = self.cpe_summary(l)
                        result.append((l, r))
                    except:
                        print("BAD DATA FORMAT OF %s!"%cve_id)
                else:
                    children = node['cpe_match']
                    for platform in children:
                        cpe_uri = self.cpe_version(platform)
                        if 'cpe:2.3:a' in cpe_uri or 'firmware' in cpe_uri:
                            l.append(cpe_uri)
                        else:
                            r.append(cpe_uri)
                    l = self.cpe_summary(l)
                    r = self.cpe_summary(r)
            else:
                cpe = []
                for platform in node['cpe_match']:
                    cpe.append(self.cpe_version(platform))
                cpe = self.cpe_summary(cpe)
                result.append((cpe, []))
        return result        

    def get_cpe(self, nodes, results):
        cpe23uri = ""
        for node in nodes:
            operator = node['operator']
            if operator == "AND":
                if 'children' in node:
                    results = self.get_cpe(node['children'], results)
            else:
                cpe_match = node['cpe_match']
                for cpe in cpe_match:
                    if not cpe['vulnerable']:
                        continue
                    if 'versionStartIncluding' in cpe:
                        cpe23uri = cpe['cpe23Uri'] + ":" + cpe['versionStartIncluding']
                    elif 'versionStartExcluding' in cpe:
                        cpe23uri = cpe['cpe23Uri'] + ":" + cpe['versionStartExcluding']
                    else:
                        cpe23uri = cpe['cpe23Uri'] + ":*"
                    if 'versionEndIncluding' in cpe:
                        cpe23uri += ":" + cpe['versionEndIncluding']
                    elif 'versionEndExcluding' in cpe:
                        cpe23uri += ":" + cpe['versionEndExcluding']
                    else:
                        cpe23uri += ":*"
                    results.append(cpe23uri)
        return results

    def l2s(self, str_list):
        string = ""
        for stri in str_list:
            string += stri + " "
        return string.strip()
    
    def cpe_summary(self, cpes):
        summary = {}
        for cpe in cpes:
            cpe = self._cpe_processor(cpe)
            product = cpe['product']
            if product in summary:
                summary[product]['versionStart'] = summary[product]['versionStart'] if cmp_version(cpe['versionStart'], summary[product]['versionStart']) == 1 else cpe['versionStart']
                summary[product]['versionEnd'] = cpe['versionEnd'] if cmp_version(cpe['versionEnd'], summary[product]['versionEnd']) == 1 else summary[product]['versionEnd']
            else:
                summary[product] = cpe
        for product in summary:
            uri = summary[product]['uri']
            uri = uri.split(':')
            uri[5] = "*"
            uri[6] = "*"
            uri[13] = summary[product]['versionStart']
            uri[14] = summary[product]['versionEnd']
            temp = ""
            for i in uri:
                temp += i + ":"
            uri = temp.strip(":")
            summary[product]['uri'] = uri
        return summary

    def _cpe_processor(self, cpe):
        result = {}
        words = cpe.split(":")
        
        result["type"] = type_dict[words[2]] # OS, Hardware or Software
        product = words[3].split('_') + words[4].split('_')
        product = self.l2s(product)
        result["product"] = product
        result["id"] = product
        version = "0"
        if words[5] != "*":
            version = words[5]
            if words[6] != "*":
                version += " " + words[6]
        result["versionStart"] = words[13] if words[13] != "*" else version
        result["versionEnd"] = words[14] if words[14] != "*" else version
        result["prop"] = "Platform"
        result["uri"] = cpe
        result["vulnerable"] = True if words[15] == "T" else False
        return result
    
    def traverse_single(self, path, count, cve_details):
        logger.info("Starting to traverse cve: %s"%path)
        cve_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'type', 'description', 'impact', 'cved_impact', 'baseMetricV2', 'baseMetricV3', 'complete'])
        cpe_df = pd.DataFrame(columns=['id:ID', ':LABEL', 'type', 'product', 'versionStart', 'versionEnd', 'vulnerable'])
        rel_df = pd.DataFrame(columns=[':START_ID', ':END_ID', ':TYPE'])
        with open(path, 'r', encoding='utf-8') as f:
            items = json.load(f)
        items = items['CVE_Items']
        # items = tqdm(items)
        for cur in items:
            cve = cur['cve']
            src = cve['CVE_data_meta']['ID']
            # items.set_postfix(CVE=src)
            # print(src)
            des = cve['description']['description_data'][0]['value']
            if ("** REJECT **" not in des):
                # df.loc[len(df.index)] = [src, des]
                # CVSS
                cvss = cur['impact']
                cvss2 = {}
                cvss3 = {}
                # baseMetricV2
                if ('baseMetricV2' in cvss):
                    cvss2 = cvss['baseMetricV2']
                # baseMetricV3
                if ('baseMetricV3' in cvss):
                    cvss3 = cvss['baseMetricV3']
                cved_impact = ", ".join(cve_details[src]) if src in cve_details else "unknown"
                cved_impact = cved_impact.strip()
                if not cvss2 and not cvss3:
                    impact = CIA_LOSS
                    logger.info(src)
                else:
                    impact = get_vul_type(cvss2, cvss3, cve_details[src] if src in cve_details else [])
                cvss2 = json.dumps(cvss2)
                cvss3 = json.dumps(cvss3)
                cve_df.loc[len(cve_df.index)] = [src, CVE_TYPE, "CVE", des, impact, cved_impact, cvss2, cvss3, json.dumps(cve)]
                

                # Find related CWE
                cwes = cve['problemtype']['problemtype_data'][0]['description']
                for cwe in cwes:
                    cwe = cwe['value']
                    if cwe != "NVD-CWE-noinfo" and cwe != "NVD-CWE-Other":
                        rel_df.loc[len(rel_df.index)] = [cwe, src, VULNERABILITY_WEAKNESS_REL]

                # Find CPE
                if 'configurations' in cur and 'nodes' in cur['configurations']:
                    cpe = cur['configurations']['nodes']
                    summary = self._get_cpe(cpe, src)
                    for sum in summary:
                        for product in sum[0]:
                            cpe_df.loc[len(cpe_df.index)] = [
                                sum[0][product]['uri'], PLATFORM_TYPE, sum[0][product]['type'], sum[0][product]['product'], 
                                sum[0][product]['versionStart'], sum[0][product]['versionEnd'], sum[0][product]['vulnerable']
                                ]
                            rel_df.loc[len(rel_df.index)] = [sum[0][product]['uri'], src, PLATFORM_REL]
                            if sum[1]:
                                for platform in sum[1]:
                                    cpe_df.loc[len(cpe_df.index)] = [
                                        sum[1][platform]['uri'], PLATFORM_TYPE, sum[1][platform]['type'], sum[1][platform]['product'], 
                                        sum[1][platform]['versionStart'], sum[1][platform]['versionEnd'], sum[1][platform]['vulnerable']
                                        ]
                                    rel_df.loc[len(rel_df.index)] = [sum[1][platform]['uri'], src, PLATFORM_REL]
                                    rel_df.loc[len(rel_df.index)] = [sum[0][product]['uri'], sum[1][platform]['uri'], "And"]
                                    rel_df.loc[len(rel_df.index)] = [sum[1][platform]['uri'], sum[0][product]['uri'], "And"]
        cve_df = cve_df.drop_duplicates()
        cve_df.to_csv('data/neo4j/nodes/cve_cve%d.csv'%count, index=False)
        cpe_df = cpe_df.drop_duplicates()
        cpe_df.to_csv('data/neo4j/nodes/cve_cpe%d.csv'%count, index=False)
        rel_df = rel_df.drop_duplicates()
        rel_df.to_csv('data/neo4j/relations/cve_rel%d.csv'%count, index=False)
    
    def traverse(self):
        # KURO
        # df = pd.DataFrame(columns=['id', 'des'])
        # product = set()
        # df = pd.DataFrame(columns=['product'])
        count = 0
        mt = MultiTask()
        cves = self.get_cves()
        mt.create_pool(32)
        base = config.get("DataUpdater", "base_path")
        path = os.path.join(base, "cve_details/impact.json")
        with open(path, 'r') as f:
            cve_details = json.load(f)
        tasks = [(task, id, cve_details) for id, task in enumerate(cves)]
        mt.apply_task(self.traverse_single, tasks)
        mt.delete_pool() 
    
    def get_cves(self):
        """get paths of cve in json format

        Returns:
            _type_: _description_
        """        
        base = config.get("DataUpdater", "base_path")
        path = os.path.join(base, "cve")
        cves = os.listdir(path)
        not_included = ["CVE-Modified.json", "CVE-Recent.json", "cve.json"]
        ret = []
        for cve in cves:
            if cve in not_included:
                continue
            if os.path.splitext(cve)[1] == '.json':
                ret.append(os.path.join(path, cve))
        return ret


if __name__ == '__main__':
    cves = [
        'data/base/cve/CVE-2002.json', 'data/CVE/CVE-2003.json', 'data/CVE/CVE-2004.json',
        'data/CVE/CVE-2005.json', 'data/CVE/CVE-2006.json', 'data/CVE/CVE-2007.json',
        'data/CVE/CVE-2008.json', 'data/CVE/CVE-2009.json', 'data/CVE/CVE-2010.json',
        'data/CVE/CVE-2011.json', 'data/CVE/CVE-2012.json', 'data/CVE/CVE-2013.json',
        'data/CVE/CVE-2014.json', 'data/CVE/CVE-2015.json', 'data/CVE/CVE-2016.json',
        'data/CVE/CVE-2017.json', 'data/CVE/CVE-2018.json', 'data/CVE/CVE-2019.json',
        'data/CVE/CVE-2020.json', 'data/CVE/CVE-2021.json', ]
    cvet = CVETraverser()
    cves = cvet.get_cves()
    cvet.traverse(cves)



