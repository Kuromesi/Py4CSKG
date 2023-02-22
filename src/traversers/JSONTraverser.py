import json
import pandas as pd
from tqdm import tqdm 
from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from webapp.utils.version_compare import *

type_dict = {
    'a': "Software",
    'o': "OS",
    'h': "Hardware"
}

class CVETraverser():
    def __init__(self) -> None:
        self.ds = GDBSaver()
        self.rs = RDBSaver()
        self.type = "Vulnerability"

    def find_kv(self):
        pass

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
                summary[product]['versionStart'] = summary[product]['versionStart'] if cmp_version(cpe['versionStart'], summary[product]['versionStart']) else cpe['versionStart']
                summary[product]['versionEnd'] = cpe['versionEnd'] if cmp_version(cpe['versionEnd'], summary[product]['versionEnd']) else summary[product]['versionEnd']
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
        return result

    def cpe_processor(self, cpe):
        result = {}
        words = cpe.split(":")
        result["cpe_version"] = words[0] + "-" + words[1]
        result["part"] = words[2]
        result["vendor"] = words[3]
        result["id"] = words[4]
        result["version"] = words[5]
        result["update"] = words[6]
        result["edition"] = words[7]
        result["language"] = words[8]
        result["sw_edition"] = words[9]
        result["target_sw"] = words[10]
        result["target_hw"] = words[11]
        result["other"] = words[12]
        result["versionStart"] = words[13]
        result["versionEnd"] = words[14]
        result["type"] = "CPE"
        result["prop"] = "Platform"
        result["url"] = cpe
        return result

    def traverse(self, cves):
        # KURO
        # df = pd.DataFrame(columns=['id', 'des'])
        # product = set()
        # df = pd.DataFrame(columns=['product'])

        for path in cves:
            with open(path, 'r', encoding='utf-8') as f:
                items = json.load(f)
            items = items['CVE_Items']
            items = tqdm(items)
            for cur in items:
                cve = cur['cve']
                src = cve['CVE_data_meta']['ID']
                items.set_postfix(CVE=src)
                # print(src)
                des = cve['description']['description_data'][0]['value']
                if ("** REJECT **" not in des):
                    # df.loc[len(df.index)] = [src, des]
                    # CVSS
                    cvss = cur['impact']
                    cvss2 = "None"
                    cvss3 = "None"
                    # baseMetricV2
                    if ('baseMetricV2' in cvss):
                        cvss2 = json.dumps(cvss['baseMetricV2'])
                    # baseMetricV3
                    if ('baseMetricV3' in cvss):
                        cvss3 = json.dumps(cvss['baseMetricV3'])
                    node = {'id': src,
                            'type': "CVE",
                            'prop': self.type,
                            'des': des,
                            'baseMetricV2': cvss2,
                            'baseMetricV3': cvss3,
                            'complete': json.dumps(cve)}
                    cve_id = self.ds.addNode(node)
                    self.rs.saveNodeId(src, cve_id)
                    

                    # Find related CWE
                    cwes = cve['problemtype']['problemtype_data'][0]['description']
                    for cwe in cwes:
                        cwe = cwe['value']
                        if cwe != "NVD-CWE-noinfo" and cwe != "NVD-CWE-Other":
                            # dest = self.rs.getNode(cwe)
                            self.rs.saveRDF(cwe, src, "observed_example")

                    # Find CPE
                    if 'configurations' in cur and 'nodes' in cur['configurations']:
                        cpe = cur['configurations']['nodes']
                        cpe_uri = self.get_cpe(cpe, [])
                        summary = self.cpe_summary(cpe_uri)
                        for product in summary:
                            if not self.rs.checkNode(summary[product]['uri']):
                                cpe_id = self.ds.addNode(summary[product])
                                self.rs.saveNodeId(summary[product]['uri'], cpe_id)
                                
                            self.rs.saveRDF(src, summary[product]['uri'], "has_platform")
                        # for uri in cpe_uri:
                        #     res = self._cpe_processor(uri)
                        #     # product.add(res['product'])
                        #     if not self.rs.checkNode(uri):
                        #         cpe_id = self.ds.addNode(res)
                        #         self.rs.saveNodeId(uri, cpe_id)
                                
                        #     self.rs.saveRDF(src, uri, "has_platform")
        # df['product'] = list(product)
        # df.to_csv('data/CVE/product.csv', index=False)
        # df.to_csv('myData/learning/CVE2CAPEC/cve.csv', index=False)
if __name__ == '__main__':
    cves = [
        'data/CVE/CVE-2002.json', 'data/CVE/CVE-2003.json', 'data/CVE/CVE-2004.json',
        'data/CVE/CVE-2005.json', 'data/CVE/CVE-2006.json', 'data/CVE/CVE-2007.json',
        'data/CVE/CVE-2008.json', 'data/CVE/CVE-2009.json', 'data/CVE/CVE-2010.json',
        'data/CVE/CVE-2011.json', 'data/CVE/CVE-2012.json', 'data/CVE/CVE-2013.json',
        'data/CVE/CVE-2014.json', 'data/CVE/CVE-2015.json', 'data/CVE/CVE-2016.json',
        'data/CVE/CVE-2017.json', 'data/CVE/CVE-2018.json', 'data/CVE/CVE-2019.json',
        'data/CVE/CVE-2020.json', 'data/CVE/CVE-2021.json', ]
    cvet = CVETraverser(cves)
    cvet.traverse()



