import json
import pandas as pd
# from service.GDBSaver import GDBSaver
# from service.RDBSaver import RDBSaver

class CVETraverser():
    def __init__(self, cves) -> None:
        # self.ds = GDBSaver()
        # self.rs = RDBSaver()
        self.cves = cves
        self.type = "Vulnerability"

    def find_kv(self):
        pass

    def get_cpe(self, nodes, results):
        cpe23uri = ""
        for node in nodes:
            operator = node['operator']
            if operator is "AND":
                if 'children' in node:
                    results = self.get_cpe(node['children'], results)
            else:
                cpe_match = node['cpe_match']
                for cpe in cpe_match:
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
        return results

    def cpe_processor(cpe):
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

    def traverse(self):
        # KURO
        # df = pd.DataFrame(columns=['id', 'des'])

        for path in self.cves:
            with open(path, 'r', encoding='utf-8') as f:
                items = json.load(f)
            items = items['CVE_Items']
            for cur in items:
                cve = cur['cve']
                src = cve['CVE_data_meta']['ID']
                print(src)
                des = cve['description']['description_data'][0]['value']
                if ("** REJECT **" not in des):
                    df.loc[len(df.index)] = [src, des]
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
                            'baseMetricV3': cvss3}
                    # self.ds.addNode(node)

                    # Find related CWE
                    cwes = cve['problemtype']['problemtype_data'][0]['description']
                    for cwe in cwes:
                        cwe = cwe['value']
                        # if cwe is not "NVD-CWE-noinfo" and cwe is not "NVD-CWE-Other":
                            # dest = self.rs.getNode(cwe)
                            # self.rs.saveRDF(cwe, src, "observed_example")

                    # Find CPE
                    if 'configurations' in cur and 'nodes' in cur['configurations']:
                        cpe = cur['configurations']['nodes']
                        cpe_uri = self.get_cpe(cpe, [])
                        # for uri in cpe_uri:
                            # if not self.rs.checkNode(uri):
                            #     self.ds.addNode(self.cpe_processor(uri))
                            # self.rs.saveRDF(src, uri, "has_platform")
        df.to_csv('myData/learning/CVE2CAPEC/cve.csv', index=False)
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



