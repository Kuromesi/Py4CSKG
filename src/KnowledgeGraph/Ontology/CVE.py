import json

IMPACT_ORDER = ["System CIA loss", "Application arbitrary code execution", "System arbitrary code execution", 
                "Gain user privilege", "Privilege escalation", "Gain root privilege"]
def cmp_cve(a, b):
    if IMPACT_ORDER.index(a.impact) > IMPACT_ORDER.index(b.impact):
        return 1
    elif IMPACT_ORDER.index(a.impact) == IMPACT_ORDER.index(b.impact):
        a_score = a.exploit_score + a.impact_score
        b_score = b.exploit_score + b.impact_score
        if a_score > b_score: return 1
        elif a_score == b_score: return 0
        else: return -1

def get_max_pos_entries(entries):
        res = {}
        for entry in entries:
            access = entry.access
            priv_req = entry.privileges_required
            if access in res:
                if priv_req in res[access]:
                    if cmp_cve(entry, res[access][priv_req]) > 0:
                        res[access][priv_req] = entry
                else:
                    res[access][priv_req] = entry
            else:
                res[access] = {}
                res[access][priv_req] = entry
        return res

class CVEEntry():
    def __init__(self, record) -> None:
        self.impact = record['type']
        if cvss2:
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.exploit_score = cvss2['exploitabilityScore']
            self.impact_score = cvss2['impactScore']
            if cvss2['cvssV3']['authentication'] is "Single" or cvss2['cvssV3']['authentication'] is "Multiple":
                self.privileges_required = "Low"
            else:
                self.privileges_required = "None"

        if cvss3:
            cvss3 = json.loads(record['baseMetricV3'])
            self.privileges_required = cvss3['cvssV3']['privilegesRequired']