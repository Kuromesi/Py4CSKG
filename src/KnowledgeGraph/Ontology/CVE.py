import json

# constants
ACCESS_LOCAL = "LOCAL"
ACCESS_NETWORK = "NETWORK"
ACCESS_ADJACENT = "ADJACENT_NETWORK"

CIA_LOSS = "system cia loss"
APP_EXEC = "application arbitrary code execution"
SYS_EXEC = "system arbitrary code execution"
APP_PRIV = "gain privilege on application"
PRIV_ESC = "privilege escalation"
USER_PRIV = "gain user privilege"
ROOT_PRIV = "gain root privilege"
PRIV_UND = "component privilege based privilege"
EXEC_UND = "component privilege based execution"

CODE_EXEC_CVED = "code execution"
GAIN_PRIV_CVED = "privilege escalation"

IMPACT_ORDER = ["system CIA loss", "gain privilege on application", "application arbitrary code execution", "system arbitrary code execution", 
                "gain user privilege", "privilege escalation", "gain root privilege"]

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

def get_vul_type(entry):
    cvss2 = entry.cvss2
    cvss3 = entry.cvss3
    vul_types = []
    effect = ""
    if cvss2 and cvss3:
        if cvss2["confidentialityImpact"] == "Low" and cvss2["integrityImpact"] == "Low" and cvss2["availabilityImpact"] == "Low":
            if GAIN_PRIV_CVED in vul_types:
                effect = USER_PRIV if cvss2["obtainUserPrivilege"] else APP_PRIV
            elif CODE_EXEC_CVED in vul_types:
                effect = APP_EXEC
        elif cvss2["confidentialityImpact"] == "High" and cvss2["integrityImpact"] == "High" and cvss2["availabilityImpact"] == "High":
            if GAIN_PRIV_CVED in vul_types:
                effect = ROOT_PRIV if cvss3['cvssV3']['privilegesRequired'] == "None" else PRIV_ESC
            elif CODE_EXEC_CVED in vul_types:
                effect = SYS_EXEC
            else:
                effect = CIA_LOSS
        else:
            effect = CIA_LOSS

    elif cvss2:
        if cvss2["confidentialityImpact"] == "Low" and cvss2["integrityImpact"] == "Low" and cvss2["availabilityImpact"] == "Low":
            if GAIN_PRIV_CVED in vul_types:
                effect = USER_PRIV if cvss2["obtainUserPrivilege"] else APP_PRIV
            elif CODE_EXEC_CVED in vul_types:
                effect = APP_EXEC
            else:
                effect = CIA_LOSS
        elif cvss2["confidentialityImpact"] == "High" and cvss2["integrityImpact"] == "High" and cvss2["availabilityImpact"] == "High":
            if GAIN_PRIV_CVED in vul_types:
                effect = ROOT_PRIV if cvss3['cvssV2']['authentication'] == "None" else PRIV_ESC # differ from both cvss2 and cvss3 exists state
            elif CODE_EXEC_CVED in vul_types:
                effect = SYS_EXEC
            else:
                effect = CIA_LOSS
        else:
            effect = CIA_LOSS
    
    elif cvss3:
        if cvss3["confidentialityImpact"] == "High" and cvss3["integrityImpact"] == "High" and cvss3["availabilityImpact"] == "High":
            if GAIN_PRIV_CVED in vul_types:
                effect = PRIV_UND if cvss3['cvssV3']['privilegesRequired'] == "None" else PRIV_ESC
            elif CODE_EXEC_CVED in vul_types:
                effect = EXEC_UND
            else:
                effect = CIA_LOSS
        else:
            effect = CIA_LOSS

    else:
        raise ValueError("neither CVSSv2 nor CVSSv3 exists")

class CVEEntry():
    def __init__(self, record) -> None:
        self.id = record['id']
        self.impact = record['type']
        if cvss2 and cvss3:
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            cvss3 = json.loads(record['baseMetricV3'])
            self.privileges_required = cvss3['cvssV3']['privilegesRequired']
        elif cvss2:
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            if cvss2['cvssV3']['authentication'] is "Single" or cvss2['cvssV3']['authentication'] is "Multiple":
                self.privileges_required = "Low"
            else:
                self.privileges_required = "None"
        elif cvss3:
            cvss3 = json.loads(record['baseMetricV3'])
            self.access = cvss3['cvssV3']['accessVector']
            self.score = cvss3['cvssV3']['baseScore']
            self.privileges_required = cvss3['cvssV3']['privilegesRequired']
        else:
            raise ValueError("neither CVSSv2 nor CVSSv3 exists")