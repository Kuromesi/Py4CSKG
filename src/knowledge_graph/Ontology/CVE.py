import json

# constants
ACCESS_PHYSICAL = "PHYSICAL"
ACCESS_LOCAL = "LOCAL"
ACCESS_ADJACENT = "ADJACENT_NETWORK"
ACCESS_NETWORK = "NETWORK"

CIA_LOSS = "system cia loss"
APP_PRIV = "gain privilege on application"
USER_PRIV = "gain user privilege"
ROOT_PRIV = "gain root privilege"

APP_EXEC = "application arbitrary code execution"
SYS_EXEC = "system arbitrary code execution"
PRIV_ESC = "privilege escalation"
PRIV_UND = "component privilege based privilege"
EXEC_UND = "component privilege based execution"

CODE_EXEC_CVED = "code execution"
GAIN_PRIV_CVED = "privilege escalation"

IMPACT_ORDER = ["system CIA loss", "gain privilege on application", "application arbitrary code execution", "system arbitrary code execution", 
                "gain user privilege", "privilege escalation", "gain root privilege"]

ACCESS_ORDER = [ACCESS_PHYSICAL, ACCESS_LOCAL, ACCESS_ADJACENT, ACCESS_NETWORK]
IMPACT_ORDER = []

def cmp_access(a, b):
    if a not in ACCESS_ORDER or b not in ACCESS_ORDER:
        raise ValueError(f"{a} or {b} not in default access types") 
    if ACCESS_ORDER.index(a) > ACCESS_ORDER.index(b):
        return 1
    elif ACCESS_ORDER.index(a) == ACCESS_ORDER.index(b):
        return 0
    else:
        return -1

def cmp_impact(a, b):
    if IMPACT_ORDER.index(a) > IMPACT_ORDER.index(b):
        return 1
    elif IMPACT_ORDER.index(a) == IMPACT_ORDER.index(b):
        return 0
    else:
        return -1

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

def get_vul_type(cvss2=None, cvss3=None, impact=[]):
    impact = [i.lower() for i in impact]
    if cvss2:
        if cvss2["obtainUserPrivilege"]:
            return USER_PRIV
        if cvss2["obtainAllPrivilege"]:
            return ROOT_PRIV
        if cvss2["obtainOtherPrivilege"]:
            return APP_PRIV
        
        cvss2 = cvss2['cvssV2']

        if cvss2["confidentialityImpact"] == "NONE" or cvss2["integrityImpact"] == "NONE" or cvss2["availabilityImpact"] == "NONE":
            return CIA_LOSS
        elif cvss2["confidentialityImpact"] == "COMPLETE" and cvss2["integrityImpact"] == "COMPLETE" and cvss2["availabilityImpact"] == "COMPLETE":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return ROOT_PRIV
        else:
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return USER_PRIV
    
    elif cvss3:
        cvss3 = cvss3['cvssV3']
        if cvss3["confidentialityImpact"] == "HIGH" and cvss3["integrityImpact"] == "HIGH" and cvss3["availabilityImpact"] == "HIGH":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                if cvss3["baseSeverity"] == "CRITICAL":
                    return ROOT_PRIV
                else:
                    return USER_PRIV
        elif GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
            return APP_PRIV
        else:
            return CIA_LOSS
    else:
        raise ValueError("neither CVSSv2 nor CVSSv3 exists")

    return CIA_LOSS

def _get_vul_type(cvss2, cvss3, impact):
    impact = [i.lower() for i in impact]
    effect = ""
    if cvss2 and cvss3:
        cvss2_full = cvss2
        cvss2 = cvss2['cvssV2']
        cvss3 = cvss3['cvssV3']
        if cvss2["confidentialityImpact"] == "PARTIAL" and cvss2["integrityImpact"] == "PARTIAL" and cvss2["availabilityImpact"] == "PARTIAL":
            if GAIN_PRIV_CVED in impact:
                effect = USER_PRIV if cvss2_full["obtainUserPrivilege"] else APP_PRIV
            elif CODE_EXEC_CVED in impact:
                effect = APP_EXEC
        elif cvss2["confidentialityImpact"] == "COMPLETE" and cvss2["integrityImpact"] == "COMPLETE" and cvss2["availabilityImpact"] == "COMPLETE":
            if GAIN_PRIV_CVED in impact:
                effect = ROOT_PRIV if cvss3['privilegesRequired'] == "NONE" else PRIV_ESC
            elif CODE_EXEC_CVED in impact:
                effect = SYS_EXEC
        else:
            effect = CIA_LOSS

    elif cvss2:
        cvss2_full = cvss2
        cvss2 = cvss2['cvssV2']
        if cvss2["confidentialityImpact"] == "PARTIAL" and cvss2["integrityImpact"] == "PARTIAL" and cvss2["availabilityImpact"] == "PARTIAL":
            if GAIN_PRIV_CVED in impact:
                effect = USER_PRIV if cvss2_full["obtainUserPrivilege"] else APP_PRIV
            elif CODE_EXEC_CVED in impact:
                effect = APP_EXEC
        elif cvss2["confidentialityImpact"] == "COMPLETE" and cvss2["integrityImpact"] == "COMPLETE" and cvss2["availabilityImpact"] == "COMPLETE":
            if GAIN_PRIV_CVED in impact:
                effect = ROOT_PRIV if cvss2['authentication'] == "NONE" else PRIV_ESC # differ from both cvss2 and cvss3 exists state
            elif CODE_EXEC_CVED in impact:
                effect = SYS_EXEC
        else:
            effect = CIA_LOSS
    
    elif cvss3:
        cvss3 = cvss3['cvssV3']
        if cvss3["confidentialityImpact"] == "HIGH" and cvss3["integrityImpact"] == "HIGH" and cvss3["availabilityImpact"] == "HIGH":
            if GAIN_PRIV_CVED in impact:
                effect = PRIV_UND if cvss3['privilegesRequired'] == "NONE" else PRIV_ESC
            elif CODE_EXEC_CVED in impact:
                effect = EXEC_UND
        else:
            effect = CIA_LOSS
    else:
        raise ValueError("neither CVSSv2 nor CVSSv3 exists")
    if not effect:
        effect = CIA_LOSS
    return effect

class CVEEntry():
    def __init__(self, record=None) -> None:
        if not record:
            self.score = 1
            return
        self.id = record['id']
        self.impact = record['impact']
        cvss2 = None
        cvss3 = None
        if 'baseMetricV2' in record and 'baseMetricV3' in record:
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            cvss3 = json.loads(record['baseMetricV3'])
            self.privileges_required = cvss3['cvssV3']['privilegesRequired']
            self.effect = get_vul_type(cvss2, cvss3, self.impact.split(", "))
        elif 'baseMetricV2' in record:
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            if cvss2['cvssV2']['authentication'] is "Single" or cvss2['cvssV2']['authentication'] is "Multiple":
                self.privileges_required = "Low"
            else:
                self.privileges_required = "None"
            self.effect = get_vul_type(cvss2, None, self.impact.split(", "))
        elif 'baseMetricV3' in record:
            cvss3 = json.loads(record['baseMetricV3'])
            self.access = cvss3['cvssV3']['attackVector']
            self.score = cvss3['cvssV3']['baseScore']
            self.privileges_required = cvss3['cvssV3']['privilegesRequired']
            self.effect = get_vul_type(None, cvss3, self.impact.split(", "))
        else:
            raise ValueError("neither CVSSv2 nor CVSSv3 exists")