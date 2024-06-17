import re, json
from ontologies.constants import *

regs = [re.compile(r".*gain.*privilege.*"), 
             re.compile(r".*escalat.*"), 
             re.compile(r".*(obtain|gain|as).*(user|administra|root).*"),
             re.compile(r".*hijack.*authenticat.*"),
             re.compile(r".*(create|modify|append|read).*arbitrary.*"),
             re.compile(r".*execut.*"),
             re.compile(r".*takeover.*")]

def convert_cve_to_atomic_attack(cve_id, cve_des, cvss_v2, cvss_v3):
    access = ""
    gain = get_privilege_level(cve_des, cvss_v2, cvss_v3)
    score = 0.0
    if cvss_v3 is not None:
        access = cvss_v3['attackVector']
        score = cvss_v3['impactScore']
    elif cvss_v2 is not None:
        access = cvss_v2['accessVector']
        score = cvss_v2['impactScore']
    else:
        raise Exception("Neither cvss2 nor cvss3 exists")

    return AtomicAttack(cve_id, access, gain, score, "None")
        
def get_privilege_level(description, cvss_v2=None, cvss_v3=None):
    cved_impact = []
    if is_code_exec(description):
        cved_impact.append(CODE_EXEC_CVED)
    if is_gain_privileges(description):
        cved_impact.append(GAIN_PRIV_CVED)

    vul_type = get_vul_type(cvss2=cvss_v2, cvss3=cvss_v3, impact=cved_impact)      
    return vul_type
        
def is_code_exec(text) -> bool:
    if "execution" in text.lower() or "execute" in text.lower():
        return True
    return False

def is_gain_privileges(text) -> bool:
    text = text.lower()
    for reg in regs:
        if reg.match(text):
            return True
    return False

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

def get_vul_type(cvss2=None, cvss3=None, impact=[]):
    impact = [i.lower() for i in impact]
    if cvss2:
        if cvss2["obtainUserPrivilege"]:
            return PRIV_USER
        if cvss2["obtainAllPrivilege"]:
            return PRIV_ROOT
        if cvss2["obtainOtherPrivilege"]:
            return PRIV_APP
        
        # cvss2 = cvss2['cvssV2']

        if cvss2["confidentialityImpact"] == "NONE" or cvss2["integrityImpact"] == "NONE" or cvss2["availabilityImpact"] == "NONE":
            return CIA_LOSS
        elif cvss2["confidentialityImpact"] == "COMPLETE" and cvss2["integrityImpact"] == "COMPLETE" and cvss2["availabilityImpact"] == "COMPLETE":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return PRIV_ROOT
        else:
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return PRIV_USER
    
    elif cvss3:
        # cvss3 = cvss3['cvssV3']
        if cvss3["confidentialityImpact"] == "HIGH" and cvss3["integrityImpact"] == "HIGH" and cvss3["availabilityImpact"] == "HIGH":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                # if cvss3["baseSeverity"] == "CRITICAL":
                #     return PRIV_ROOT
                # else:
                return PRIV_USER
        elif GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
            return PRIV_APP
        else:
            return CIA_LOSS
    else:
        raise ValueError("neither CVSSv2 nor CVSSv3 exists")

    return CIA_LOSS

class CVEEntry():
    id: str
    score: float
    access: str
    impact: str
    description: str
    def __init__(self, record=None) -> None:
        self.parse_record(record)
    
    def parse_record(self, record):
        if not record:
            self.score = 1.0
            return
        self.id = record['id']
        self.description = record['description']
        cvss2 = json.loads(record['baseMetricV2'])
        cvss3 = json.loads(record['baseMetricV3'])
        self.impact = get_privilege_level(self.description, cvss2, cvss3)
        if record['baseMetricV2'] != "{}" and record['baseMetricV3'] != "{}":
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            cvss3 = json.loads(record['baseMetricV3'])
            self.privileges_required = PRIV_REQ_MAP[cvss3['cvssV3']['privilegesRequired']]
            self.effect = self.impact
        elif record['baseMetricV2'] != "{}":
            cvss2 = json.loads(record['baseMetricV2'])
            self.access = cvss2['cvssV2']['accessVector']
            self.score = cvss2['cvssV2']['baseScore']
            if cvss2['cvssV2']['authentication'] == "Single" or cvss2['cvssV2']['authentication'] == "Multiple":
                self.privileges_required = "Low"
            else:
                self.privileges_required = "None"
        elif record['baseMetricV3'] != "{}":
            cvss3 = json.loads(record['baseMetricV3'])
            self.access = cvss3['cvssV3']['attackVector']
            self.score = cvss3['cvssV3']['baseScore']
            self.privileges_required = PRIV_REQ_MAP[cvss3['cvssV3']['privilegesRequired']]
        else:
            raise ValueError("neither CVSSv2 nor CVSSv3 exists")