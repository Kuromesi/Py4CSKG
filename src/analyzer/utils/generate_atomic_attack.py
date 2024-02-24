import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from ontologies.modeling import AtomicAttack
from ontologies.constants import *
from ontologies.cve import CVEEntry
from service import gdb
import requests, re, json
from utils.Logger import logger

regs = [re.compile(r".*gain.*privilege.*"), 
             re.compile(r".*escalat.*"), 
             re.compile(r".*(obtain|gain|as).*(user|administra|root).*"),
             re.compile(r".*hijack.*authenticat.*"),
             re.compile(r".*(create|modify|append|read).*arbitrary.*"),
             re.compile(r".*execut.*"),
             re.compile(r".*takeover.*"),
             re.compile(r".*(command|code).*inject.*"),
             re.compile(r".*inject.*(code|command).*"),]

def convert_cve_to_atomic_attack(cve_id):
    success, cve_des, access, cvss_v2, cvss_v3 = get_cve_data(cve_id)
    if not success:
        return AtomicAttack(cve_id, ACCESS_NETWORK, CIA_LOSS, 1.0, "None")
    gain = get_privilege_level(cve_des, cvss_v2, cvss_v3)
    score = 0.0
    if cvss_v3 is not None:
        access = cvss_v3['cvssV3']['attackVector']
        score = cvss_v3['impactScore']
    elif cvss_v2 is not None:
        access = cvss_v2['cvssV2']['accessVector']
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

def get_vul_type(cvss2=None, cvss3=None, impact=[]):
    impact = [i.lower() for i in impact]
    if cvss2:
        if cvss2["obtainUserPrivilege"]:
            return PRIV_USER
        if cvss2["obtainAllPrivilege"]:
            return PRIV_ROOT
        if cvss2["obtainOtherPrivilege"]:
            return CIA_LOSS
        
        cvss2 = cvss2['cvssV2']

        if cvss2["confidentialityImpact"] == "NONE" or cvss2["integrityImpact"] == "NONE" or cvss2["availabilityImpact"] == "NONE":
            return CIA_LOSS
        elif cvss2["confidentialityImpact"] == "COMPLETE" and cvss2["integrityImpact"] == "COMPLETE" and cvss2["availabilityImpact"] == "COMPLETE":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return PRIV_ROOT
        else:
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                return PRIV_USER
    
    elif cvss3:
        cvss3 = cvss3['cvssV3']
        if cvss3["confidentialityImpact"] == "HIGH" and cvss3["integrityImpact"] == "HIGH" and cvss3["availabilityImpact"] == "HIGH":
            if GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
                # if cvss3["baseSeverity"] == "CRITICAL":
                #     return PRIV_ROOT
                # else:
                return PRIV_USER
        elif GAIN_PRIV_CVED in impact or CODE_EXEC_CVED in impact:
            return CIA_LOSS
        else:
            return CIA_LOSS
    else:
        raise ValueError("neither CVSSv2 nor CVSSv3 exists")

    return CIA_LOSS

def get_cve_data(cve_id):
    logger.info(f"getting cve data: {cve_id}")
    query = f"MATCH (n:Vulnerability) WHERE n.id=\"{cve_id}\" RETURN n"
    nodes = gdb.sendQuery(query)
    if not nodes:
        logger.warning(f"{cve_id} is not recorded")
        return False, "", "", None, None
    des = nodes[0][0]['description']
    cvss3, cvss2 = None, None
    access = ""
    if  nodes[0][0]['baseMetricV3'] != "{}":
        cvss3 = json.loads(nodes[0][0]['baseMetricV3'])
        access = cvss3['cvssV3']['attackVector']
    if nodes[0][0]['baseMetricV2'] != "{}":
        cvss2 = json.loads(nodes[0][0]['baseMetricV2'])
        if not access:
            access = cvss2['cvssV2']['accessVector']
    if cvss2 or cvss3:
        return True, des, access, cvss2, cvss3
    logger.warning(f"neither cvss2 nor cvss3 exists: {cve_id}")
    return False, "", "", None, None

def get_cve_data_from_api(cve_id):
    success = False
    cve_data = request_cve_api(cve_id)
    if cve_data is None:
        return success, "", "", None, None
    success = True
    access = ""
    cve_des = cve_data['descriptions'][0]['value']
    cvss_v2, cvss_v3 = None, None
    if 'cvssMetricV31' in cve_data['metrics']:
        key = 'cvssMetricV31'
    elif 'cvssMetricV30' in cve_data['metrics']:
        key = 'cvssMetricV30'
    if len(cve_data['metrics'][key]) > 0:
        cvss_v3 = cve_data['metrics'][key][0]
        cvss_v3['cvssV3'] = cvss_v3['cvssData']
        del cvss_v3['cvssData']
    if len(cve_data['metrics']['cvssMetricV2']) > 0:
        cvss_v2 = cve_data['metrics']['cvssMetricV2'][0]
        cvss_v2['cvssV2'] = cvss_v2['cvssData']
        del cvss_v2['cvssData']
    return success, cve_des, access, cvss_v2, cvss_v3 

def request_cve_api(cve_id):
    try:
        res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        res = res.json()
        if len(res['vulnerabilities']) > 0:
            cve_data = res['vulnerabilities'][0]['cve']
            return cve_data
        else: return None
    except Exception as e:
        print(e)
        return None
if __name__ == "__main__":
    get_cve_data("CVE-2022-0001")