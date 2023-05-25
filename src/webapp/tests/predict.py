from utils.prediction import *

text = "Buffer overflow in sccw allows local users to gain root access via the HOME environmental variable."
# cve2capec.calculate_similarity(text)

cve2cwe = CVE2CWE()
cve2cwe.predict(text)