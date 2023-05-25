import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'src'))

from TextClassification.cve2cwe import *

if __name__ == '__main__':
    cve2cwe = CVE2CWE()
    cve2cwe.init_bert()
    text = "The com_rss option (rss.php) in (1) Mambo and (2) Joomla! allows remote attackers to cause a denial of service (disk consumption and possibly web-server outage) via multiple requests with different values of the feed parameter."
    cve2cwe.bert_predict(text)