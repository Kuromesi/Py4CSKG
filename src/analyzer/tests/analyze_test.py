import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

from TextSimilarity.cve2capec import *
from TextClassification.cve2cwe import *
from analyzer.analyze import *

def cve2capecFactory():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    return TextSimilarity(df, weight_path='./data/embeddings/capec_embedding.npy')


if __name__ == '__main__':
    cve2cwe = CVE2CWE()
    cve2cwe.init_bert()
    cve2capec = cve2capecFactory()
    ma = ModelAnalyzer(cve2capec, cve2cwe)
    vul_report = ma.vul_find("cisco secure access control system", "0")
    ma.vul_analyze(vul_report)