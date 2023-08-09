import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

# from TextSimilarity.TextSimilarity import *
# from TextClassification.cve2cwe import *
# from analyzer.bk.analyze import *
from analyzer.tests.tests import gen_test_graph
from analyzer.analyze import ModelAnalyzer
from service.GDBSaver import GDBSaver

def cve2capecFactory():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    return TextSimilarity(df, weight_path='./data/embeddings/capec_embedding.npy')

def vul_analyze_test():
    cve2cwe = CVE2CWE()
    cve2cwe.init_bert()
    cve2capec = cve2capecFactory()
    ma = ModelAnalyzer(cve2capec, cve2cwe)
    vul_report = ma.vul_find("cisco secure access control system", "0")
    ma.vul_analyze(vul_report)
    
def analyze_test():
    cve2cwe = None
    cve2capec = None
    ma = ModelAnalyzer(cve2capec, cve2cwe)
    with open('src/webapp/data/Demonstration_new/graph.json', 'r') as f:
        graph = json.load(f)
    ma.convert_pyvis(graph)
    ma.analyze()

def analyzer_test():
    graph = gen_test_graph()
    gs = GDBSaver()
    ma = ModelAnalyzer(gs, graph)
    ma.find_attack_path("web server", "database server", graph, ma.vul_graph)



if __name__ == '__main__':
    analyzer_test()