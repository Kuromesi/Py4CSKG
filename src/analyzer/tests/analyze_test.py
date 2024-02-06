import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))

# from TextSimilarity.TextSimilarity import *
# from TextClassification.cve2cwe import *
# from analyzer.bk.analyze import *
from analyzer.tests.tests import gen_test_graph
# from analyzer.analyze import *
# from analyzer.graph.GraphAdapter import GraphProcessor
from analyzer.analyzer import ModelAnalyzer
from analyzer.ontologies.ontology import AtomicAttack
from knowledge_graph.Ontology.CVE import *
from service.GDBSaver import GDBSaver
import networkx as nx
from analyzer.utils.random_graph import gen_random_network
import resource, time, random
import matplotlib.pyplot as plt
from analyzer.tests.vul_env_graph import vul_env
import numpy as np
from memory_profiler import profile

def measure_resources(func):
   def wrapper(*args, **kwargs):
       # 获取进程的内存使用情况
       rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

       # 获取进程的 CPU 使用情况
       cpu_time_before = resource.getrusage(resource.RUSAGE_SELF).ru_utime

       # 调用原始函数
       result = func(*args, **kwargs)

       # 获取进程的内存使用情况
       rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

       # 获取进程的 CPU 使用情况
       cpu_time_after = resource.getrusage(resource.RUSAGE_SELF).ru_utime

       # 计算内存使用增量
       rss_diff = rss_after - rss_before

       # 计算 CPU 使用增量
       cpu_diff = cpu_time_after - cpu_time_before

       print("Memory usage:", rss_diff, "bytes")
       print("CPU usage:", cpu_diff, "seconds")

       return result

   return wrapper

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
    gp = GraphProcessor()
    graph = gp.convert_pyvis("src/webapp/data/stuxnet_cve/graph.json")['graph']
    gs = GDBSaver()
    ma = ModelAnalyzer(gs, graph)
    ma.find_attack_path("employee workstation", "engineering workstation", graph, ma.vul_graph)

def build_cve_tree_test():
    gdb = GDBSaver()
    # query = "MATCH(n:Vulnerability) RETURN n ORDER BY rand() LIMIT 10"
    query = "MATCH (n:Vulnerability) WHERE n.id='CVE-2013-7172' or n.id='CVE-2012-0931' RETURN n"
    cves = gdb.sendQuery(query)
    cve_entries: list[CVEEntry] = []
    for cve in cves:
        cve_entries.append(CVEEntry(cve[0]))
    cve_tree = CVETree(cve_entries)

def test_new_analyzer():
    model = nx.DiGraph()
    node1 = ("workstation", {
        "os": [],
        "firmware": [],
        "software": [],
        "hardware": [],
        "atomic": [{
            "access": ACCESS_NETWORK,
            "name": "test_vul",
            "gain": PRIV_USER,
            "score": 10.0,
            "require": "None"
        }]
    })
    node2 = ("server", {
        "os": [],
        "firmware": [],
        "software": [],
        "hardware": [],
        "atomic": [{
            "access": ACCESS_NETWORK,
            "name": "test_vul",
            "gain": PRIV_USER,
            "score": 10.0,
            "require": "None"
        }]
    })
    node3 = ("database", {
        "os": [],
        "firmware": [],
        "software": [],
        "hardware": [],
        "atomic": [{
            "access": ACCESS_NETWORK,
            "name": "test_vul",
            "gain": PRIV_USER,
            "score": 10.0,
            "require": "None"
        }]
    })
    model.add_edges_from([(node1[0], node2[0], {"transitions": [], "access": ACCESS_NETWORK}), 
                          (node2[0], node3[0], {"transitions": [], "access": ACCESS_NETWORK})])
    model.add_nodes_from([node1, node2, node3])
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml")
    ma.analyze(model)

def test_attack_graph_performance(ma: ModelAnalyzer, model: nx.DiGraph, src: str, dst: str):
    ma.analyze(model)
    # ma.analyze_attack_path(model, src, dst)

def test_attack_path_performance(ma: ModelAnalyzer, model: nx.DiGraph, src: str, dst: str):
    ma.analyze_attack_path(model, src, dst)

def test_random_graph():
    samplings = [100, 1000, 3000, 5000, 7000, 9000, 11000, 13000, 15000, 17000, 19000, 20000]
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml")
    time_result = []
    memory_result = []
    avg_num = 10
    for sampling in samplings:
        model = gen_random_network(1, sampling)
        vul_graph = ma.analyze(model)
        tmp_time_result = []
        for i in range(avg_num):
            flag = True
            while flag:
                src = f"{random.randint(0, (len(model.nodes)) / 4 - 1)}:root"
                dst = f"{random.randint(3 * (len(model.nodes)) / 4, len(model.nodes) - 1)}:none"
                if nx.has_path(vul_graph, src, dst):
                    flag = False
                    while dst == src:
                        dst = random.randint(0, len(model.nodes))
                    start_time = time.time()
                    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                    test_attack_graph_performance(ma, model, src, dst)
                    # test_attack_path_performance(ma, vul_graph, src, dst)
                    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                    rss_diff = rss_after - rss_before
                    end_time = time.time()
            tmp_time_result.append(end_time - start_time)
        time_result.append(sum(tmp_time_result) / avg_num)
        # time_result.append(max(tmp_time_result))
        memory_result.append(rss_diff)
    print(time_result)
    print(memory_result)
    plt.figure(figsize=(8, 6))
    plt.plot(samplings, time_result, marker='o', linestyle='-', color='b')
    # plt.xscale('log')  # 对横坐标进行对数变换
    plt.xlabel('Network Nodes')
    plt.ylabel('Running Time (s)')
    plt.title('Running Time vs Network Nodes')
    plt.grid(True)
    plt.tight_layout()
    plt.show()
    # [0.00020833492279052736, 0.0005552053451538086, 0.0010239458084106445, 0.0017614078521728516, 0.001987881660461426, 0.0025138378143310545, 0.004114799499511719, 0.003915176391601562, 0.005895490646362305, 0.009697232246398926, 0.008445324897766114, 0.00933931827545166]
    # [0.00015374422073364258, 0.0005534052848815918, 0.0009964418411254883, 0.0019069242477416993, 0.002433798313140869, 0.0028776073455810546, 0.003753204345703125, 0.00403771162033081, 0.004932050704956055, 0.007560615539550781, 0.009774432182312012, 0.008056378364562989]

def generate_layout(model: nx.DiGraph, status: nx.DiGraph, ma: ModelAnalyzer, seed: int=1) -> dict[str, np.ndarray]:
    pos = nx.spring_layout(model, seed=seed)
    distance = 0.035
    status_pos = {}
    properties = ma.rules.properties
    for node, node_pos in pos.items():
        node_root = f"{node}:root"
        node_user = f"{node}:user"
        node_access = f"{node}:access"
        node_none = f"{node}:none"

        root_pos = np.array([node_pos[0], node_pos[1] + distance / 2])
        user_pos = np.array([node_pos[0] - distance, node_pos[1]])
        access_pos = np.array([node_pos[0] - 2 * distance, node_pos[1] - distance])
        none_pos = np.array([node_pos[0] - 2 * distance, node_pos[1] + distance])

        status_pos[node_root] = root_pos
        status_pos[node_user] = user_pos
        status_pos[node_access] = access_pos
        status_pos[node_none] = none_pos

    return status_pos


def test_vul_env():
    ma = ModelAnalyzer("src/analyzer/rules/experiment/rule.yaml")
    model = ma.analyze(vul_env)
    pos = generate_layout(vul_env, model, ma, 4)
    plt.figure(figsize=(26, 20))
    nx.draw(model, with_labels=True, pos=pos, node_color="#8adacf", font_size=15, font_family="Times New Roman", font_weight="bold")
    plt.margins(0, 0)
    plt.savefig(f"src/analyzer/tests/vul_env.png", dpi=200, bbox_inches='tight')
    # plt.show()
    # ma.analyze_attack_path(model, "internet:access", "mysql:none", "score")
    # ma.analyze_attack_path(model, "internet:access", "mysql:none", "weight")
    # ma.analyze_attack_path(model, "internet:access", "workstation:root", "score")
    # ma.analyze_attack_path(model, "internet:access", "workstation:root", "weight")
    # ma.analyze_attack_path(model, "internet:access", "mail_server:user", "score")
    # ma.analyze_attack_path(model, "internet:access", "mail_server:user", "weight")
    ma.analyze_attack_path(model, "internet:access", "neo4j:none", "score")
    ma.analyze_attack_path(model, "internet:access", "neo4j:none", "weight")
    
if __name__ == '__main__':
    test_vul_env()
    # test_random_graph()