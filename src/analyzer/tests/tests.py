import networkx as nx

def gen_test_graph():
    # 创建一个有向图
    G = nx.DiGraph()
    node_1 = ("web server", 
              {
                  "os": [],
                  "firmware": [],
                  "software": [("yxcms_yxcms", "1.4.7", "network", "user"), ("phpmyadmin_phpmyadmin", "4.8.3", "network", "user")],
                  "entry": []
               })
    node_2 = ("domain controller", 
              {
                  "os": [("microsoft_windows_server_2008", "r2", "local")],
                  "firmware": [],
                  "software": [("microsoft_internet_information_services", "7.0", "adjacent", "root")],
                  "entry": ["shared folder"]
              })
    node_3 = ("domain member", 
              {
                  "os": [],
                  "firmware": [],
                  "software": [("microsoft_server_message_block", "1.0", "adjacent", "user")],
                  "entry": []
              })
    node_4 = ("database server", 
              {
                  "os": [("microsoft_windows_server_2008", "r2", "local")],
                  "firmware": [], 
                  "software": [("oracle_database_server", "10.2.0.3", "adjacent", "user")],
                  "entry": []
              })
    node_5 = ("domain member2", 
              {
                  "os": [("microsoft_windows_server_2008", "r2", "local")],
                  "firmware": [],
                  "software": [],
                  "entry": []
              })
    nodes = [
        node_1, node_2, node_3, node_4, node_5
    ]
    G.add_nodes_from(nodes)

    # 添加边
    G.add_edge("web server", "domain controller")
    G.add_edge("domain controller", "web server")
    G.add_edge("domain member", "domain controller")
    G.add_edge("domain controller", "domain member")
    G.add_edge("domain member", "database server")
    G.add_edge("database server", "domain member")
    G.add_edge("database server", "domain member2")
    G.add_edge("domain member2", "database server")
    G.add_edge("domain member2", "domain controller")
    G.add_edge("domain controller", "domain member2")
    
    return G