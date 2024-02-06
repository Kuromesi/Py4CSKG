import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(BASE_DIR))


import networkx as nx
import matplotlib.pyplot as plt
from analyzer.ontologies.ontology import *
from knowledge_graph.Ontology.CVE import *

# servers
monitor = {
    "name": "monitor",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
database = {
    "name": "database",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
workstation = {
    "name": "workstation",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
ftp_server = {
    "name": "ftp_server",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
web_server = {
    "name": "web_server",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
mail_server = {
    "name": "mail_server",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}

# networks
work_zone = {
    "name": "work_zone",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
scada_zone = {
    "name": "scada_zone",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
dmz_zone = {
    "name": "dmz_zone",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
internet = {
    "name": "internet",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}

# products
ruby = {
    "name": "ruby",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2017-17405",
        "access": ACCESS_NETWORK,
        "gain": PRIV_ROOT,
        "require": "None",
        "score": 9.3
    },]
}

gitlab = {
    "name": "gitlab",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2016-9086",
        "access": ACCESS_NETWORK,
        "gain": CIA_LOSS,
        "require": "None",
        "score": 4.0
    },]
}
oracle = {
    "name": "oracle",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2023-21839",
        "access": ACCESS_NETWORK,
        "gain": CIA_LOSS,
        "require": "None",
        "score": 7.5
    },]
}
git_shell = {
    "name": "git-shell",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2017-8386",
        "access": ACCESS_NETWORK,
        "gain": PRIV_USER,
        "require": "None",
        "score": 6.5
    },]
}
opensmtpd = {
    "name": "opensmtpd",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2020-7247",
        "access": ACCESS_NETWORK,
        "gain": PRIV_ROOT,
        "require": "None",
        "score": 10.0
    },]
}
phpmailer = {
    "name": "phpmailer",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2017-5223",
        "access": ACCESS_LOCAL,
        "gain": CIA_LOSS,
        "require": "None",
        "score": 2.1
    },]
}
jenkins = {
    "name": "jenkins",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2017-1000353",
        "access": ACCESS_NETWORK,
        "gain": PRIV_USER,
        "require": "None",
        "score": 7.5
    },]
}
neo4j = {
    "name": "neo4j",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2021-34371",
        "access": ACCESS_NETWORK,
        "gain": PRIV_USER,
        "require": "None",
        "score": 7.5
    },]
}
openssh = {
    "name": "openssh",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2018-15473",
        "access": ACCESS_NETWORK,
        "gain": CIA_LOSS,
        "require": "None",
        "score": 5.0
    },]
}
polkit = {
    "name": "polkit",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2021-4034",
        "access": ACCESS_LOCAL,
        "gain": PRIV_ROOT,
        "require": "None",
        "score": 7.2
    },]
}
kibana = {
    "name": "kibana",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2018-17246",
        "access": ACCESS_NETWORK,
        "gain": PRIV_USER,
        "require": "None",
        "score": 7.5
    },]
}
phpmyadmin = {
    "name": "phpmyadmin",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2016-5734",
        "access": ACCESS_NETWORK,
        "gain": PRIV_USER,
        "require": "None",
        "score": 7.5
    },]
}
mysql = {
    "name": "mysql",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": [{
        "name": "CVE-2012-2122",
        "access": ACCESS_NETWORK,
        "gain": CIA_LOSS,
        "require": "None",
        "score": 5.1
    },]
}

# exposes
mail_expose = {
    "name": "mail_expose",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}
workstation_expose = {
    "name": "workstation_expose",
    "os": [],
    "software": [],
    "hardware": [],
    "firmware": [],
    "atomic_attacks": []
}

# edges
service_host_property = {"access": ACCESS_LOCAL, "transitions": ["user:access", "root:root"]}
host_service_property = {"access": ACCESS_LOCAL, "transitions": ["user:user", "root:root", "user:access"]}
expose_service_property = {"access": ACCESS_ADJACENT, "transitions": []}
zone_service_property = {"access": ACCESS_ADJACENT, "transitions": []}
zone_expose_property = {"access": ACCESS_ADJACENT, "transitions": ["access:access"]}
host_zone_property = {"access": ACCESS_ADJACENT, "transitions": ["access:access"]}
zone_zone_property = {"access": ACCESS_ADJACENT, "transitions": ["access:access"]}

edges = [
    (web_server["name"], oracle["name"], host_service_property), (oracle["name"], web_server["name"], service_host_property),
    (web_server["name"], gitlab["name"], host_service_property), (gitlab["name"], web_server["name"], service_host_property),
    (web_server["name"], git_shell["name"], host_service_property), (git_shell["name"], web_server["name"], service_host_property),
    (ftp_server["name"], ruby["name"], host_service_property), (ruby["name"], ftp_server["name"], service_host_property),
    (mail_server["name"], opensmtpd["name"], host_service_property), (opensmtpd["name"], mail_server["name"], service_host_property),
    (mail_server["name"], phpmailer["name"], host_service_property), (phpmailer["name"], mail_server["name"], service_host_property),
    (workstation["name"], jenkins["name"], host_service_property), (jenkins["name"], workstation["name"], service_host_property),
    (workstation["name"], openssh["name"], host_service_property), (openssh["name"], workstation["name"], service_host_property),
    (workstation["name"], neo4j["name"], host_service_property), (neo4j["name"], workstation["name"], service_host_property),
    (workstation["name"], polkit["name"], host_service_property), (polkit["name"], workstation["name"], service_host_property),
    (monitor["name"], kibana["name"], host_service_property), (kibana["name"], monitor["name"], service_host_property),
    (monitor["name"], phpmyadmin["name"], host_service_property), (phpmyadmin["name"], monitor["name"], service_host_property),
    (database["name"], mysql["name"], host_service_property), (mysql["name"], database["name"], service_host_property),
    
    (mail_expose["name"], opensmtpd["name"], expose_service_property), (mail_expose["name"], phpmailer["name"], expose_service_property),
    (workstation_expose["name"], jenkins["name"], expose_service_property), (workstation_expose["name"], openssh["name"], expose_service_property), (workstation_expose["name"], neo4j["name"], expose_service_property),
    (dmz_zone["name"], workstation_expose["name"], zone_expose_property), (dmz_zone["name"], mail_expose["name"], zone_expose_property),
    (dmz_zone["name"], ruby["name"], zone_service_property), (scada_zone["name"], kibana["name"], zone_service_property),
    (internet["name"], gitlab["name"], zone_service_property),
    (internet["name"], git_shell["name"], zone_service_property),
    (monitor["name"], mysql["name"], zone_service_property),

    (scada_zone["name"], work_zone["name"], zone_zone_property), (work_zone["name"], scada_zone["name"], zone_zone_property),
    (workstation["name"], work_zone["name"], host_zone_property), (workstation["name"], dmz_zone["name"], host_zone_property),
    (mail_server["name"], dmz_zone["name"], host_zone_property), (ftp_server["name"], dmz_zone["name"], host_zone_property), (web_server["name"], dmz_zone["name"], host_zone_property),
    (monitor["name"], scada_zone["name"], host_zone_property),
]

nodes = [
    (monitor["name"], monitor), (database["name"], database), (workstation["name"], workstation), (ftp_server["name"], ftp_server), (web_server["name"], web_server), (mail_server["name"], mail_server),
    (work_zone["name"], work_zone), (scada_zone["name"], scada_zone), (dmz_zone["name"], dmz_zone), (internet["name"], internet),
    (ruby["name"], ruby), (oracle["name"], oracle), (git_shell["name"], git_shell), (opensmtpd["name"], opensmtpd), (phpmailer["name"], phpmailer), (jenkins["name"], jenkins), (neo4j["name"], neo4j), (openssh["name"], openssh), (polkit["name"], polkit), (kibana["name"], kibana), (phpmyadmin["name"], phpmyadmin), (mysql["name"], mysql), (gitlab["name"], gitlab),
    (mail_expose["name"], mail_expose), (workstation_expose["name"], workstation_expose)
]

vul_env = nx.DiGraph()
vul_env.add_edges_from(edges)
vul_env.add_nodes_from(nodes)
# pos = nx.spring_layout(vul_env, seed=42)
# nx.draw(vul_env, pos, with_labels=True)
# plt.show()