from service.GDBSaver import GDBSaver

THRESHOLD = 100
gdb = GDBSaver()
visited = set()

class CWENode():
    cve = 0

cwe_dict = {}
new_tree = {}

def traverse(node_id:str, parent_id:str) -> int:
    if node_id in visited:
        return 0
    query = "MATCH (n:Weakness) WHERE n.id=\"%s\" MATCH (n)-[:ChildOf]-(a) RETURN a"%node_id
    nodes = gdb.sendQuery(query)
    cve = cwe_dict[node_id]
    for node in nodes:
        id = node[0].get('id')
        cve += traverse(id)

    visited.add(node_id)
    if cve < THRESHOLD:
        new_tree[node_id] = parent_id
        return cve
    return 0



def traverseCWE():
    # Pillar
    query = "MATCH (n:Weakness) WHERE n.id=\"CWE-1000\" MATCH (n)-[:Has_Member]-(a) RETURN a"
    pillars = gdb.sendQuery(query)
    for pillar in pillars:
        id = pillar[0].get('id')
        traverse(id, id)
        


