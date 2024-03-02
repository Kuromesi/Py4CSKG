import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)

from service.GDBSaver import GDBSaver
from collections import Counter

gdb = GDBSaver()

def get_technique_impact(id):
    query = f"match (n:Technique)-[]-(v:Vulnerability) \
            where n.id=\"{id}\" return v.impact"
    results = gdb.sendQuery(query)
    results = [r[0] for r in results]
    counter = Counter(results)
    print(counter)

if __name__ == "__main__":
    get_technique_impact("CAPEC-242")