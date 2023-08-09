import pandas as pd
import re, os

# r = re.compile(r".*cve_cpe\d+.csv")
r = re.compile(r".*cve_rel\d+.csv")

paths = os.listdir("./data/neo4j/relations")
df = pd.DataFrame()
for path in paths:
    if r.findall(path):
        t = pd.read_csv(os.path.join("./data/neo4j/relations/", path))
        df = pd.concat([df, t], ignore_index=True)
df = df.drop_duplicates()
df.to_csv("./data/neo4j/relations/cve_rel.csv", index=False)