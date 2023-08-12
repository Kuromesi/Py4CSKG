import pandas as pd
import re, os

cpe_r = re.compile(r".*cve_cpe\d+.csv")
rel_r = re.compile(r".*cve_rel\d+.csv")
path_rel = "./data/neo4j/data/import/relations"
path_cpe = "./data/neo4j/data/import/nodes"
r = cpe_r

paths = os.listdir(path_cpe)
df = pd.DataFrame()
for path in paths:
    if r.findall(path):
        t = pd.read_csv(os.path.join(path_cpe, path))
        df = pd.concat([df, t], ignore_index=True)
df = df.drop_duplicates()
df.to_csv(os.path.join(path_cpe, "cve_cpe.csv"), index=False)