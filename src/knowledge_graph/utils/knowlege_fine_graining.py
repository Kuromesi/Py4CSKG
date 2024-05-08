import os, re
import pandas as pd

CPE_PATH = re.compile(r'cve_cpe.*.csv')
CVE_CWE = re.compile(r'cve_rel.*.csv')

def remove_duplicates(path):
    files = os.listdir(path)
    cpe_df = None
    for file in files:
        if CPE_PATH.match(file):
            df = pd.read_csv(os.path.join(path, file))
            if cpe_df is None:
                cpe_df = df
            else:
                cpe_df = pd.concat([cpe_df, df], axis=0, ignore_index=True)
    cpe_df.drop_duplicates(inplace=True)
    cpe_df.to_csv(os.path.join('cve_cpe.csv'), index=False)

def reverse_cve_cwe(path):
    files = os.listdir(path)
    for file in files:
        if CVE_CWE.match(file):
            df = pd.read_csv(os.path.join(path, file))
            for index, row in df.iterrows():
                if row[':TYPE'] == "Exploit":
                    row[':START_ID'], row[':END_ID'] = row[':END_ID'], row[':START_ID']
                    df.loc[index] = row
            df.to_csv(os.path.join("data/neo4j/relations", file), index=False)


if __name__ == "__main__":
    # remove_duplicates("data/neo4j/data/import/nodes")
    reverse_cve_cwe("data/neo4j/data/import/relations")
    