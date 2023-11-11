import json, os

def old_cved_proc():
    cved = {}
    old2new = {
        "Overflow": "Overflow",
        "Mem. Corr.": "Memory Corruption",
        "Exec Code": "Code Execution",
        "Dir. Trav.": "Directory Traversal",
        "Bypass": "Bypass",
        "File Inclusion": "File Inclusion",
        "XSS": "XSS",
        "CSRF": "CSRF",
        "Sql": "Sql Injection",
        "DoS": "Denial of Service",
        "+Info": "Information Leak",
        "+Priv": "Privilege Escalation",
    }
    for file in os.listdir("./data/base/cve_details"):
        if file == "impact.json":
            continue
        with open(os.path.join("./data/base/cve_details", file), "r") as f:
            cved.update(json.load(f))
    ncved = {}
    for entry, impact in cved.items():
        ncved[entry] = []
        for k, v in old2new.items():
            if k in impact:
                ncved[entry].append(v)
    with open("./data/base/cve_details/nImpact.json", "w") as f:
        json.dump(ncved, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    old_cved_proc()