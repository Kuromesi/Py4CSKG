# This program aims to extract CVE from ATT&CK procedures as training data
# e.g. ProLock can use **CVE-2019-0859** to escalate privileges on a compromised host.

from bs4 import BeautifulSoup as bs
import re, json
from service.GDBSaver import GDBSaver

CVE = re.compile(r'CVE-\d*-\d*')
GDB = GDBSaver()

def extract(path):
    tactics_list = []
    with open('data/attack/tactics.json', 'r') as f:
        tactics_dict = json.load(f)
    with open('data/attack/tactics.txt', 'r') as f:
        tactics_list = f.readlines()
        tactics_list = [x.strip() for x in tactics_list]
    with open(path, 'r') as f:
        attack = f.read()

    text2id = lambda x: str(tactics_list.index(tactics_dict[x]))
    attack =bs(attack, 'xml')
    with open('data/attack/attack.train', 'w') as f:
        for technique in attack.find_all('Technique'):
            print(technique.attrs['id'])
            line = ''
            if technique.find('Tactics'):
                tactics = technique.find('Tactics').get_text().strip().split(', ')
            else:
                tactics = technique.find('Tactic').get_text().strip().split(', ')
            tactics = [text2id(x) for x in tactics]
            
            examples = []
            for exa in technique.find_all('Example'):
                if CVE.search(exa.get_text()):
                    examples.extend(CVE.findall(exa.get_text()))
            if examples:
                for x in tactics:
                    line += x + '|'
                line = line.strip('|')
                line += ' , '
                for x in examples:
                    try:
                        des = GDB.sendQuery("MATCH (n:Vulnerability) WHERE n.id='%s' RETURN n"%x)[0][0].get('des').strip()
                        f.write(line + des + "\n")
                    except:
                        print("not recorded")

if __name__ == '__main__':
    extract('data/attack/enterprise.xml')