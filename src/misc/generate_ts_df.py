import pandas as pd
import re
from bs4 import BeautifulSoup

CWE_PATH = "data/base/cwe/CWE.xml"
CAPEC_PATH = "data/base/capec/CAPEC.xml"

df = pd.DataFrame(columns=['id', 'name', 'description'])

def proc_text(text: str) -> str:
    # 去除换行符
    text = text.strip()
    text = text.replace('\n', '')
    text = re.sub(r'\s+', ' ', text)  # 使用正则表达式替换多余的空格
    return text

def generate_cwe_df():
    global df
    with open(CWE_PATH, 'r') as f:
        soup = BeautifulSoup(f, 'xml')
    elements = soup.find_all('Weakness')
    for element in elements:
        id = f"CWE-{element['ID']}"
        name = element['Name']
        des = element.find_all('Description')[0]
        des = proc_text(des.text)
        extended_des = element.find_all('Extended_Description')
        if extended_des:
            des = des + proc_text(extended_des[0].text)
        if not des:
            print(name)
            continue
        df.loc[len(df.index)] = [id, name, des]
    
def generate_capec_df():
    with open(CAPEC_PATH, 'r') as f:
        soup = BeautifulSoup(f, 'xml')
    elements = soup.find_all('Attack_Pattern')
    for element in elements:
        id = f"CAPEC-{element['ID']}"
        name = element['Name']
        des = element.find_all('Description')[0]
        des = proc_text(des.text)
        extended_des = element.find_all('Extended_Description')
        if extended_des:
            des = des + proc_text(extended_des[0].text)
        if not des:
            print(name)
            continue
        df.loc[len(df.index)] = [id, name, des]

def generate_attack_df(path: str):
    with open(path, 'r') as f:
        soup = BeautifulSoup(f, 'xml')
    elements = soup.find_all('Technique')
    for element in elements:
        id = element['id']
        name = element['name']
        des = proc_text(element.contents[0])
        if not des:
            print(name)
            continue
        df.loc[len(df.index)] = [id, name, des]

def generate_df():
    generate_attack_df("data/base/attack/enterprise.xml")
    generate_attack_df("data/base/attack/ics.xml")
    generate_attack_df("data/base/attack/mobile.xml")
    generate_capec_df()
    generate_cwe_df()

if __name__ == "__main__":
    generate_df()
    df.to_csv("tmp.csv", index=False)