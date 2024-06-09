import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from text_classification import new_bert_text_classification
from dotenv import load_dotenv

def test_text_classification(model_path: str, device: str):
    cve2cwe = new_bert_text_classification(model_path, device, "./myData/learning/CVE2CWE/classification.labels")
    text = "HTTP request smuggling vulnerability in Sun Java System Proxy Server before 20061130, when used with Sun Java System Application Server or Sun Java System Web Server, allows remote attackers to bypass HTTP request filtering, hijack web sessions, perform cross-site scripting (XSS), and poison web caches via unspecified attack vectors."
    print(cve2cwe.predict(text))

if __name__ == '__main__':
    load_dotenv('src/tests/env/text_classification.env')
    test_text_classification(os.getenv("MODEL_PATH"), os.getenv("DEVICE"))