import sys, os, json
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from text_classification import TextClassification

def test_text_classification():
    cve2cwe = TextClassification()
    cve2cwe.init_bert()
    text = "HTTP request smuggling vulnerability in Sun Java System Proxy Server before 20061130, when used with Sun Java System Application Server or Sun Java System Web Server, allows remote attackers to bypass HTTP request filtering, hijack web sessions, perform cross-site scripting (XSS), and poison web caches via unspecified attack vectors."
    print(cve2cwe.bert_predict(text))

if __name__ == '__main__':
    test_text_classification()