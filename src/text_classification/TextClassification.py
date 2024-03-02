import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from text_classification.BERT import *
from text_classification.utils.Dataset import *
from text_classification.config.BERTConfig import *
from utils.Config import config

class TextClassification():
    def init_bert(self):
        self.bert = BERT.from_pretrained(config.get("TextClassification", "cve2cwe_path"))
        self.device = config.get("TextClassification", "device")
        if self.device == "gpu":
            self.bert.to('cuda')
        bert_config = BERTConfig()
        self.bert_dataset = BERTDataset(bert_config)
        self.bert_labels = loadLabels(bert_config.label_path)
        
    def bert_predict(self, text):
        text_vec = self.bert_dataset.text2vec(text)
        if self.device == "gpu":
            data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
        else:
            data = {'data': text_vec['input_ids'], 'attention_mask': text_vec['attention_mask']}
        pred = self.bert(data['data'], attention_mask=data['attention_mask'])[0]
        pred = pred.cpu().data
        pred = torch.max(pred, 1)[1]
        return self.bert_labels[pred[0]]

if __name__ == "__main__":
    cve2cwe = TextClassification()
    cve2cwe.init_bert()
    text = "HTTP request smuggling vulnerability in Sun Java System Proxy Server before 20061130, when used with Sun Java System Application Server or Sun Java System Web Server, allows remote attackers to bypass HTTP request filtering, hijack web sessions, perform cross-site scripting (XSS), and poison web caches via unspecified attack vectors."
    print(cve2cwe.bert_predict(text))