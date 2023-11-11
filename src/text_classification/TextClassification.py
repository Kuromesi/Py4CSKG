import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from text_classification.BERT import *
from text_classification.utils.Dataset import *
from text_classification.config.BERTConfig import *
from utils.Config import config

class CVE2CWE():
    def init_bert(self):
        self.bert = BERT.from_pretrained(config.get("TextClassification", "cve2cwe_path"))
        device = config.get("TextClassification", "device")
        if device == "gpu":
            self.bert.to('cuda')
        bert_config = BERTConfig()
        self.bert_dataset = BERTDataset(bert_config)
        self.bert_labels = loadLabels(bert_config.label_path)
        
    def bert_predict(self, text):
        text_vec = self.bert_dataset.text2vec(text)
        data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
        pred = self.bert(data['data'], attention_mask=data['attention_mask'])[0]
        pred = pred.cpu().data
        pred = torch.max(pred, 1)[1]
        return self.bert_labels[pred[0]]

if __name__ == "__main__":
    cve2cwe = CVE2CWE()
    cve2cwe.init_bert()
    text = "An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent."
    print(cve2cwe.bert_predict(text))