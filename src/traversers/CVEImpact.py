import torch
import torch.nn as nn
from tqdm import trange, tqdm
from TextSimilarity.models import *
from TextSimilarity.bert_crf import *
from torchcrf import CRF
from transformers import AutoTokenizer
from TextClassification.BERT import *
from TextClassification.utils.Dataset import *
from TextClassification.config.BERTConfig import BERTImpactConfig
from service.GDBSaver import *
from service.RDBSaver import *
import json

class CVEImpact():
    def __init__(self) -> None:
        config = BERTBiLSTMCRFConfig()
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        model_dir = "./trained_models/BERTBiLSTMCRFNER"
        self.model = BERTBiLSTMCRF.from_pretrained(model_dir, config)
        self.model.to(self.device)
        self.labels = ['O', 'B-vul', 'I-vul', 'B-cons', 'I-cons']
        
        self.classifier = BERT.from_pretrained('trained_models/BERTImpact')
        self.classifier.to(self.device)
        config = BERTImpactConfig()
        self.dataset = BERTDataset(config)
        self.impact_type = loadLabels(config.label_path)
        
        self.gs = GDBSaver()
        self.rs = RDBSaver()
        

    def idx2tag(self, id):
        tags = [[self.labels[y] for y in x if y > -1] for x in id]
        return tags

    def predict(self, sentence):
        tokenized = self.tokenizer(sentence, return_tensors="pt", padding=True, truncation=True, max_length=256)
        text_vec = tokenized['input_ids'].to(self.device)
        input_token_starts = []
        for i in range(len(text_vec)):
            word_ids = tokenized.word_ids(i)
            input_token_starts.append([1 if i != None else 0 for i in word_ids])
        input_token_starts = torch.tensor(input_token_starts, dtype=torch.long).to(self.device)
        attention_mask = tokenized['attention_mask'].to(self.device)
        logits = self.model((text_vec, input_token_starts), attention_mask=attention_mask, use_crf=True)
        ids = self.model.crf.decode(emissions=logits[0])
        tags = self.idx2tag(ids)
        tokens = self.tokenizer.tokenize(sentence)
        results = list(zip(tokens, tags[0]))
        classification_data = []
        words = []
        for res in results:
            if res[1][2: ] == 'cons':
                if res[0][: 2] == '##':
                    if words:
                        words[-1] += res[0][2: ]
                else:
                    words.append(res[0])
            else:
                if words:
                    classification_data.append(words)
                    words = []
        data_type = []
        if classification_data:
            for classification_datum in classification_data:
                temp = ""
                for datum in classification_datum:
                    temp += datum + " "
                temp = temp.strip()
                data_type.append(self.BERT_classification_predict(temp))
        else:
            data_type.append(self.BERT_classification_predict(sentence))
        return data_type
                    
    def BERT_classification_predict(self, text):
        text_vec = self.dataset.text2vec(text)
        data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
        pred = self.classifier(data['data'], attention_mask=data['attention_mask'])[0]
        pred = pred.cpu().data
        pred = torch.max(pred, 1)[1]
        return self.impact_type[pred[0]]
    
    def get_impact(self, sentence, cvss2, cvss3=None):
        data_type = self.predict(sentence)
        impact = ""
        if cvss3:
            if cvss3['cvssV3']['confidentialityImpact'] == "HIGH" and cvss3['cvssV3']['integrityImpact'] == "HIGH" and cvss3['cvssV3']['availabilityImpact'] == "HIGH":
                if "code_exec" in data_type:
                    impact = "System arbitrary code execution"
                else:
                    if "privilege_escalation" in data_type:
                        impact = "Privilege escalation" if cvss3['cvssV3']['attackVector'] == "LOCAL" else "Gain root privilege"
                    else:
                        impact = "System CIA loss"
            else:
                if "privilege_escalation" in data_type:
                    impact = "Gain user privilege" if cvss2['obtainUserPrivilege'] else "Gain application privilege"
                else:
                    impact = "Application arbitrary code execution" if "code_exec" in data_type else "System CIA loss"
        else:        
            if cvss2['cvssV2']['confidentialityImpact'] == "COMPLETE" and cvss2['cvssV2']['integrityImpact'] == "COMPLETE" and cvss2['cvssV2']['availabilityImpact'] == "COMPLETE":
                if "code_exec" in data_type:
                    impact = "System arbitrary code execution"
                else:
                    if "privilege_escalation" in data_type:
                        impact = "Privilege escalation" if cvss2['cvssV2']['accessVector'] == "LOCAL" else "Gain root privilege"
                    else:
                        impact = "System CIA loss"
            else:
                if "privilege_escalation" in data_type:
                    impact = "Gain user privilege" if cvss2['obtainUserPrivilege'] else "Gain application privilege"
                else:
                    impact = "Application arbitrary code execution" if "code_exec" in data_type else "System CIA loss"
        return impact
                
    def traverse(self):
        query = "MATCH (n:Vulnerability) RETURN n"
        results = self.gs.sendQuery(query)
        results = tqdm(results)
        results.set_description("Predict CVE impact type")
        for res in results:
            res = res[0]
            id = res['id']
            results.set_postfix(id=id)
            # if 'impact' in res:
            #     continue
            if 'baseMetricV2' in res:
                node_id = res.id
                if 'baseMetricV3' in res:
                    impact = self.get_impact(res['description'], json.loads(res['baseMetricV2']), json.loads(res['baseMetricV3']))
                else:
                    impact = self.get_impact(res['description'], json.loads(res['baseMetricV2']))
                query = "MATCH (n:Vulnerability) WHERE id(n)=%d SET n.impact='%s'"%(node_id, impact)
                self.gs.sendQuery(query)

if __name__ == "__main__":
    
    ner = NERPredict()
    sentence = "A memory corruption vulnerability exists in InDesign 15.1.1 (and earlier versions). Insecure handling of a malicious indd file could be abused to cause an out-of-bounds memory access, potentially resulting in code execution in the context of the current user."
    res = ner.predict(sentence)
    ids = res['ids']
    print(res['res'])