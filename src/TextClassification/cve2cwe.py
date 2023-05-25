from TextClassification.BERT import *
from TextClassification.utils.Dataset import *
from TextClassification.config.BERTConfig import *

class CVE2CWE():
    def init_bert(self):
        self.bert = BERT.from_pretrained('trained_models/BERTBiLSTMCRF')
        self.bert.to('cuda')
        config = BERTConfig()
        self.bert_dataset = BERTDataset(config)
        self.bert_labels = loadLabels(config.label_path)
        
    def bert_predict(self, text):
        text_vec = self.bert_dataset.text2vec(text)
        data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
        pred = self.bert(data['data'], attention_mask=data['attention_mask'])[0]
        pred = pred.cpu().data
        pred = torch.max(pred, 1)[1]
        
        print(self.bert_labels[pred[0]])

if __name__ == "__main__":
    BERT_classification_predict()