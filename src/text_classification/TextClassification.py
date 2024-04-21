import torch, abc
from text_classification.BERT import *
from text_classification.utils.Dataset import BERTDataset, loadLabels
from text_classification.config.BERTConfig import BERTConfig
from utils import logger

class TextClassification():
    @abc.abstractmethod
    def predict(self, text) -> str:
        pass

class BERTTextClassification(TextClassification):
    def __init__(self, device: str, model_path: str, label_path: str) -> None:
        if torch.cuda.is_available() and device == "cuda":
            if torch.cuda.is_available():
                logger.info("use device cuda for text classification")
                self.device = device
            else:
                logger.info("try to use device cuda for text classification, but cuda is not available")
                self.device = "cpu"
        else:
            logger.info("use device cpu for text classification")
            self.device = "cpu"
        self.bert = BERT.from_pretrained(model_path)
        if self.device == "cuda":
            self.bert.to('cuda')
        bert_config = BERTConfig()
        self.bert_dataset = BERTDataset(bert_config)
        self.bert_labels = loadLabels(label_path)

    def predict(self, text) -> str:
        logger.info(f"predict text: {text}")
        text_vec = self.bert_dataset.text2vec(text)
        if self.device == "cuda":
            data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
        else:
            data = {'data': text_vec['input_ids'], 'attention_mask': text_vec['attention_mask']}
        pred = self.bert(data['data'], attention_mask=data['attention_mask'])[0]
        pred = pred.cpu().data
        pred = torch.max(pred, 1)[1]
        return self.bert_labels[pred[0]]
    
def new_bert_text_classification(model_path: str, device: str, label_path: str) -> TextClassification:
    cve2cwe = BERTTextClassification(device, model_path, label_path)
    return cve2cwe