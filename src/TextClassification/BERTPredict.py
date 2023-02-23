from BERT import *
from utils.Dataset import *
from config.BERTConfig import *


def BERT_classification_predict():
    model = BERT.from_pretrained('trained_models/BERTBiLSTMCRF')
    model.to('cuda')
    config = BERTConfig()
    dataset = BERTDataset(config)
    text = "A missing HTTP header (X-Frame-Options) in Kiwi Syslog Server has left customers vulnerable to click jacking. Clickjacking is an attack that occurs when an attacker uses a transparent iframe in a window to trick a user into clicking on an actionable item, such as a button or link, to another server in which they have an identical webpage. The attacker essentially hijacks the user activity intended for the original server and sends them to the other server. This is an attack on both the user and the server."
    text_vec = dataset.text2vec(text)
    data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
    pred = model(data['data'], attention_mask=data['attention_mask'])[0]
    pred = pred.cpu().data
    pred = torch.max(pred, 1)[1]
    labels = loadLabels(config.label_path)
    print(labels[pred[0]])

if __name__ == "__main__":
    BERT_classification_predict()