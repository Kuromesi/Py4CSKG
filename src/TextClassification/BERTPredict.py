from BERT import *
from utils.Dataset import *
from config.BERTConfig import *


def BERT_classification_predict():
    model = BERT.from_pretrained('trained_models/BERT')
    model.to('cuda')
    config = BERTConfig()
    dataset = BERTDataset(config)
    text = "In setSyncSampleParams of SampleTable.cpp, there is possible resource exhaustion due to a missing bounds check. This could lead to remote denial of service with no additional execution privileges needed.."
    text_vec = dataset.text2vec(text)
    data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
    pred = model(data['data'], attention_mask=data['attention_mask'])[0]
    pred = pred.cpu().data
    pred = torch.max(pred, 1)[1]
    labels = loadLabels(config.label_path)
    print(labels[pred[0]])

if __name__ == "__main__":
    BERT_classification_predict()