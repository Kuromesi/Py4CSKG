import torch
import torch.nn as nn
from tqdm import trange, tqdm
from models import *
from bert_crf import *
from torchcrf import CRF
from transformers import AutoTokenizer

class NERPredict():
    def __init__(self) -> None:
        config = BERTBiLSTMCRFConfig()
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        model_dir = "./trained_models/BERTBiLSTMCRF"
        self.model = BERTBiLSTMCRF.from_pretrained(model_dir, config)
        self.model.to(self.device)
        self.labels = ['O', 'B-vul', 'I-vul', 'B-cons', 'I-cons']

    def idx2tag(self, id):
        tags = [[self.labels[y] for y in x if y > -1] for x in id]
        return tags

    def predict(self, sentence):
        tokenized = self.tokenizer(sentence, return_tensors="pt")
        text_vec = tokenized['input_ids'].to(self.device)
        input_token_starts = [[1] * len(text_vec[0])]
        input_token_starts[0][0] = 0
        input_token_starts[0][-1] = 0
        input_token_starts = torch.tensor(input_token_starts, dtype=torch.long).to(self.device)
        attention_mask = tokenized['attention_mask'].to(self.device)
        logits = self.model((text_vec, input_token_starts), attention_mask=attention_mask, use_crf=True)
        ids = self.model.crf.decode(emissions=logits[0])[0]
        tags = self.idx2tag([ids])
        tokens = self.tokenizer.tokenize(sentence)
        res = list(zip(tokens, tags[0]))
        weight = []
        for i in range(len(ids)):
            if ids[i] != 0:
                weight.append(i + 1)
        return {'res': res, 'ids': ids, 'weight': weight}

if __name__ == "__main__":
    
    ner = NERPredict(model, config)
    sentence = "Untrusted search path vulnerability in the add_filename_to_string function in intl/gettext/loadmsgcat.c for Elinks 0.11.1 allows local users to cause Elinks to use an untrusted gettext message catalog (.po file) in a ""../po"" directory, which can be leveraged to conduct format string attacks."
    res = ner.predict(sentence)
    ids = res['ids']
    print(res['res'])
    weight = []
    for i in range(len(ids)):
        if ids[i] != 0:
            weight.append(i + 1)
    print(weight)