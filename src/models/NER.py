import torch
import torch.nn as nn
import numpy as np
from models.utils.utils import *
from models.Model import Model
from torchcrf import CRF
from models.layers.train_utils import Embeddings

class NER(Model):
    def loss_op(self, data):
        y = data['label']
        y_pred = data['predict']
        attention_mask = data['attention_mask']
        loss = self.crf(emissions=y_pred, tags=y, mask=attention_mask)
        return -1 * loss

class NERBiLSTMCRF(Model):
    def __init__(self, config, src_vocab):
        super(NERBiLSTMCRF, self).__init__()
        # self.dropout = nn.Dropout(config.dropout)
        self.src_embed = Embeddings(config.d_model, src_vocab)

        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=True, batch_first=True, bias=True)

        if config.bidirectional:
            lstm_hiddens = config.lstm_hiddens * 2
        else:
            lstm_hiddens = config.lstm_hiddens

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(lstm_hiddens, lstm_hiddens),
            nn.Linear(lstm_hiddens, lstm_hiddens),
            nn.Linear(lstm_hiddens, config.output_size))

        self.crf = CRF(num_tags=config.output_size, batch_first=True)

    def forward(self, x):
        # outputs =self.bert(input_ids=x[0], attention_mask=x[1], token_type_ids=token_type_ids)
        # sequence_output = outputs[0]
        # sequence_output = self.dropout(sequence_output)
        logits = self.src_embed(x['data'])
        logits = self.bilstm(logits)[0]
        logits = self.classifier(logits)
        return logits