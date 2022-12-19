# Model.py

import torch
import torch.nn as nn
from copy import deepcopy
from models.layers.train_utils import Embeddings,PositionalEncoding
from models.layers.attention import MultiHeadedAttention
from models.layers.encoder import EncoderLayer, Encoder
from models.layers.feed_forward import PositionwiseFeedForward
import numpy as np
from models.utils.utils import *
from transformers import BertModel, BertConfig
from models.Model import Model
from models.utils.metric import MultiClassScorer

class MultiClass(Model):
    scorer = MultiClassScorer()
    def loss_op(self, data):
        y = data['label']
        y_pred = data['predict']
        y = y.type(torch.cuda.LongTensor)
        loss = nn.CrossEntropyLoss()
        loss = loss(y_pred, y)
        return loss

class MultiClassTransformer(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassTransformer, self).__init__()
        self.config = config
        h, N, dropout = self.config.h, self.config.N, self.config.dropout
        d_model, d_ff = self.config.d_model, self.config.d_ff
        
        attn = MultiHeadedAttention(h, d_model)
        ff = PositionwiseFeedForward(d_model, d_ff, dropout)
        position = PositionalEncoding(d_model, dropout)
        
        self.encoder = Encoder(EncoderLayer(config.d_model, deepcopy(attn), deepcopy(ff), dropout), N)
        self.src_embed = nn.Sequential(Embeddings(config.d_model, src_vocab), deepcopy(position)) #Embeddings followed by PE

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.Linear(d_model, d_model),
            nn.Linear(d_model, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded_sents = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        encoded_sents = self.encoder(embedded_sents)
        final_out = self.classifier(encoded_sents[:, 0, :])
        return final_out

class MultiClassBiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBiLSTM, self).__init__()
        self.config = config
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=True, batch_first=True, bias=True)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))
        
        # Softmax non-linearity
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits
    
    
class MultiClassBertBiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBertBiLSTM, self).__init__()
        self.config = config
        self.best = 0
        bertConfig = BertConfig.from_pretrained(config.model_name)

        # Embedding layer
        self.src_embed = BertModel.from_pretrained(config.model_name, config=bertConfig)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=bertConfig.hidden_size, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=True, batch_first=True, bias=True)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))
        
        # Softmax non-linearity
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        with torch.no_grad():
            logits = self.src_embed(x['data'], attention_mask=x['attention_mask']).last_hidden_state # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits

class MultiClassCNN(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBertBiLSTM, self).__init__()
        self.config = config
        self.best = 0
        bertConfig = BertConfig.from_pretrained(config.model_name)

        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Convolution layer
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=self.config.d_model, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[0]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[0]+1)
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=self.config.d_model, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[1]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[1]+1)
        )
        self.conv3 = nn.Sequential(
            nn.Conv1d(in_channels=self.config.d_model, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[2]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[2]+1)
        )

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))

    def forward(self, x):
        logits = self.src_embed(x['data']).permute(1,2,0)
        # embedded_sent.shape = (batch_size=64,d_model=300,max_sen_len=20)
        
        conv_out1 = self.conv1(logits).squeeze(2) #shape=(64, num_channels, 1) (squeeze 1)
        conv_out2 = self.conv2(logits).squeeze(2)
        conv_out3 = self.conv3(logits).squeeze(2)
        logits = torch.cat((conv_out1, conv_out2, conv_out3), 1)
        logits = self.classifier(logits)
        return logits