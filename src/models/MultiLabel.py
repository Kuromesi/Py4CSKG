import torch
import torch.nn as nn
from copy import deepcopy
from models.layers.train_utils import Embeddings,PositionalEncoding
from models.layers.attention import MultiHeadedAttention
from models.layers.encoder import EncoderLayer, Encoder
from models.layers.feed_forward import PositionwiseFeedForward
import numpy as np
from models.utils.utils import *
from models.utils.metric import MultiLabelScorer, MultiClassScorer
import abc
from models.Model import Model

class MultiLabel(Model):
    scorer = MultiLabelScorer()
    def loss_op(self, data):
        y = data['label']
        y_pred = data['predict']
        loss = nn.BCELoss()
        loss = loss(y_pred, y)
        return loss

class MultiLabelBiLSTM(MultiLabel):
    def __init__(self, config, src_vocab):
        super(MultiLabelBiLSTM, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        if config.bidirectional:
            lstm_hiddens = config.lstm_hiddens * 2
        else:
            lstm_hiddens = config.lstm_hiddens
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(lstm_hiddens, lstm_hiddens),
            nn.Linear(lstm_hiddens, lstm_hiddens),
            nn.Linear(lstm_hiddens, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return self.sigmoid(logits)
        
class MultiLabelGru(MultiLabel):
    def __init__(self, config, src_vocab):
        super(MultiLabelGru, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.gru = nn.GRU(config.d_model, config.hidden_dim, config.layer_dim, batch_first=True)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.Linear(config.hidden_dim, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.gru(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return self.sigmoid(logits) 

class MultiLabelRNN(MultiLabel):
    def __init__(self, config, src_vocab):
        super(MultiLabelRNN, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.rnn = nn.RNN(config.d_model, config.hidden_dim, config.layer_dim, batch_first=True)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.Linear(config.hidden_dim, config.hidden_dim),
            nn.Linear(config.hidden_dim, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.rnn(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return self.sigmoid(logits) 

class MultiLabelTransformer(MultiLabel):
    def __init__(self, config, src_vocab):
        super(MultiLabelTransformer, self).__init__()
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
        # all_out = self.bilstm(encoded_sents)[0][:, 0, :]
        final_out = self.classifier(encoded_sents[:, 0, :])
        return self.sigmoid(final_out)