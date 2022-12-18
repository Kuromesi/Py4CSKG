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
        loss = nn.CrossEntropyLoss(y_pred, y)
        return loss

class MultiClassTransformer(nn.Module):
    def __init__(self, config, src_vocab):
        super(MultiClassTransformer, self).__init__()
        self.config = config
        self.best = 0
        self.scorer = MultiClassScorer()
        h, N, dropout = self.config.h, self.config.N, self.config.dropout
        d_model, d_ff = self.config.d_model, self.config.d_ff
        
        attn = MultiHeadedAttention(h, d_model)
        ff = PositionwiseFeedForward(d_model, d_ff, dropout)
        position = PositionalEncoding(d_model, dropout)
        
        self.encoder = Encoder(EncoderLayer(config.d_model, deepcopy(attn), deepcopy(ff), dropout), N)
        self.src_embed = nn.Sequential(Embeddings(config.d_model, src_vocab), deepcopy(position)) #Embeddings followed by PE

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=True, batch_first=True, bias=True)

        # Convolution Layer
        # self.conv1 = nn.Sequential(
        #     nn.Conv1d(in_channels=d_model, out_channels=config.num_channels, kernel_size=config.kernel_size[0]),
        #     nn.ReLU(),
        #     nn.MaxPool1d(config.max_sen_len - config.kernel_size[0]+1)
        # )
        # self.conv2 = nn.Sequential(
        #     nn.Conv1d(in_channels=d_model, out_channels=config.num_channels, kernel_size=config.kernel_size[1]),
        #     nn.ReLU(),
        #     nn.MaxPool1d(config.max_sen_len - config.kernel_size[1]+1)
        # )
        # self.conv3 = nn.Sequential(
        #     nn.Conv1d(in_channels=d_model, out_channels=config.num_channels, kernel_size=config.kernel_size[2]),
        #     nn.ReLU(),
        #     nn.MaxPool1d(config.max_sen_len - config.kernel_size[2]+1)
        # )

        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))


        # Fully-Connected Layer
        self.fc = nn.Linear(
            self.config.num_channels*len(self.config.kernel_size),
            self.config.output_size
        )
        
        self.fc1 = nn.Linear(
            self.config.d_model,
            self.config.d_model
        )
        self.fc2 = nn.Linear(
            self.config.d_model,
            self.config.output_size
        )
        
        # Softmax non-linearity
        # self.softmax = nn.Softmax(dim=1)
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        embedded_sents = self.src_embed(x) # shape = (batch_size, sen_len, d_model)
        encoded_sents = self.encoder(embedded_sents)
        
        # Convert input to (batch_size, d_model) for linear layer
        final_feature_map = encoded_sents[:, 0, :]
        
        # encoded_sents = encoded_sents.permute(0, 2, 1)
        all_out = self.bilstm(encoded_sents)[0][:, 0, :]
        # conv_out1 = self.conv1(encoded_sents).squeeze(2)
        # conv_out2 = self.conv2(encoded_sents).squeeze(2)
        # conv_out3 = self.conv3(encoded_sents).squeeze(2)
        # all_out = torch.cat((conv_out1, conv_out2, conv_out3), 1)
        final_out = self.classifier(all_out)
        # final_out = self.fc1(final_feature_map)
        # final_out = self.fc(final_out)
        return final_out
    
    def add_optimizer(self, optimizer):
        self.optimizer = optimizer
        # Exponential
        # self.attenuation = torch.optim.lr_scheduler.ExponentialLR(self.optimizer, gamma=self.config.gamma)
        
        # Step
        self.attenuation = torch.optim.lr_scheduler.StepLR(self.optimizer, step_size=int(self.config.max_epochs / 3), gamma=self.config.gamma)
        
    def add_loss_op(self, loss_op):
        self.loss_op = loss_op
                
    def run_epoch(self, train_iterator, val_iterator, epoch):
        train_losses = []
        val_accuracies = []
        losses = []
            
        for i, batch in enumerate(train_iterator):
            self.optimizer.zero_grad()
            if torch.cuda.is_available():
                x = batch[1].cuda()
                # y = (batch[0] - 1).type(torch.cuda.LongTensor)
                y = batch[0].cuda().type(torch.cuda.LongTensor)
            else:
                x = batch[1].type(torch.LongTensor)
                # y = (batch[0] - 1).type(torch.LongTensor)
                y = batch[0]
            y_pred = self.__call__(x)
            loss = self.loss_op(y_pred, y)
            loss.backward()
            losses.append(loss.data.cpu().numpy())
            self.optimizer.step()
            if i % 200 == 0:
                print("Iter: {}".format(i+1))
                avg_train_loss = np.mean(losses)
                train_losses.append(avg_train_loss)
                print("\tAverage training loss: {:.5f}".format(avg_train_loss))
                losses = []
                
                # Evalute Accuracy on validation set
                accuracy, precision, f1, recall = self.scorer.evaluate_model(self, val_iterator, "Validation")
                if (i  > 4 * self.config.max_epochs / 5 and self.best < precision):
                    save_model(self, 'ckpts/transformer.pkl')
                    self.best = precision
                self.train()       
        return train_losses, val_accuracies

class MultiClassBiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBiLSTM, self).__init__()
        self.config = config
        self.best = 0
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
    
    def loss_op(self, y_pred, y):
        y = y.type(torch.cuda.LongTensor)
        loss = nn.CrossEntropyLoss(y_pred, y)
        return loss