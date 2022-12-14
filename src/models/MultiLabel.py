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

class MultiLabelBiLSTM(nn.Module):
    def __init__(self, config, src_vocab):
        super(MultiLabelBiLSTM, self).__init__()
        self.config = config
        self.best = 0
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=True, batch_first=True, bias=True)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        logits = self.src_embed(x) # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return self.sigmoid(logits)
    
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
                y = batch[0].cuda()
            else:
                x = batch[1].type(torch.LongTensor)
                # y = (batch[0] - 1).type(torch.LongTensor)
                y = batch[0]
            y_pred = self.__call__(x)
            loss = self.loss_op(y_pred, y)
            loss.backward()
            losses.append(loss.data.cpu().numpy())
            self.optimizer.step()
            if i % 50 == 0:
                print("Iter: {}".format(i+1))
                avg_train_loss = np.mean(losses)
                train_losses.append(avg_train_loss)
                print("\tAverage training loss: {:.5f}".format(avg_train_loss))
                losses = []
                
                # Evalute Accuracy on validation set
                accuracy, precision, f1, recall, report = self.scorer.evaluate_model(self, val_iterator, "Validation")
                if (i  > 4 * self.config.max_epochs / 5 and self.best < precision):
                    save_model(self, self.model_path)
                    self.best = precision
                self.train()       
        return train_losses, val_accuracies
        

class MultiLabelTransformer(nn.Module):
    def __init__(self, config, src_vocab):
        super(MultiLabelTransformer, self).__init__()
        self.config = config
        self.best = 0
        self.scorer = Scorer()
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

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(config.lstm_hiddens * 2, config.output_size))

        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded_sents = self.src_embed(x) # shape = (batch_size, sen_len, d_model)
        encoded_sents = self.encoder(embedded_sents)
        all_out = self.bilstm(encoded_sents)[0][:, 0, :]
        final_out = self.classifier(all_out)
        return self.sigmoid(final_out)
    
    def add_optimizer(self, optimizer):
        self.optimizer = optimizer
        # Exponential
        # self.attenuation = torch.optim.lr_scheduler.ExponentialLR(self.optimizer, gamma=self.config.gamma)
        
        # Step
        self.attenuation = torch.optim.lr_scheduler.StepLR(self.optimizer, step_size=int(self.config.max_epochs / 3), gamma=self.config.gamma)
        
    def add_loss_op(self, loss_op):
        self.loss_op = loss_op
    
    def reduce_lr(self):
        print("Reducing LR")
        for g in self.optimizer.param_groups:
            g['lr'] = g['lr'] / 2
                
    def run_epoch(self, train_iterator, val_iterator, epoch):
        train_losses = []
        val_accuracies = []
        losses = []
            
        for i, batch in enumerate(train_iterator):
            self.optimizer.zero_grad()
            if torch.cuda.is_available():
                x = batch[1].cuda()
                # y = (batch[0] - 1).type(torch.cuda.LongTensor)
                y = batch[0].cuda()
            else:
                x = batch[1].type(torch.LongTensor)
                # y = (batch[0] - 1).type(torch.LongTensor)
                y = batch[0]
            y_pred = self.__call__(x)
            loss = self.loss_op(y_pred, y)
            loss.backward()
            losses.append(loss.data.cpu().numpy())
            self.optimizer.step()
            if i % 50 == 0:
                print("Iter: {}".format(i+1))
                avg_train_loss = np.mean(losses)
                train_losses.append(avg_train_loss)
                print("\tAverage training loss: {:.5f}".format(avg_train_loss))
                losses = []
                
                # Evalute Accuracy on validation set
                accuracy, precision, f1, recall, report = self.scorer.evaluate_model(self, val_iterator, "Validation", self.labels)
                if (i  > 4 * self.config.max_epochs / 5 and self.best < precision):
                    save_model(self, 'ckpts/transformer.pkl')
                    self.best = precision
                self.train()       
        return train_losses, val_accuracies