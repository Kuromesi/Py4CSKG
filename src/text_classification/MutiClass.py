# Model.py

import torch
import torch.nn as nn
from copy import deepcopy
from TextClassification.layers.train_utils import Embeddings,PositionalEncoding
from TextClassification.layers.attention import MultiHeadedAttention
from TextClassification.layers.encoder import EncoderLayer, Encoder
from TextClassification.layers.feed_forward import PositionwiseFeedForward
import numpy as np
from TextClassification.utils.utils import *
from transformers import BertModel, BertConfig, RobertaModel, RobertaConfig, GPT2Config, GPT2Model, BertPreTrainedModel
from TextClassification.Model import Model
from TextClassification.utils.metric import MultiClassScorer

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
            # nn.Linear(d_model, d_model),
            # nn.Linear(d_model, d_model),
            nn.Linear(d_model, config.output_size))

    def forward(self, x):
        embedded_sents = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        encoded_sents = self.encoder(embedded_sents)
        final_out = self.classifier(encoded_sents[:, 0, :])
        # final_out = self.classifier(encoded_sents.mean(1))
        return final_out

class MultiClassBiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBiLSTM, self).__init__()
        self.config = config
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        lstm_hiddens = config.lstm_hiddens * 2 if config.bidirectional else config.lstm_hiddens
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(lstm_hiddens, config.output_size))

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits
    
class MultiClassBert(BertPreTrainedModel):

    def __init__(self, config):
        super(MultiClassBert, self).__init__(config)
        self.bert = BertModel(config)
        self.dropout = torch.nn.Dropout(config.hidden_dropout_prob)
        self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)
        self.init_weights()

    def forward(self, x):
        logits = self.bert(x['data'], attention_mask=x['attention_mask'])[1] # shape = (batch_size, sen_len, d_model)
        logits = self.classifier(logits)
        return logits
    
    def add_optimizer(self, optimizer, config):
        self.best = 0
        self.config = config
        self.optimizer = optimizer
        self.scorer = MultiClassScorer()
        # Exponential
        # self.attenuation = torch.optim.lr_scheduler.ExponentialLR(self.optimizer, gamma=self.config.gamma)
        
        # Step
        self.attenuation = torch.optim.lr_scheduler.StepLR(self.optimizer, step_size=int(self.config.max_epochs / 3), gamma=self.config.gamma)
        
    def loss_op(self, data):
        y = data['label']
        y_pred = data['predict']
        y = y.type(torch.cuda.LongTensor)
        loss = nn.CrossEntropyLoss()
        loss = loss(y_pred, y)
        return loss
                
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
            data = {'data': x,
                    'label': y,
                    'attention_mask': batch[2].cuda()}
            y_pred = self.__call__(data)
            data['predict'] = y_pred
            loss = self.loss_op(data)
            loss.backward()
            losses.append(loss.data.cpu().numpy())
            self.optimizer.step()
            if i % 500 == 0:
                print("Iter: {}".format(i+1))
                avg_train_loss = np.mean(losses)
                train_losses.append(avg_train_loss)
                print("\tAverage training loss: {:.5f}".format(avg_train_loss))
                losses = []
                
                # Evalute Accuracy on validation set
                report = self.scorer.evaluate_model(self, val_iterator, "Validation")
                if (epoch  > 4 * self.config.max_epochs / 5 and self.best < report['precision']):
                    save_model(self, self.model_path)
                    self.best = report['precision']
                self.train()       
        return train_losses, val_accuracies

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
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        lstm_hiddens = config.lstm_hiddens * 2 if config.bidirectional else config.lstm_hiddens
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(lstm_hiddens, config.output_size))

    def forward(self, x):
        with torch.no_grad():
            logits = self.src_embed(x['data'], attention_mask=x['attention_mask']).last_hidden_state # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits
    
class MultiClassRobertaBiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassRobertaBiLSTM, self).__init__()
        self.config = config
        self.best = 0
        bertConfig = RobertaConfig.from_pretrained(config.model_name)

        # Embedding layer
        self.src_embed = RobertaModel.from_pretrained(config.model_name, config=bertConfig)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=bertConfig.hidden_size, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        lstm_hiddens = config.lstm_hiddens * 2 if config.bidirectional else config.lstm_hiddens
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(lstm_hiddens, config.output_size))

    def forward(self, x):
        with torch.no_grad():
            logits = self.src_embed(x['data'], attention_mask=x['attention_mask']).last_hidden_state # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits

class MultiClassGPT2BiLSTM(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassGPT2BiLSTM, self).__init__()
        self.config = config
        self.best = 0
        bertConfig = GPT2Config.from_pretrained(config.model_name)

        # Embedding layer
        self.src_embed = GPT2Model.from_pretrained(config.model_name, config=bertConfig)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=bertConfig.hidden_size, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        lstm_hiddens = config.lstm_hiddens * 2 if config.bidirectional else config.lstm_hiddens
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            # nn.Linear(config.lstm_hiddens * 2, config.lstm_hiddens * 2),
            nn.Linear(lstm_hiddens, config.output_size))

    def forward(self, x):
        with torch.no_grad():
            logits = self.src_embed(x['data'], attention_mask=x['attention_mask']).last_hidden_state # shape = (batch_size, sen_len, d_model)
        logits = self.bilstm(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits

class MultiClassCNN(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassCNN, self).__init__()
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
            # nn.Linear(config.num_channels*len(self.config.kernel_size), config.num_channels*len(self.config.kernel_size)),
            # nn.Linear(config.num_channels*len(self.config.kernel_size), config.num_channels*len(self.config.kernel_size)),
            nn.Linear(config.num_channels*len(self.config.kernel_size), config.output_size))

    def forward(self, x):
        logits = self.src_embed(x['data']).permute(0, 2, 1)
        # embedded_sent.shape = (batch_size=64,d_model=300,max_sen_len=20)
        a = logits.size()
        conv_out1 = self.conv1(logits).squeeze(2) #shape=(64, num_channels, 1) (squeeze 1)
        conv_out2 = self.conv2(logits).squeeze(2)
        conv_out3 = self.conv3(logits).squeeze(2)
        logits = torch.cat((conv_out1, conv_out2, conv_out3), 1)
        logits = self.classifier(logits)
        return logits

class MultiClassGru(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassGru, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.gru = nn.GRU(config.d_model, config.hidden_dim, config.layer_dim, batch_first=True, bidirectional=config.bidirectional)

        hidden_dim = config.hidden_dim * 2 if config.bidirectional else config.hidden_dim
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(hidden_dim, hidden_dim),
            # nn.Linear(hidden_dim, hidden_dim),
            nn.Linear(hidden_dim, config.output_size))

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.gru(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits

class MultiClassRNN(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassRNN, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.rnn = nn.RNN(config.d_model, config.hidden_dim, config.layer_dim, batch_first=True, bidirectional=config.bidirectional)

        hidden_dim = config.hidden_dim * 2 if config.bidirectional else config.hidden_dim
        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            # nn.Linear(hidden_dim, hidden_dim),
            # nn.Linear(hidden_dim, hidden_dim),
            nn.Linear(hidden_dim, config.output_size))

    def forward(self, x):
        logits = self.src_embed(x['data']) # shape = (batch_size, sen_len, d_model)
        logits = self.rnn(logits)[0][:, 0, :]
        logits = self.classifier(logits)
        return logits

class MultiClassBiLSTMCNN(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassBiLSTMCNN, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.bilstm = nn.LSTM(input_size=config.d_model, hidden_size=config.lstm_hiddens, num_layers=config.lstm_layers,
                        bidirectional=config.bidirectional, batch_first=True, bias=True)

        lstm_hiddens = config.lstm_hiddens * 2 if config.bidirectional else config.lstm_hiddens

        cnn_input = config.d_model + lstm_hiddens

        # CNN layer
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[0]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[0]+1)
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[1]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[1]+1)
        )
        self.conv3 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[2]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[2]+1)
        )

        # Dropout layer
        self.dropout = nn.Dropout(config.dropout)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.num_channels*len(self.config.kernel_size), config.output_size))

    def forward(self, x):
        embedding = self.src_embed(x['data'])
        # embedded_sent.shape = (batch_size=64,d_model=300,max_sen_len=20)
        lstm_output, _ = self.bilstm(embedding)
        logits = torch.cat((embedding, lstm_output), 2)
        logits = logits.permute(0, 2, 1)
        conv_out1 = self.conv1(logits).squeeze(2) #shape=(64, num_channels, 1) (squeeze 1)
        conv_out2 = self.conv2(logits).squeeze(2)
        conv_out3 = self.conv3(logits).squeeze(2)
        logits = torch.cat((conv_out1, conv_out2, conv_out3), 1)
        logits = self.classifier(logits)
        return logits
    
class MultiClassGruCNN(MultiClass):
    def __init__(self, config, src_vocab):
        super(MultiClassGruCNN, self).__init__()
        self.config = config
        # Embedding layer
        self.src_embed = Embeddings(config.d_model, src_vocab)

        # Bilstm layer
        self.gru = nn.GRU(config.d_model, config.hidden_dim, config.layer_dim, batch_first=True, bidirectional=config.bidirectional)

        hidden_dim = config.hidden_dim * 2 if config.bidirectional else config.hidden_dim
        cnn_input = config.d_model + hidden_dim

        # CNN layer
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[0]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[0]+1)
        )
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[1]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[1]+1)
        )
        self.conv3 = nn.Sequential(
            nn.Conv1d(in_channels=cnn_input, out_channels=self.config.num_channels, kernel_size=self.config.kernel_size[2]),
            nn.ReLU(),
            nn.MaxPool1d(self.config.max_sen_len - self.config.kernel_size[2]+1)
        )

        # Dropout layer
        self.dropout = nn.Dropout(config.dropout)

        # Fully-Connected Layer
        self.classifier = nn.Sequential(
            nn.Linear(config.num_channels*len(self.config.kernel_size), config.output_size))

    def forward(self, x):
        embedding = self.src_embed(x['data'])
        # embedded_sent.shape = (batch_size=64,d_model=300,max_sen_len=20)
        lstm_output, _ = self.gru(embedding)
        logits = torch.cat((embedding, lstm_output), 2)
        logits = logits.permute(0, 2, 1)
        conv_out1 = self.conv1(logits).squeeze(2) #shape=(64, num_channels, 1) (squeeze 1)
        conv_out2 = self.conv2(logits).squeeze(2)
        conv_out3 = self.conv3(logits).squeeze(2)
        logits = torch.cat((conv_out1, conv_out2, conv_out3), 1)
        logits = self.classifier(logits)
        return logits