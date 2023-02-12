from transformers import BertPreTrainedModel, BertModel
from torch.nn.utils.rnn import pad_sequence
import torch
from torchcrf import CRF
import math
import numpy as np

class BERTBiLSTMCRFConfig:
    name = "BERTBiLSTMCRF"
    dataset = "conll2003"
    dropout = 0.5
    output_size = 5
    lr = 3e-5
    lstm_lr = 2e-3
    crf_lr = 7.5e-3
    max_epochs = 100
    min_epochs = 5
    batch_size = 2
    max_sen_len = 200
    gamma = 0.99
    weight_decay = 0.001
    model_name = "sentence-transformers/all-MiniLM-L6-v2" #sentence-transformers/all-MiniLM-L6-v2  bert-base-uncased jackaduma/SecBERT kamalkraj/bert-base-cased-ner-conll2003
    full_finetuning = True
    clip_grad = 5
    patience = 0.02
    patience_num = 5
    lstm_hiddens = 768
    lstm_layers = 2
    bidirectional = True

class BERTBiLSTMCRF(BertPreTrainedModel):
    def __init__(self, config, params):
        super(BERTBiLSTMCRF, self).__init__(config)
        self.num_labels = config.num_labels

        self.bert = BertModel(config)
        self.bilstm = torch.nn.LSTM(input_size=config.hidden_size, hidden_size=params.lstm_hiddens, num_layers=params.lstm_layers,
                                bidirectional=True, batch_first=True, bias=True)
        self.dropout = torch.nn.Dropout(config.hidden_dropout_prob)
        self.classifier = torch.nn.Linear(params.lstm_hiddens * 2, config.num_labels)
        self.crf = CRF(num_tags=config.num_labels, batch_first=True)

        self.init_weights()

    def forward(self, input_data, token_type_ids=None, attention_mask=None, labels=None,
                position_ids=None, inputs_embeds=None, head_mask=None, use_crf=False):
        input_ids, input_token_starts = input_data
        outputs = self.bert(input_ids,
                            attention_mask=attention_mask,
                            token_type_ids=token_type_ids,
                            position_ids=position_ids,
                            head_mask=head_mask,
                            inputs_embeds=inputs_embeds)
        sequence_output = outputs[0]
        logits = self.__get_lstm_features(sequence_output, input_token_starts=input_token_starts)

        outputs = (logits,)
        if labels is not None:
            if use_crf:
                loss_mask = labels.gt(-1)
                if loss_mask is not None:
                    loss_mask = labels.gt(-1)
                    loss = -self.crf(emissions=logits, tags=labels, mask=loss_mask)
            else:
                loss_mask = labels.gt(-1)
                loss_fct = torch.nn.CrossEntropyLoss()
                if loss_mask is not None:
                    active_loss = loss_mask.view(-1) == 1
                    active_logits = logits.view(-1, self.num_labels)[active_loss]
                    active_labels = labels.view(-1)[active_loss]
                    loss = loss_fct(active_logits, active_labels)
                else:
                    loss = loss_fct(logits.view(-1, self.num_labels), labels.view(-1))
            outputs = (loss,) + outputs

        return outputs  # (loss), scores
    
    def __get_lstm_features(self, sequence_output, input_token_starts=None):
        seq_length = input_token_starts.sum(1)
        sorted_seq_length, perm_idx = seq_length.sort(descending=True)
        origin_sequence_output = [layer[starts.nonzero().squeeze(1)]
                                for layer, starts in zip(sequence_output, input_token_starts)]
        # 将sequence_output的pred_label维度padding到最大长度
        padded_sequence_output = pad_sequence(origin_sequence_output, batch_first=True)
        padded_sequence_output = padded_sequence_output[perm_idx, :, :]
        packed_sequence = torch.nn.utils.rnn.pack_padded_sequence(padded_sequence_output, sorted_seq_length.to('cpu'), batch_first=True)
        sequence_output = self.bilstm(packed_sequence)[0]
        sequence_output, _ = torch.nn.utils.rnn.pad_packed_sequence(sequence_output, batch_first=True)
        perm_idx = perm_idx.tolist()
        unperm_idx = [perm_idx.index(i) for i in range(len(perm_idx))]
        sequence_output = sequence_output[unperm_idx, :, :]
        sequence_output = self.dropout(sequence_output)
        logits = self.classifier(sequence_output)    
        return logits
