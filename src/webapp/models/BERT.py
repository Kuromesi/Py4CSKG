from transformers import BertPreTrainedModel, BertModel
from torch.nn.utils.rnn import pad_sequence
import torch
from torchcrf import CRF

class BERTConfig:
    name = "BERTBiLSTMCRF"
    seed = 17
    dropout = 0.1
    output_size = 295
    lr = 3e-5
    linear_lr = 7.5e-3
    max_epochs = 100
    min_epochs = 5
    batch_size = 64
    max_sen_len = 200
    gamma = 0.99
    weight_decay = 0.001
    model_name = "jackaduma/SecBERT" #sentence-transformers/all-MiniLM-L6-v2  bert-base-uncased jackaduma/SecBERT kamalkraj/bert-base-cased-ner-conll2003
    full_finetuning = True
    clip_grad = 5
    patience = 0.02
    patience_num = 10
    lstm_hiddens = 768
    lstm_layers = 2
    bidirectional = True
    train_file = './myData/learning/CVE2CWE/base/cve.test'
    test_file = './myData/learning/CVE2CWE/base/cve.test'
    label_path = './myData/learning/CVE2CWE/classification.labels'

class BERT(BertPreTrainedModel):
    def __init__(self, config):
        super(BERT, self).__init__(config)
        self.num_labels = config.num_labels
        self.bert = BertModel(config)
        self.dropout = torch.nn.Dropout(config.hidden_dropout_prob)
        self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)
        self.init_weights()

    def forward(self, input_data, token_type_ids=None, attention_mask=None, labels=None,
                position_ids=None, inputs_embeds=None, head_mask=None, use_crf=False):
        input_ids = input_data
        outputs = self.bert(input_ids,
                            attention_mask=attention_mask,
                            token_type_ids=token_type_ids,
                            position_ids=position_ids,
                            head_mask=head_mask,
                            inputs_embeds=inputs_embeds)
        sequence_output = outputs[0]
        mask = attention_mask.unsqueeze(-1).expand(sequence_output.size()).float()
        sequence_output = self.dropout(sequence_output)
        summed = torch.sum(sequence_output, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        logits = self.classifier(mean_pooled)    
        outputs = (logits, )
        if labels != None:
            y = labels
            y_pred = logits
            y = y.type(torch.cuda.LongTensor)
            loss = self.loss_func(y_pred, y)
            outputs = (loss, ) + outputs

        
        return outputs  # (loss), scores
