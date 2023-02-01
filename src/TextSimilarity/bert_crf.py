# config.py

class BERTCRFConfig(object):
    name = "BERTCRF"
    dataset = "conll2003"
    dropout = 0.2
    output_size = 9
    lr = 3e-5
    crf_lr = 7.5e-3
    max_epochs = 100
    min_epochs = 5
    batch_size = 64
    max_sen_len = 200
    gamma = 0.99
    weight_decay = 0.001
    model_name = "sentence-transformers/all-MiniLM-L6-v2" #sentence-transformers/all-MiniLM-L6-v2  bert-base-uncased jackaduma/SecBERT kamalkraj/bert-base-cased-ner-conll2003
    full_finetuning = True
    clip_grad = 5
    patience = 0.02
    patience_num = 100

class BertCNNCrfConfig(object):
    dropout = 0.1
    output_size = 9
    lr = 0.0015
    crf_lr = 0.01
    max_epochs = 60
    batch_size = 128
    max_sen_len = 200
    gamma = 0.5
    model_name = "bert-large-uncased" #bert-base-uncased jackaduma/SecBERT
    num_channels = 100
    kernel_size = [3,4,5]
    lstm_hiddens = 768
    lstm_layers = 2

class BiLSTMCRFConfig:
    model_type = 'MultiClass'
    dataset = "conll2003"
    d_model = 512 #512 in Transformer Paper
    dropout = 0.2
    output_size = 9
    lr = 0.015
    max_epochs = 30
    batch_size = 256
    max_sen_len = 200
    gamma = 0.95
    model_name = "sentence-transformers/all-MiniLM-L6-v2" #bert-base-uncased jackaduma/SecBERT
    lstm_hiddens = 768
    lstm_layers = 2
    bidirectional = True

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