class BERTConfig:
    name = "BERTBiLSTMCRF"
    seed = 17
    dropout = 0.1
    output_size = 158
    lr = 3e-5
    linear_lr = 7.5e-3
    max_epochs = 100
    min_epochs = 5
    batch_size = 16
    max_sen_len = 200
    gamma = 0.99
    weight_decay = 0.001
    model_name = "bert-base-uncased" #sentence-transformers/all-MiniLM-L6-v2  bert-base-uncased jackaduma/SecBERT kamalkraj/bert-base-cased-ner-conll2003
    full_finetuning = True
    clip_grad = 5
    patience = 0.02
    patience_num = 10
    lstm_hiddens = 768
    lstm_layers = 2
    bidirectional = True
    train_file = './myData/learning/CVE2CWE/base/cve.train'
    test_file = './myData/learning/CVE2CWE/base/cve.test'
    label_path = './myData/learning/CVE2CWE/base/classification_base.labels'