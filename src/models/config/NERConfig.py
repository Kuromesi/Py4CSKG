class NERBiLSTMConfig(object):
    class model_config:
        model_type = 'NER'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2

    class trainer_config:
        model = "MultiClassBiLSTM"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBiLSTM.pkl'