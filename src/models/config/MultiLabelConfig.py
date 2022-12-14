# config.py

class TransformerConfig(object):
    N = 6 #6 in Transformer Paper
    d_model = 256 #512 in Transformer Paper
    d_ff = 512 #2048 in Transformer Paper
    h = 8
    dropout = 0.2
    output_size = 48
    lr = 0.0005
    max_epochs = 60
    batch_size = 256
    max_sen_len = 100
    gamma = 0.5
    model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
    num_channels = 100
    kernel_size = [3,4,5]
    lstm_hiddens = 768
    lstm_layers = 2
    
class MultiLabelBiLSTMConfig(object):
    class model_config:
        model_type = 'MultiLabel'
        N = 6 #6 in Transformer Paper
        d_model = 256 #512 in Transformer Paper
        d_ff = 512 #2048 in Transformer Paper
        h = 8
        dropout = 0.2
        output_size = 48
        lr = 0.0005
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2

    class trainer_config:
        model = "MultiLabelBiLSTM"
        train_file = './myData/learning/CVE2Technique/cve.train'
        test_file = './myData/learning/CVE2Technique/cve.test'
        label_path = './myData/learning/CVE2Technique/classification.labels'
        model_path = './ckpts/CVE2Technique/MultiLabelBiLSTM.pkl'