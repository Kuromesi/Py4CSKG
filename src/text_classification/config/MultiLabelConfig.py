# config.py

class MultiLabelTransformerTacticConfig(object):
    class model_config:
        model_type = 'MultiLabel'
        N = 6 #6 in Transformer Paper
        d_model = 512 #512 in Transformer Paper
        d_ff = 2048 #2048 in Transformer Paper
        h = 8
        dropout = 0.2
        output_size = 11
        lr = 0.0005
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT

    class trainer_config:
        model = "MultiLabelTransformer"
        train_file = './myData/learning/CVE2Tactic/cve.train'
        test_file = './myData/learning/CVE2Tactic/cve.test'
        label_path = './myData/learning/CVE2Tactic/classification.labels'
        model_path = './ckpts/CVE2Tactic/MultiLabelTransformer.pkl'
    
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
        bidirectional = True

    class trainer_config:
        model = "MultiLabelBiLSTM"
        train_file = './myData/learning/CVE2Technique/cve.train'
        test_file = './myData/learning/CVE2Technique/cve.test'
        label_path = './myData/learning/CVE2Technique/classification.labels'
        model_path = './ckpts/CVE2Technique/MultiLabelBiLSTM.pkl'

class MultiLabelGruConfig(object):
    class model_config:
        model_type = 'MultiLabel'
        N = 6 #6 in Transformer Paper
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 48
        lr = 0.001
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        hidden_dim = 768
        layer_dim = 4

    class trainer_config:
        model = "MultiLabelGru"
        train_file = './myData/learning/CVE2Technique/cve.train'
        test_file = './myData/learning/CVE2Technique/cve.test'
        label_path = './myData/learning/CVE2Technique/classification.labels'
        model_path = './ckpts/CVE2Technique/MultiLabelGru.pkl'

class MultiLabelRNNConfig(object):
    class model_config:
        model_type = 'MultiLabel'
        N = 6 #6 in Transformer Paper
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 48
        lr = 0.0005
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        hidden_dim = 128
        layer_dim = 2

    class trainer_config:
        model = "MultiLabelRNN"
        train_file = './myData/learning/CVE2Technique/cve.train'
        test_file = './myData/learning/CVE2Technique/cve.test'
        label_path = './myData/learning/CVE2Technique/classification.labels'
        model_path = './ckpts/CVE2Technique/MultiLabelRNN.pkl'

class MultiLabelBiLSTMConfigTactic(object):
    class model_config:
        model_type = 'MultiLabel'
        N = 6 #6 in Transformer Paper
        d_model = 256 #512 in Transformer Paper
        d_ff = 512 #2048 in Transformer Paper
        h = 8
        dropout = 0.2
        output_size = 11
        lr = 0.0005
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        model = "MultiLabelBiLSTM"
        train_file = './myData/learning/CVE2Tactic/cve.train'
        test_file = './myData/learning/CVE2Tactic/cve.test'
        label_path = './myData/learning/CVE2Tactic/classification.labels'
        model_path = './ckpts/CVE2Tactic/MultiLabelLSTMCNN.pkl'