class MultiClassBiLSTMConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBiLSTM"
        model = "MultiClassBiLSTM"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBiLSTM.pkl'

class MultiClassBiLSTMBaseConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 38
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBiLSTMBase"
        model = "MultiClassBiLSTM"
        train_file = './myData/learning/CVE2CWE/base/cve.train'
        test_file = './myData/learning/CVE2CWE/base/cve.test'
        label_path = './myData/learning/CVE2CWE/base/classification_base.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBiLSTMBase.pkl'

class MultiClassBertBiLSTMConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBertBiLSTM"
        model = "MultiClassBertBiLSTM"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBertBiLSTM.pkl'
        
class MultiClassBiLSTMProcedureConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 8
        max_sen_len = 100
        gamma = 0.5
        model_name = "jackaduma/SecBERT" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBertBiLSTMProcedure"
        model = "MultiClassBertBiLSTM"
        train_file = './myData/learning/CVE2Tactic/cve_procedure.train'
        test_file = './myData/learning/CVE2Tactic/cve_procedure.test'
        label_path = './myData/learning/CVE2Tactic/classification.labels'
        model_path = './ckpts/CVE2Tactic/MultiClassBiLSTMProcedure.pkl'
        
class MultiClassBiLSTMNLPConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBiLSTMNLP"
        model = "MultiClassBiLSTM"
        train_file = './myData/learning/CVE2CWE/cve_nlp.train'
        test_file = './myData/learning/CVE2CWE/cve_nlp.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBiLSTMNLP.pkl'

class MultiClassCNNConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.0005
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        num_channels = 100
        kernel_size = [3,4,5]

    class trainer_config:
        name = "MultiClassCNN"
        model = "MultiClassCNN"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassCNN.pkl'

class MultiClassTransformerConfig(object):
    class model_config:
        model_type = 'MultiClass'
        N = 6 #6 in Transformer Paper
        d_model = 512 #512 in Transformer Paper
        d_ff = 2048 #2048 in Transformer Paper
        h = 8
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT

    class trainer_config:
        name = "MultiClassTransformer"
        model = "MultiClassTransformer"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassTransformer.pkl'

class MultiClassGruConfig(object):
    class model_config:
        model_type = 'MultiClass'
        N = 6 #6 in Transformer Paper
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        hidden_dim = 768
        layer_dim = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassGru"
        model = "MultiClassGru"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassGru.pkl'

class MultiClassRNNConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.0005
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        hidden_dim = 128
        layer_dim = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassRNN"
        model = "MultiClassRNN"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassRNN.pkl'

class MultiClassBiLSTMCNNConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 30
        batch_size = 256
        max_sen_len = 150
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        num_channels = 100
        kernel_size = [3,4,5]
        lstm_hiddens = 768
        lstm_layers = 2
        bidirectional = True

    class trainer_config:
        name = "MultiClassBiLSTMCNN"
        model = "MultiClassBiLSTMCNN"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassCNN.pkl'

class MultiClassBertConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 10
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "jackaduma/SecBERT" #bert-base-uncased jackaduma/SecBERT

    class trainer_config:
        name = "MultiClassBert"
        model = "MultiClassBert"
        train_file = './myData/learning/CVE2CWE/cve.train'
        test_file = './myData/learning/CVE2CWE/cve.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBert.pkl'