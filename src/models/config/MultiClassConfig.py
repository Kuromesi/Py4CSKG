class MultiClassBiLSTMConfig(object):
    class model_config:
        model_type = 'MultiClass'
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

class MultiClassBertBiLSTMConfig(object):
    class model_config:
        model_type = 'MultiClass'
        d_model = 256 #512 in Transformer Paper
        dropout = 0.2
        output_size = 295
        lr = 0.001
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "jackaduma/SecBERT" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2

    class trainer_config:
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
        max_epochs = 60
        batch_size = 8
        max_sen_len = 100
        gamma = 0.5
        model_name = "jackaduma/SecBERT" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2

    class trainer_config:
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
        max_epochs = 60
        batch_size = 256
        max_sen_len = 100
        gamma = 0.5
        model_name = "bert-base-uncased" #bert-base-uncased jackaduma/SecBERT
        lstm_hiddens = 768
        lstm_layers = 2

    class trainer_config:
        model = "MultiClassBiLSTM"
        train_file = './myData/learning/CVE2CWE/cve_nlp.train'
        test_file = './myData/learning/CVE2CWE/cve_nlp.test'
        label_path = './myData/learning/CVE2CWE/classification.labels'
        model_path = './ckpts/CVE2CWE/MultiClassBiLSTMNLP.pkl'