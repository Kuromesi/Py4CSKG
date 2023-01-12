# train.py

from models.utils.utils import *
from models.MultiLabel import *
from models.config.MultiLabelConfig import *
from models.config.MultiClassConfig import *
from models.trainer import *

def multi_train():
    config = [MultiClassBiLSTMConfig(),
              MultiClassBertBiLSTMConfig(),
              MultiClassCNNConfig(),
              MultiClassGruConfig(),
              MultiClassRNNConfig(),
              MultiClassTransformerConfig(),
              MultiClassBiLSTMCNNConfig()]
    config = [MultiClassBiLSTMBaseConfig(),
              MultiClassBertBiLSTMBaseConfig(),
              MultiClassCNNBaseConfig(),
              MultiClassGruBaseConfig(),
              MultiClassRNNBaseConfig(),
              MultiClassTransformerBaseConfig(),
              MultiClassBiLSTMCNNBaseConfig()]
    config = [MultiClassGPT2BiLSTMBaseConfig(),
              MultiClassRobertaBiLSTMBaseConfig()]
    for conf in config:
        trainer_config = conf.trainer_config
        model_config = conf.model_config
        trainer = Trainer(trainer_config=trainer_config, model_config=model_config)
        trainer.train()

def train():
    # config = MultiLabelBiLSTMConfig()
    # config = MultiLabelGruConfig()
    # config = MultiLabelRNNConfig()
    # config = MultiClassBiLSTMBaseConfig()
    # config = MultiClassBiLSTMBaseNLPConfig()
    # config = MultiClassBiLSTMCNNBaseConfig()
    # config = MultiClassBiLSTMNSConfig(
    # config = MultiClassBiLSTMCNNNSConfig()
    # config = MultiClassBiLSTMConfig()
    # config = MultiClassBertBiLSTMConfig()
    # config = MultiClassGPT2BiLSTMConfig()
    config = MultiClassGruCNNBaseConfig()
    # config = MultiClassRobertaBiLSTMConfig()
    # config = MultiLabelBiLSTMConfigTactic()
    # config = MultiLabelTransformerTacticConfig()
    # config = MultiClassBiLSTMProcedureConfig()
    # config = MultiClassCNNConfig()
    # config = MultiClassGruConfig()
    # config = MultiClassBiLSTMCNNConfig()
    # config = MultiClassRNNConfig()
    # config = MultiClassTransformerConfig()
    # config = MultiClassBertConfig()
    # config = MultiClassBiLSTMNLPConfig()
    trainer_config = config.trainer_config
    model_config = config.model_config
    trainer = Trainer(trainer_config=trainer_config, model_config=model_config)
    trainer.train()

def multiLabelPredict():
    model = load_model('ckpts/CVE2Technique/MultiLabelBiLSTM.pkl')
    config = model.config
    dataset = Dataset(config)
    text = "Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are affected by an improper authorization vulnerability in the integrations module. Successful exploitation could lead to unauthorized access to restricted resources by an unauthenticated attacker. Access to the admin console is required for successful exploitation."
    text_vec = dataset.text2vec(text)
    pred = model((text_vec['input_ids'].cuda(), text_vec['attention_mask'].cuda()))
    # pred = model(text_vec['input_ids'].cuda())
    pred = pred.cpu().data
    # pred = torch.where(pred >= 0.3, 1, pred)
    # pred = torch.where(pred < 0.3, 0, pred)
    pred = pred.tolist()[0]
    labels = model.labels
    for i in range(len(labels)):
        if pred[i] > 0.3:
            print("Label: %s, P: %f"%(labels[i], pred[i]))

def multiClassPredict():
    model = load_model('ckpts/CVE2CWE/MultiClassGruBase.pkl')
    config = model.config
    dataset = Dataset(config)
    text = "A remote script injection vulnerability was discovered in HPE 3PAR StoreServ Management and Core Software Media version(s): prior to 3.5.0.1."
    text_vec = dataset.text2vec(text)
    data = {'data': text_vec['input_ids'].cuda(), 'attention_mask': text_vec['attention_mask'].cuda()}
    pred = model(data)
    pred = pred.cpu().data
    pred = torch.max(pred, 1)[1]
    labels = model.labels
    print(labels[pred[0]])

def evaluate():
    config = [MultiClassBiLSTMConfig(),
              MultiClassBertBiLSTMConfig(),
              MultiClassCNNConfig(),
              MultiClassGruConfig(),
              MultiClassRNNConfig(),
              MultiClassTransformerConfig()]
    # config = [MultiClassBiLSTMBaseConfig]
    config = [MultiClassBiLSTMBaseConfig(),
              MultiClassBertBiLSTMBaseConfig(),
              MultiClassCNNBaseConfig(),
              MultiClassGruBaseConfig(),
              MultiClassRNNBaseConfig(),
              MultiClassTransformerBaseConfig(),
              MultiClassBiLSTMCNNBaseConfig()]
    config = [MultiClassGPT2BiLSTMBaseConfig(),
              MultiClassRobertaBiLSTMBaseConfig()]
    config = [MultiClassGruBaseConfig()]
    for conf in config:
        scorer = Scorer(conf)
        model = load_model(conf.trainer_config.model_path)
        report = scorer.evaluate(model)
        report.to_csv('./myData/learning/evaluation/%s.csv'%conf.trainer_config.name, index=False)

if __name__=='__main__':
    # train()
    # multi_train()
    # multiClassPredict()
    # multiLabelPredict()
    evaluate()