# train.py

from models.utils.utils import *
from models.MultiLabel import *
from models.config.MultiLabelConfig import *
from models.config.MultiClassConfig import *
from models.trainer import *

def train():
    # config = MultiLabelBiLSTMConfig()
    # config = MultiLabelGruConfig()
    # config = MultiLabelRNNConfig()
    # config = MultiClassBiLSTMConfig()
    # config = MultiClassBertBiLSTMConfig()
    # config = MultiLabelBiLSTMConfigTactic()
    # config = MultiLabelTransformerTacticConfig()
    # config = MultiClassBiLSTMProcedureConfig()
    # config = MultiClassCNNConfig()
    config = MultiClassTransformerConfig()
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
    model = load_model('ckpts/CVE2Tactic/MultiClassBiLSTMProcedure.pkl')
    config = model.config
    dataset = Dataset(config)
    text = "Possible system denial of service in case of arbitrary changing Firefox browser parameters. An attacker could change specific Firefox browser parameters file in a certain way and then reboot the system to make the system unbootable."
    text_vec = dataset.text2vec(text)
    pred = model((text_vec['input_ids'].cuda(), text_vec['attention_mask'].cuda()))
    pred = pred.cpu().data
    pred = torch.max(pred, 1)[1]
    labels = model.labels
    print(labels[pred[0]])

if __name__=='__main__':
    train()
    # multiClassPredict()
    # multiLabelPredict()