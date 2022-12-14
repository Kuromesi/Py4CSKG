# train.py

from models.utils.utils import *
from models.MultiLabel import *
from models.config.MultiLabelConfig import *
from models.config.MultiClassConfig import *
from models.trainer import *

if __name__=='__main__':
    # config = MultiLabelBiLSTMConfig()
    config = MultiClassBiLSTMConfig()
    trainer_config = config.trainer_config
    model_config = config.model_config
    trainer = Trainer(trainer_config=trainer_config, model_config=model_config)
    trainer.train()

