from models.utils.utils import *
from models.MultiLabel import *
from models.MutiClass import *
import torch.optim as optim
from torch import nn
from models.utils.metric import *


class Trainer():
    def __init__(self, trainer_config, model_config):
        self.model = trainer_config.model
        self.train_file = trainer_config.train_file
        self.test_file = trainer_config.test_file
        self.label_path = trainer_config.label_path
        self.model_path = trainer_config.model_path
        self.model_config = model_config
        self.dataset = Dataset(model_config)

    def train(self):
        if self.model == 'MultiLabelBiLSTM':
            self.run(MultiLabelBiLSTM(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassBiLSTM':
            self.run(MultiClassBiLSTM(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassBertBiLSTM':
            self.run(MultiClassBertBiLSTM(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiLabelGru':
            self.run(MultiLabelGru(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiLabelRNN':
            self.run(MultiLabelRNN(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiLabelTransformer':
            self.run(MultiLabelTransformer(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)

    def run(self, model, model_type):
        self.dataset.load_data(self.train_file, self.test_file)
        labels = loadLabels(self.label_path)

        if model_type == 'MultiLabel':
            model.scorer = MultiLabelScorer()
            model.add_loss_op(nn.BCELoss())
        elif model_type == 'MultiClass':
            model.scorer = MultiClassScorer()
            model.add_loss_op(nn.CrossEntropyLoss())
        model.model_path = self.model_path
        model.labels = labels
        model.cuda()
        model.train()
        model.add_optimizer(optim.Adam(model.parameters(), lr=self.model_config.lr, weight_decay=0.0002))
        
        train_losses = []
        val_accuracies = []
        for i in range(self.model_config.max_epochs):
            print ("Epoch: {}".format(i))
            print("\t Learning Rate: {:.5f}".format(model.optimizer.state_dict()['param_groups'][0]['lr']))
            train_loss,val_accuracy = model.run_epoch(self.dataset.train_iterator, self.dataset.val_iterator, i)
            model.attenuation.step()
            train_losses.append(train_loss)
            val_accuracies.append(val_accuracy)

        print("##########FINAL RESULTS##########")
        train_acc = model.scorer.evaluate_model(model, self.dataset.train_iterator, "Train")
        print("#################################")
        val_acc = model.scorer.evaluate_model(model, self.dataset.val_iterator, "Validation")
        print("#################################")
        test_acc = model.scorer.evaluate_model(model, self.dataset.test_iterator, "Test")
        print("#################################")