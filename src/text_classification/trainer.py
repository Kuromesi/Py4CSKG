from TextClassification.utils.utils import *
from TextClassification.MultiLabel import *
from TextClassification.MutiClass import *
# from TextClassification.NER import *
import torch.optim as optim
from torch import nn
from TextClassification.utils.metric import *
import pandas as pd
# from models.utils.Dataset import *


class Trainer():
    def __init__(self, trainer_config, model_config):
        self.name = trainer_config.name
        self.model = trainer_config.model
        self.train_file = trainer_config.train_file
        self.test_file = trainer_config.test_file
        self.label_path = trainer_config.label_path
        self.model_path = trainer_config.model_path
        self.model_config = model_config
        if model_config.model_type == 'NER':
            self.dataset = NERDataset(model_config)
        else:
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
        elif self.model == 'NERBiLSTMCRF':
            self.run(NERBiLSTMCRF(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassCNN':
            self.run(MultiClassCNN(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassTransformer':
            self.run(MultiClassTransformer(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassRNN':
            self.run(MultiClassRNN(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassGru':
            self.run(MultiClassGru(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassBiLSTMCNN':
            self.run(MultiClassBiLSTMCNN(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassBert':
            self.run(MultiClassBert.from_pretrained(self.model_config.model_name, num_labels=self.model_config.output_size), self.model_config.model_type)
        elif self.model == 'MultiClassRobertaBiLSTM':
            self.run(MultiClassRobertaBiLSTM(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassGPT2BiLSTM':
            self.run(MultiClassGPT2BiLSTM(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)
        elif self.model == 'MultiClassGruCNN':
            self.run(MultiClassGruCNN(self.model_config, len(self.dataset.vocab)), self.model_config.model_type)

            

    def run(self, model, model_type):
        self.dataset.load_data(self.train_file, self.test_file)
        labels = loadLabels(self.label_path)
        model.model_path = self.model_path
        model.labels = labels
        model.cuda()
        model.train()
        model.add_optimizer(optim.Adam(model.parameters(), lr=self.model_config.lr, weight_decay=0.0002), self.model_config)
        
        train_losses = []
        val_accuracies = []
        for i in range(self.model_config.max_epochs):
            print ("Epoch: {}".format(i))
            print("\t Learning Rate: {:.5f}".format(model.optimizer.state_dict()['param_groups'][0]['lr']))
            train_loss, val_accuracy = model.run_epoch(self.dataset.train_iterator, self.dataset.val_iterator, i)
            model.attenuation.step()
            train_losses.append(train_loss)
            val_accuracies.append(val_accuracy)
            
        model = load_model(self.model_path)
        print("##########FINAL RESULTS##########")
        train_acc = model.scorer.evaluate_model(model, self.dataset.train_iterator, "Train")
        print("#################################")
        val_acc = model.scorer.evaluate_model(model, self.dataset.val_iterator, "Validation")
        print("#################################")
        test_acc = model.scorer.evaluate_model(model, self.dataset.test_iterator, "Test")
        print("#################################")
        res = pd.read_csv('./myData/learning/result.csv')
        res.loc[len(res.index)] = [self.name, test_acc['accuracy'], test_acc['precision'], test_acc['f1'], test_acc['recall']]
        res.to_csv('./myData/learning/result.csv', index=False)