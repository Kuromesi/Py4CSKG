import torch
import torch.nn as nn
import numpy as np
from TextClassification.utils.utils import *
import abc

class Model(nn.Module):
    best = 0
    @abc.abstractmethod
    def forward(self):
        return

    def add_optimizer(self, optimizer):
        self.optimizer = optimizer
        # Exponential
        # self.attenuation = torch.optim.lr_scheduler.ExponentialLR(self.optimizer, gamma=self.config.gamma)
        
        # Step
        self.attenuation = torch.optim.lr_scheduler.StepLR(self.optimizer, step_size=int(self.config.max_epochs / 3), gamma=self.config.gamma)
        
    def add_loss_op(self, loss_op):
        self.loss_op = loss_op
                
    def run_epoch(self, train_iterator, val_iterator, epoch):
        train_losses = []
        val_accuracies = []
        losses = []
            
        for i, batch in enumerate(train_iterator):
            self.optimizer.zero_grad()
            if torch.cuda.is_available():
                x = batch[1].cuda()
                # y = (batch[0] - 1).type(torch.cuda.LongTensor)
                y = batch[0].cuda()
            else:
                x = batch[1].type(torch.LongTensor)
                # y = (batch[0] - 1).type(torch.LongTensor)
                y = batch[0]
            data = {'data': x,
                    'label': y,
                    'attention_mask': batch[2].cuda()}
            y_pred = self.__call__(data)
            data['predict'] = y_pred
            loss = self.loss_op(data)
            loss.backward()
            losses.append(loss.data.cpu().numpy())
            self.optimizer.step()
            if i % 50 == 0:
                print("Iter: {}".format(i+1))
                avg_train_loss = np.mean(losses)
                train_losses.append(avg_train_loss)
                print("\tAverage training loss: {:.5f}".format(avg_train_loss))
                losses = []
                
                # Evalute Accuracy on validation set
                report = self.scorer.evaluate_model(self, val_iterator, "Validation")
                if (epoch  > 4 * self.config.max_epochs / 5 and self.best < report['precision']):
                    save_model(self, self.model_path)
                    self.best = report['precision']
                self.train()       
        return train_losses, val_accuracies