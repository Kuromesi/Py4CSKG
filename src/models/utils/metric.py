import torch
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, f1_score, recall_score, classification_report

class MultiLabelScorer():
    def evaluate_model(self, model, iterator, name):
        all_preds = []
        all_y = []
        for idx,batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch[1].cuda()
                attention_mask = batch[2].cuda()
                y = batch[0].cuda()
            else:
                x = batch[1]
            y_pred = model((x, attention_mask))
            y_pred = y_pred.cpu().data
            predicted = torch.where(y_pred >= 0.3, 1, y_pred)
            predicted = torch.where(predicted < 0.3, 0, predicted)
            all_preds.extend(predicted.numpy())
            all_y.extend(batch[0].numpy())
        preds = np.array(all_preds)
        accuracy = accuracy_score(all_y, preds, normalize=True)
        precision = precision_score(all_y, preds, average='samples')
        f1 = f1_score(all_y, preds, average='samples')
        recall = recall_score(all_y, preds, average='samples')
        report = classification_report(all_y, preds, target_names=model.labels)
        print("\t{name} Accuracy: {score:.4f}".format(name=name, score=accuracy))
        print("\t{name} Precision: {score:.4f}".format(name=name, score=precision))
        print("\t{name} F1: {score:.4f}".format(name=name, score=f1))
        print("\t{name} Recall: {score:.4f}".format(name=name, score=recall))
        return accuracy, precision, f1, recall, report

class MultiClassScorer():
    def evaluate_model(self, model, iterator, name):
        all_preds = []
        all_y = []
        for idx,batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch[1].cuda()
                attention_mask = batch[2].cuda()
                attention_mask = batch[2].cuda()
            else:
                x = batch[1]
            y_pred = model((x, attention_mask))
            # predicted = torch.max(y_pred.cpu().data, 1)[1] + 1
            y_pred = y_pred.cpu().data
            predicted = torch.max(y_pred, 1)[1]
            all_preds.extend(predicted.numpy())
            all_y.extend(batch[0].numpy())
        preds = np.array(all_preds)
        accuracy = accuracy_score(all_y, preds, normalize=True)
        precision = precision_score(all_y, preds, average='micro')
        f1 = f1_score(all_y, preds, average='micro')
        recall = recall_score(all_y, preds, average='micro')
        print("\t{name} Accuracy: {score:.4f}".format(name=name, score=accuracy))
        print("\t{name} Precision: {score:.4f}".format(name=name, score=precision))
        print("\t{name} F1: {score:.4f}".format(name=name, score=f1))
        print("\t{name} Recall: {score:.4f}".format(name=name, score=recall))
        return accuracy, precision, f1, recall