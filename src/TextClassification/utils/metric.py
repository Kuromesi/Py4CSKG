import torch
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, f1_score, recall_score, classification_report, confusion_matrix
from collections import defaultdict
from utils.utils import *
import pandas as pd
from utils.logger import *

def report2csv(report:str) -> pd.DataFrame:
    report = report.split('\n')
    header = ['name']
    header.extend(report[0].split())
    df = pd.DataFrame(columns=header)
    for i in range(1, len(report)):
        if len(report[i]) != 0 and len(report[i].split()) == len(header):
            df.loc[len(df.index)] = report[i].split()
    return df


class MultiLabelScorer():
    def evaluate_model(self, model, iterator, name):
        all_preds = []
        all_y = []
        for idx, batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch[1].cuda()
                attention_mask = batch[2].cuda()
                y = batch[0].cuda()
            else:
                x = batch[1]
            data = {'data': x,
                    'label': y,
                    'attention_mask': attention_mask}
            y_pred = model(data)
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
        report = classification_report(all_y, preds, target_names=model.labels, labels=range(len(model.labels)))
        print("\t{name} Accuracy: {score:.4f}".format(name=name, score=accuracy))
        print("\t{name} Precision: {score:.4f}".format(name=name, score=precision))
        print("\t{name} F1: {score:.4f}".format(name=name, score=f1))
        print("\t{name} Recall: {score:.4f}".format(name=name, score=recall))
        result = {'accuracy': accuracy,
                  'precision': precision,
                  'f1': f1,
                  'recall': recall,
                  'report': report}
        return result

class MultiClassScorer():
    def evaluate_model(self, model, iterator, name):
        all_preds = []
        all_y = []
        for idx, batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch['text_vec'].cuda()
                attention_mask = batch['attention_mask'].cuda()
                y = batch['label_vec'].cuda()
            else:
                x = batch[1]
            data = {'data': x,
                    'label': y,
                    'attention_mask': attention_mask}
            y_pred = model(x, attention_mask=attention_mask)[0]
            # predicted = torch.max(y_pred.cpu().data, 1)[1] + 1
            y_pred = y_pred.cpu().data
            predicted = torch.max(y_pred, 1)[1]
            all_preds.extend(predicted.numpy())
            all_y.extend(y.cpu().data.numpy())
        preds = np.array(all_preds)
        accuracy = accuracy_score(all_y, preds, normalize=True)
        precision = precision_score(all_y, preds, average='weighted')
        f1 = f1_score(all_y, preds, labels=model.labels, average='weighted')
        recall = recall_score(all_y, preds, labels=model.labels, average='weighted')
        # report = classification_report(all_y, preds, target_names=model.labels, labels=range(len(model.labels)), digits=4)
        # report = report2csv(report)
        # report = report.sort_values(by='precision', ascending=False)
        # confusion = confusion_matrix(all_y, preds)
        # print("\t{name} Accuracy: {score:.4f}".format(name=name, score=accuracy))
        # print("\t{name} Precision: {score:.4f}".format(name=name, score=precision))
        # print("\t{name} F1: {score:.4f}".format(name=name, score=f1))
        # print("\t{name} Recall: {score:.4f}".format(name=name, score=recall))
        # df = pd.DataFrame(confusion)
        # df.to_csv('myData/thesis/confusion_grucnn.csv')
        # result = {'accuracy': accuracy,
        #           'precision': precision,
        #           'f1': f1,
        #           'recall': recall,
        #           'report': report,
        #           'confusion': confusion} 
        result = {'accuracy': accuracy,
            'precision': precision,
            'f1': f1,
            'recall': recall} 
        return result

class BERTMultiClassScorer():
    def evaluate_model(self, model, iterator, name):
        all_preds = []
        all_y = []
        loss_avg = RunningAverage()
        for idx, batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch['text_vec'].cuda()
                attention_mask = batch['attention_mask'].cuda()
                y = batch['label_vec'].cuda()
            else:
                x = batch[1]
            data = {'data': x,
                    'label': y,
                    'attention_mask': attention_mask}
            loss, y_pred = model(x, labels=y, attention_mask=attention_mask)
            loss_avg.update(loss.item())
            # predicted = torch.max(y_pred.cpu().data, 1)[1] + 1
            y_pred = y_pred.cpu().data
            predicted = torch.max(y_pred, 1)[1]
            all_preds.extend(predicted.numpy())
            all_y.extend(y.cpu().data.numpy())
        preds = np.array(all_preds)
        accuracy = 100 * accuracy_score(all_y, preds, normalize=True)
        precision = 100 * precision_score(all_y, preds, average='weighted')
        f1 = 100 * f1_score(all_y, preds, labels=model.labels, average='weighted')
        recall = 100 * recall_score(all_y, preds, labels=model.labels, average='weighted')
        metrics = {}
        metrics['precision'] = precision
        metrics['f1'] = f1
        metrics['loss'] = loss_avg()
        metrics_str = "; ".join("{}: {:05.2f}".format(k, v) for k, v in metrics.items())
        logging.info("- {} metrics: ".format(name) + metrics_str)
        result = {'accuracy': accuracy,
            'precision': precision,
            'f1': f1,
            'recall': recall} 
        return result


class NERScorer():
    def __init__(self, labels):
        self.labels = labels

    def id2tag(self, id):
        tags = [[self.labels[y] for y in x] for x in id]
        return tags

    def evaluate_model(self, model, iterator):
        all_preds = []
        all_y = []
        for idx, batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch[1].cuda()
                attention_mask = batch[2].cuda()
                y = batch[0].cuda()
            else:
                x = batch[1]
            y_pred, loss = model(x, attention_mask=attention_mask, labels=y)
            y_pred = model.crf.decode(y_pred)
            all_preds.extend(self.id2tag(y_pred))
            all_y.extend(self.id2tag(batch[0].tolist()))
        accuracy = self.accuracy_score(all_y, all_preds)
        f1, precision, recall = self.f1_score(all_y, all_preds)
        return accuracy, f1, precision, recall

    def create_report(self, model, iterator):
        all_preds = []
        all_y = []
        for idx, batch in enumerate(iterator):
            if torch.cuda.is_available():
                x = batch[1].cuda()
                attention_mask = batch[2].cuda()
                y = batch[0].cuda()
            else:
                x = batch[1]
            y_pred, loss = model(x, attention_mask=attention_mask, labels=y)
            y_pred = model.crf.decode(y_pred)
            all_preds.extend(self.id2tag(y_pred))
            all_y.extend(self.id2tag(batch[0].tolist()))
        return self.classification_report(all_y, all_preds)

    def get_entities(self, seq, suffix=False):
        """Gets entities from sequence.
        Args:
            seq (list): sequence of labels.
        Returns:
            list: list of (chunk_type, chunk_start, chunk_end).
        Example:
            >>> from seqeval.metrics.sequence_labeling import get_entities
            >>> seq = ['B-PER', 'I-PER', 'O', 'B-LOC']
            >>> get_entities(seq)
            [('PER', 0, 1), ('LOC', 3, 3)]
        """
        # for nested list
        if any(isinstance(s, list) for s in seq):
            seq = [item for sublist in seq for item in sublist + ['O']]

        prev_tag = 'O'
        prev_type = ''
        begin_offset = 0
        chunks = []
        for i, chunk in enumerate(seq + ['O']):
            if suffix:
                tag = chunk[-1]
                type_ = chunk.split('-')[0]
            else:
                tag = chunk[0]
                type_ = chunk.split('-')[-1]

            if self.end_of_chunk(prev_tag, tag, prev_type, type_):
                chunks.append((prev_type, begin_offset, i-1))
            if self.start_of_chunk(prev_tag, tag, prev_type, type_):
                begin_offset = i
            prev_tag = tag
            prev_type = type_

        return chunks


    def end_of_chunk(self, prev_tag, tag, prev_type, type_):
        """Checks if a chunk ended between the previous and current word.
        Args:
            prev_tag: previous chunk tag.
            tag: current chunk tag.
            prev_type: previous type.
            type_: current type.
        Returns:
            chunk_end: boolean.
        """
        chunk_end = False

        if prev_tag == 'E': chunk_end = True
        if prev_tag == 'S': chunk_end = True

        if prev_tag == 'B' and tag == 'B': chunk_end = True
        if prev_tag == 'B' and tag == 'S': chunk_end = True
        if prev_tag == 'B' and tag == 'O': chunk_end = True
        if prev_tag == 'I' and tag == 'B': chunk_end = True
        if prev_tag == 'I' and tag == 'S': chunk_end = True
        if prev_tag == 'I' and tag == 'O': chunk_end = True

        if prev_tag != 'O' and prev_tag != '.' and prev_type != type_:
            chunk_end = True

        return chunk_end


    def start_of_chunk(self, prev_tag, tag, prev_type, type_):
        """Checks if a chunk started between the previous and current word.
        Args:
            prev_tag: previous chunk tag.
            tag: current chunk tag.
            prev_type: previous type.
            type_: current type.
        Returns:
            chunk_start: boolean.
        """
        chunk_start = False

        if tag == 'B': chunk_start = True
        if tag == 'S': chunk_start = True

        if prev_tag == 'E' and tag == 'E': chunk_start = True
        if prev_tag == 'E' and tag == 'I': chunk_start = True
        if prev_tag == 'S' and tag == 'E': chunk_start = True
        if prev_tag == 'S' and tag == 'I': chunk_start = True
        if prev_tag == 'O' and tag == 'E': chunk_start = True
        if prev_tag == 'O' and tag == 'I': chunk_start = True

        if tag != 'O' and tag != '.' and prev_type != type_:
            chunk_start = True

        return chunk_start

    def f1_score(self, y_true, y_pred, average='micro', digits=2, suffix=False):
        """Compute the F1 score.
        The F1 score can be interpreted as a weighted average of the precision and
        recall, where an F1 score reaches its best value at 1 and worst score at 0.
        The relative contribution of precision and recall to the F1 score are
        equal. The formula for the F1 score is::
            F1 = 2 * (precision * recall) / (precision + recall)
        Args:
            y_true : 2d array. Ground truth (correct) target values.
            y_pred : 2d array. Estimated targets as returned by a tagger.
        Returns:
            score : float.
        Example:
            >>> from seqeval.metrics import f1_score
            >>> y_true = [['O', 'O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> y_pred = [['O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> f1_score(y_true, y_pred)
            0.50
        """
        true_entities = set(self.get_entities(y_true, suffix))
        pred_entities = set(self.get_entities(y_pred, suffix))

        nb_correct = len(true_entities & pred_entities)
        nb_pred = len(pred_entities)
        nb_true = len(true_entities)

        p = 100 * nb_correct / nb_pred if nb_pred > 0 else 0
        r = 100 * nb_correct / nb_true if nb_true > 0 else 0
        score = 2 * p * r / (p + r) if p + r > 0 else 0

        return score, p, r


    def accuracy_score(self, y_true, y_pred):
        """Accuracy classification score.
        In multilabel classification, this function computes subset accuracy:
        the set of labels predicted for a sample must *exactly* match the
        corresponding set of labels in y_true.
        Args:
            y_true : 2d array. Ground truth (correct) target values.
            y_pred : 2d array. Estimated targets as returned by a tagger.
        Returns:
            score : float.
        Example:
            >>> from seqeval.metrics import accuracy_score
            >>> y_true = [['O', 'O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> y_pred = [['O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> accuracy_score(y_true, y_pred)
            0.80
        """
        if any(isinstance(s, list) for s in y_true):
            y_true = [item for sublist in y_true for item in sublist]
            y_pred = [item for sublist in y_pred for item in sublist]

        nb_correct = sum(y_t==y_p for y_t, y_p in zip(y_true, y_pred))
        nb_true = len(y_true)

        score = nb_correct / nb_true

        return score


    def classification_report(self, y_true, y_pred, digits=2, suffix=False):
        """Build a text report showing the main classification metrics.
        Args:
            y_true : 2d array. Ground truth (correct) target values.
            y_pred : 2d array. Estimated targets as returned by a classifier.
            digits : int. Number of digits for formatting output floating point values.
        Returns:
            report : string. Text summary of the precision, recall, F1 score for each class.
        Examples:
            >>> from seqeval.metrics import classification_report
            >>> y_true = [['O', 'O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> y_pred = [['O', 'O', 'B-MISC', 'I-MISC', 'I-MISC', 'I-MISC', 'O'], ['B-PER', 'I-PER', 'O']]
            >>> print(classification_report(y_true, y_pred))
                        precision    recall  f1-score   support
            <BLANKLINE>
                MISC       0.00      0.00      0.00         1
                    PER       1.00      1.00      1.00         1
            <BLANKLINE>
            avg / total       0.50      0.50      0.50         2
            <BLANKLINE>
        """
        true_entities = set(self.get_entities(y_true, suffix))
        pred_entities = set(self.get_entities(y_pred, suffix))

        name_width = 0
        d1 = defaultdict(set)
        d2 = defaultdict(set)
        for e in true_entities:
            d1[e[0]].add((e[1], e[2]))
            name_width = max(name_width, len(e[0]))
        for e in pred_entities:
            d2[e[0]].add((e[1], e[2]))

        last_line_heading = 'avg / total'
        width = max(name_width, len(last_line_heading), digits)

        headers = ["precision", "recall", "f1-score", "support"]
        head_fmt = u'{:>{width}s} ' + u' {:>9}' * len(headers)
        report = head_fmt.format(u'', *headers, width=width)
        report += u'\n\n'

        row_fmt = u'{:>{width}s} ' + u' {:>9.{digits}f}' * 3 + u' {:>9}\n'

        ps, rs, f1s, s = [], [], [], []
        for type_name, true_entities in d1.items():
            pred_entities = d2[type_name]
            nb_correct = len(true_entities & pred_entities)
            nb_pred = len(pred_entities)
            nb_true = len(true_entities)

            p = 100 * nb_correct / nb_pred if nb_pred > 0 else 0
            r = 100 * nb_correct / nb_true if nb_true > 0 else 0
            f1 = 2 * p * r / (p + r) if p + r > 0 else 0

            report += row_fmt.format(*[type_name, p, r, f1, nb_true], width=width, digits=digits)

            ps.append(p)
            rs.append(r)
            f1s.append(f1)
            s.append(nb_true)

        report += u'\n'

        # compute averages
        report += row_fmt.format(last_line_heading,
                                np.average(ps, weights=s),
                                np.average(rs, weights=s),
                                np.average(f1s, weights=s),
                                np.sum(s),
                                width=width, digits=digits)

        return report

class Scorer():
    def __init__(self, config):
        self.dataset = Dataset(config.model_config)
        self.dataset.load_data(config.trainer_config.train_file, config.trainer_config.test_file)
    def evaluate(self, model):
        result = model.scorer.evaluate_model(model, self.dataset.test_iterator, 'Test')
        print(result['report'])
        return result['report']