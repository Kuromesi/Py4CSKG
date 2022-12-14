# utils.py

from torchtext.vocab import build_vocab_from_iterator
from torchtext.data.functional import to_map_style_dataset
from torchtext.data.utils import get_tokenizer
from torchtext.functional import to_tensor
from torch.utils.data import DataLoader, Dataset
from torch.utils.data.dataset import random_split
from torch.utils.data.dataloader import _SingleProcessDataLoaderIter, _MultiProcessingDataLoaderIter
from itertools import chain
from sklearn.metrics import accuracy_score, f1_score
import random
import torch
import numpy as np
import pickle
from transformers import AutoTokenizer

class BlockShuffleDataLoader(DataLoader):
    def __init__(self, dataset: Dataset, sort_key, sort_bs_num=None, is_shuffle=True, **kwargs):
        """
        初始化函数，继承DataLoader类
        Args:
            dataset: Dataset类的实例，其中中必须包含dataset变量，并且该变量为一个list
            sort_key: 排序函数，即使用dataset元素中哪一个变量的长度进行排序
            sort_bs_num: 排序范围，即在多少个batch_size大小内进行排序，默认为None，表示对整个序列排序
            is_shuffle: 是否对分块后的内容，进行随机打乱，默认为True
            **kwargs:
        """
        super().__init__(dataset, **kwargs)
        self.sort_bs_num = sort_bs_num
        self.sort_key = sort_key
        self.is_shuffle = is_shuffle

    def __iter__(self):
        self.dataset._data = self.block_shuffle(self.dataset._data, self.batch_size, self.sort_bs_num,
                                                        self.sort_key, self.is_shuffle)
        if self.num_workers == 0:
            return _SingleProcessDataLoaderIter(self)
        else:
            return _MultiProcessingDataLoaderIter(self)

    @staticmethod
    def block_shuffle(data, batch_size, sort_bs_num, sort_key, is_shuffle):
        random.shuffle(data)
        # 将数据按照batch_size大小进行切分
        tail_data = [] if len(data) % batch_size == 0 else data[-(len(data) % batch_size):]
        data = data[:len(data) - len(tail_data)]
        assert len(data) % batch_size == 0
        # 获取真实排序范围
        sort_bs_num = len(data) // batch_size if sort_bs_num is None else sort_bs_num
        # 按照排序范围进行数据划分
        data = [data[i:i + sort_bs_num * batch_size] for i in range(0, len(data), sort_bs_num * batch_size)]
        # 在排序范围，根据排序函数进行降序排列
        data = [sorted(i, key=sort_key, reverse=True) for i in data]
        # 将数据根据batch_size获取batch_data
        data = list(chain(*data))
        data = [data[i:i + batch_size] for i in range(0, len(data), batch_size)]
        # 判断是否需要对batch_data序列进行打乱
        if is_shuffle:
            random.shuffle(data)
        # 将tail_data填补回去
        data = list(chain(*data)) + tail_data
        return data

class Dataset():
    def __init__(self, config):
        self.config = config
        self.train_iterator = None
        self.test_iterator = None
        self.val_iterator = None
        
        self.word_embeddings = {}

        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        self.vocab = self.tokenizer.vocab

    def parse_label(self, label):
        '''
        Get the actual labels from label string
        Input:
            label (string) : labels of the form '__label__2'
        Returns:
            label (int) : integer value corresponding to label string
        '''
        label = label.split('|')
        if self.config.model_type == 'MultiClass':
            idx = int(label[0])
        elif self.config.model_type == 'MultiLabel':
            idx = [0.] * self.config.output_size
            for la in label:
                idx[int(la)] = 1.0
        return idx

    def yield_tokens(self, data_iter, tokenizer):
        for _, text in data_iter:
            yield tokenizer(text)

    def collate_batch(self, batch):
        label_list, text_list, offsets = [], [], [0]
        for (_label, _text) in batch:
            label_list.append(_label)
            text_list.append(_text)
            # processed_text = torch.tensor(self.text_pipeline(_text), dtype=torch.int64)
            # text_list.append(processed_text.tolist())
            # offsets.append(processed_text.size(0))
        text_list = self.tokenizer(text_list, padding=True, truncation=True, return_tensors="pt", max_length=self.config.max_sen_len)
        text_vec = text_list['input_ids']
        attention_mask = text_list['attention_mask']
        label_list = torch.tensor(label_list, dtype=torch.float32)
        # offsets = torch.tensor(offsets[:-1]).cumsum(dim=0)
        # text_list = to_tensor(text_list, padding_value=1.0).t()
        return label_list, text_vec, attention_mask

    def load_data(self, train_file, test_file=None, val_file=None):
        # tokenizer = lambda sent: [x.lemma_.lower() for x in NLP(sent) if x.lemma_.lower() != " "]
        # tokenizer = get_tokenizer('basic_english')
        with open(train_file, 'r') as datafile:     
                    data = [line.strip().split(',', maxsplit=1) for line in datafile if len(line.strip().split(',', maxsplit=1)) > 1]
                    data_text = list(map(lambda x: x[1], data))
                    data_label = list(map(lambda x: self.parse_label(x[0]), data))
        train = list(zip(data_label, data_text))
        train_iter = to_map_style_dataset(iter(train))
        self.label_pipeline = lambda x: int(x) - 1

        # Load test data
        with open(test_file, 'r') as datafile:     
            data = [line.strip().split(',', maxsplit=1) for line in datafile]
            data_text = list(map(lambda x: x[1], data))
            data_label = list(map(lambda x: self.parse_label(x[0]), data))
        test = list(zip(data_label, data_text))
        test_dataset = to_map_style_dataset(iter(test))

        num_train = int(len(train_iter) * 0.9)
        train_dataset, valid_dataset = random_split(train_iter, [num_train, len(train_iter) - num_train])
        train_dataset = to_map_style_dataset(train_dataset)
        valid_dataset = to_map_style_dataset(valid_dataset)
        sort_key=lambda x: len(x[1])
        self.train_iterator = BlockShuffleDataLoader(train_dataset, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.val_iterator = BlockShuffleDataLoader(valid_dataset, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.test_iterator = BlockShuffleDataLoader(test_dataset, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)

        print ("Loaded {} training examples".format(len(train_dataset)))
        print ("Loaded {} test examples".format(len(test_dataset)))
        print ("Loaded {} validation examples".format(len(valid_dataset)))

    def text2vec(self, text):
        return self.tokenizer(text, padding=True, truncation=True, return_tensors="pt", max_length=self.config.max_sen_len)

        
def evaluate_model(model, iterator):
    all_preds = []
    all_y = []
    for idx,batch in enumerate(iterator):
        if torch.cuda.is_available():
            x = batch[1].cuda()
            attention_mask = batch[2].cuda()
            y = batch[0].cuda()
        else:
            x = batch[1]
        y_pred = model(x)
        # predicted = torch.max(y_pred.cpu().data, 1)[1] + 1
        y_pred = y_pred.cpu().data
        predicted = torch.where(y_pred >= 0.3, 1, y_pred)
        predicted = torch.where(predicted < 0.3, 0, predicted)
        all_preds.extend(predicted.numpy())
        all_y.extend(batch[0].numpy())
    preds = np.array(all_preds)
    score = accuracy_score(all_y, preds, normalize=True, sample_weight=None)
    return score

def save_model(model, file_name):
    """用于保存模型"""
    with open(file_name, "wb") as f:
        pickle.dump(model, f)

def load_model(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

def loadLabels(path):
    with open(path, 'r') as f:
        labels = []
        for line in f:
            labels.append(line.strip())
    return labels