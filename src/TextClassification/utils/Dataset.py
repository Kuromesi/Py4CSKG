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
import pandas as pd

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
        text_list = self.tokenizer(text_list, padding=True, truncation=True, 
                                    return_tensors="pt", max_length=self.config.max_sen_len) # padding='max_length'
        text_vec = text_list['input_ids']
        attention_mask = text_list['attention_mask']
        label_list = torch.tensor(label_list, dtype=torch.float32)
        return label_list, text_vec, attention_mask

    def df2iter(self, df:pd.DataFrame):
        text = df['text'].tolist()
        label = df['label'].tolist()
        label = list(map(lambda x: self.parse_label(x), label))
        _iter = to_map_style_dataset(iter(list(zip(label, text))))
        return _iter

    def load_data(self, train_file, test_file):
        train_df = pd.read_csv(train_file)
        test_df = pd.read_csv(test_file)
        train_iter = self.df2iter(train_df)
        test_iter = self.df2iter(test_df)

        num_train = int(len(train_iter) * 0.9)
        train_dataset, valid_dataset = random_split(train_iter, [num_train, len(train_iter) - num_train])
        train_dataset = to_map_style_dataset(train_dataset)
        valid_dataset = to_map_style_dataset(valid_dataset)

        sort_key=lambda x: len(x[1])
        self.train_iterator = BlockShuffleDataLoader(train_dataset, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.val_iterator = BlockShuffleDataLoader(valid_dataset, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.test_iterator = BlockShuffleDataLoader(test_iter, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)

        print ("Loaded {} training examples".format(len(train_dataset)))
        print ("Loaded {} test examples".format(len(test_iter)))
        print ("Loaded {} validation examples".format(len(valid_dataset)))

    def text2vec(self, text):
        return self.tokenizer(text, padding=True, truncation=True, return_tensors="pt", max_length=self.config.max_sen_len)

class NERDataset():
    def __init__(self, config, labels):
        self.config = config
        self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
        self.labels = labels
        self.label_pipe = lambda x: self.labels.index(x)

    def parse_label(self, label):
        '''
        Get the actual labels from label string
        Input:
            label (string) : labels of the form '__label__2'
        Returns:
            label (int) : integer value corresponding to label string
        '''
        label = label.split('|')
        idx = [0.] * 11
        for la in label:
            idx[int(la)] = 1.0
        return idx

    def yield_tokens(self, data_iter, tokenizer):
        for _, text in data_iter:
            yield tokenizer(text)

    def collate_batch(self, batch):
        label_list, text_list = [], []
        for (_label, _text) in batch:
            label_list.append(_label)
            text_list.append(_text)
        text_list = self.tokenizer(text=text_list, padding=True, truncation=True, return_tensors="pt", max_length=self.config.max_sen_len, is_split_into_words=True)
        word_ids = text_list.word_ids(1)
        text_vec = text_list['input_ids']
        attention_mask = text_list['attention_mask']

        # Align label
        label_vec = []
        temp = []
        for i in range(len(label_list)):
            word_ids = text_list.word_ids(i)
            for id in word_ids:
                if id == None:
                    temp.append(0)
                else:
                    temp.append(self.label_pipe(label_list[i][id]))
            label_vec.append(temp)
            temp = []
                
        label_vec = torch.tensor(label_vec, dtype=torch.long)
        return label_vec, text_vec, attention_mask

    def __read(self, path):
        with open(path, 'r') as f:
            label = []
            text = []
            data = []
            for line in f.readlines():
                line = line.strip().split()
                if len(line) < 2:
                    data.append((label, text))
                    label = []
                    text = []
                else:
                    label.append(line[3]) # change this for different format label
                    text.append(line[0])
        return to_map_style_dataset(iter(data))


    def load_data(self, train_file, test_file=None, val_file=None):
        # load train, test, validation data
        train_iter = self.__read(train_file)
        test_iter = self.__read(test_file)
        if val_file:
            val_iter = self.__read(val_file)
        else:
            num_train = int(len(train_iter) * 0.95)
            train_iter, val_iter = random_split(train_iter, [num_train, len(train_iter) - num_train])
            train_iter = to_map_style_dataset(train_iter)
            val_iter = to_map_style_dataset(val_iter)
        
        sort_key=lambda x: len(x[1])
        self.train_iterator = BlockShuffleDataLoader(train_iter, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.val_iterator = BlockShuffleDataLoader(val_iter, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)
        self.test_iterator = BlockShuffleDataLoader(test_iter, batch_size=self.config.batch_size,
                                    shuffle=True, collate_fn=self.collate_batch, sort_key=sort_key)

        print ("Loaded {} training examples".format(len(train_iter)))
        print ("Loaded {} test examples".format(len(test_iter)))
        print ("Loaded {} validation examples".format(len(val_iter)))