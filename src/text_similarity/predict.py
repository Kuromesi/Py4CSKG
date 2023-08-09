# import sys, os
# BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# sys.path.append(BASE_DIR)

import torch
import torch.nn as nn
from tqdm import trange, tqdm
from NER.models import *
from NER.bert_crf import *
from NER.predict import *
from torchcrf import CRF
from transformers import AutoTokenizer

def NERFactory():
    config = BERTBiLSTMCRFConfig()
    model_dir = "./trained_models/BERTBiLSTMCRF79"
    labels = ['O', 'B-cons', 'I-cons']
    return NERPredict(config, model_dir, labels)

if __name__ == "__main__":
    ner = NERFactory()
    sentence = "The kernel-mode drivers in Microsoft Windows XP SP3 do not properly perform indexing of a function-pointer table during the loading of keyboard layouts from disk, which allows local users to gain privileges via a crafted application, as demonstrated in the wild in July 2010 by the Stuxnet worm, aka \"Win32k Keyboard Layout Vulnerability.\"  NOTE: this might be a duplicate of CVE-2010-3888 or CVE-2010-3889."
    res = ner.predict(sentence)
    ids = res['ids']
    print(res['res'])