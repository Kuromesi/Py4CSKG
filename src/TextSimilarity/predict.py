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
    sentence = "An issue was discovered in SageCRM 7.x before 7.3 SP3. The Component Manager functionality, provided by SageCRM, permits additional components to be added to the application to enhance provided functionality. This functionality allows a zip file to be uploaded, containing a valid .ecf component file, which will be extracted to the inf directory outside of the webroot. By creating a zip file containing an empty .ecf file, to pass file-validation checks, any other file provided in zip file will be extracted onto the filesystem. In this case, a web shell with the filename '..\WWWRoot\CustomPages\aspshell.asp' was included within the zip file that, when extracted, traversed back out of the inf directory and into the SageCRM webroot. This permitted remote interaction with the underlying filesystem with the highest privilege level, SYSTEM."
    res = ner.predict(sentence)
    ids = res['ids']
    print(res['res'])