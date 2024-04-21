from transformers import AutoTokenizer, AutoModel
import pandas as pd
import torch
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from tqdm import tqdm, trange
import os
from utils.Config import config
from utils.Logger import logger
from ner.models import *
from ner.bert_crf import *
from ner.predict import *
from typing import Optional, Callable

class RealTextSimilarity():
    """def __init__(self, docs), docs are dataframe type object, can be CAPEC, ATT&CK etc.
    """    
    def __init__(self, docs: pd.DataFrame) -> None:
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased roberta-large-nli-stsb-mean-tokens all-MiniLM-L6-v2 bert-large-nli-stsb-mean-tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        # bert_config = BertConfig.from_pretrained(model_name)
        self.bert = AutoModel.from_pretrained(model_name)
        self.batch_size = 16
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.bert.to(self.device)
        self.docs = docs
    
    def init_weight(self, weight_path):
        try:
            self.docs_embedding = np.load(weight_path)
        except Exception as e:
            logger.info(f"failed to load embedding: {e}")
            self.docs_embedding = self.create_embedding(self.docs, weight_path)
               
    def init_ner(self, model_dir: str):
        config = BERTBiLSTMCRFConfig()
        labels = ['O', 'B-cons', 'I-cons', 'B-weak', 'I-weak']
        self.ner = NERPredict(config, model_dir, labels)

    def embedding(self, text, weight=None, weighted=False):
        with torch.no_grad():
            tokens = self.tokenizer(text, padding=True, return_tensors="pt", truncation=True, max_length=512).to(self.device)
            attention_mask = tokens['attention_mask'].to(self.device)
            tokens_ids = tokens['input_ids'].to(self.device)
            
            embedding = self.bert(tokens_ids)[0]
            mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
            if weighted:
                feature = weight['feature']
                tfidf = weight['tfidf']
                weight = []
                for tokens_id in tokens_ids:
                    temp = [tfidf[np.where(feature==str(i.item()))][0] if i != 0 else 0.0 for i in tokens_id ]
                    weight.append(temp)
                weight = torch.tensor(weight).to(self.device)
                weight = weight.unsqueeze(-1).expand(embedding.size()).float()
                masked_embeddings = embedding * mask * weight
            else:
                masked_embeddings = embedding * mask
            summed = torch.sum(masked_embeddings, 1)
            summed_mask = torch.clamp(mask.sum(1), min=1e-9)
            mean_pooled = summed / summed_mask
        return {'embedding': mean_pooled}

    def weighted_embedding(self, text, weighted=False):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt", truncation=True, max_length=256)
        attention_mask = tokens['attention_mask'].to(self.device)
        tokens = tokens['input_ids'].to(self.device)
        embedding = self.bert(tokens)[0]
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        if isinstance(text, list):
            if weighted:
                weight = torch.ones(tokens.size()).to(self.device)
                res = self.ner.predict(text)
                l = res['weight']
                for i in range(len(weight)):
                    weight[i][l[i]] = 20
                weight = weight.unsqueeze(-1).expand(embedding.size()).float()
                masked_embeddings = embedding * mask * weight
            else:
                masked_embeddings = embedding * mask
        else:
            if weighted:
                weight = torch.ones(tokens.size(1)).to(self.device)
                res = self.ner.predict(text)
                l = res['weight']
                weight[l] = 10
                weight = weight.unsqueeze(-1).expand(embedding.size()).float()
                masked_embeddings = embedding * mask * weight
            else:
                masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return {'embedding': mean_pooled}
        
    def batch_embedding(self, text, weight=None, weighted=False):
        step = len(text) // self.batch_size
        embedding = None
        for i in trange(step):
            batch = text[i * self.batch_size: (i + 1) * self.batch_size]
            if embedding is not None:
                embedding = torch.cat((embedding, self.embedding(batch, weight, weighted=weighted)['embedding'].to('cpu')), 0)
            else:
                embedding = self.embedding(batch, weight, weighted=weighted)['embedding'].to('cpu')

        batch = text[step * self.batch_size: len(text)]
        embedding = torch.cat((embedding, self.embedding(batch, weight, weighted=weighted)['embedding'].to('cpu')), 0)
        return embedding
    
    def transform_tfidf(self, corpus):
        tv=TfidfVectorizer()
        corpus_vec = []
        for corp in corpus:
            text = ""
            if not isinstance(corp, str):
                corp = ""
            for i in self.tokenizer.encode(corp, truncation=True, max_length=512):
                text += str(i) + " "
            corpus_vec.append(text.strip())
        tv.fit_transform(corpus_vec)
        features = tv.get_feature_names_out()
        tfidf = tv.idf_
        return {'feature': features, 'tfidf': tfidf}      
    
    def calculate_similarity(self, query, filter=Optional[Callable]):
        '''
        BERT
        '''
        query_embedding = self.weighted_embedding(query, weighted=True)['embedding'].cpu().detach().numpy()
        df = pd.DataFrame(columns=['id', 'name', 'description', 'similarity'])
        if filter:
            result = []
            for i in range(len(self.docs)):
                if filter(self.docs['id'].loc[i]):
                    result.append(i)
            # result = self.docs[self.docs['id'].isin(filter)].index
            docs_embedding = self.docs_embedding[result]
        else:
            docs_embedding = self.docs_embedding
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            if filter:
                idx = result[i]
            else:
                idx = i
            doc_id = self.docs['id'].loc[idx]
            doc_name = self.docs['name'].loc[idx]
            doc_des = self.docs['description'].loc[idx]
            df.loc[len(df.index)] = [doc_id, doc_name, doc_des, sim]
        df = df.sort_values(by='similarity', ascending=False)
        df.drop_duplicates(subset=['id'], keep='first', inplace=True)
        df = df[df['similarity'] > 0.3]
        return df

    def create_embedding(self, docs, path, weighted=True):
        docs_weight = []
        if weighted:
            docs_weight = self.transform_tfidf(docs['processed'].tolist())
        docs_embedding = self.batch_embedding(docs['processed'].tolist(), docs_weight, weighted=weighted).cpu().detach().numpy()
        np.save(os.path.join(path), docs_embedding)
        return docs_embedding

class TextSimilarity():
    def __init__(self, docs_path: str, weight_path: str, ner_path: str) -> None:
        logger.info("Initializing TextSimilarity")
        # df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
        logger.info(f"loading docs from: {docs_path}")
        df = pd.read_csv(docs_path)
        self.rts = RealTextSimilarity(df)
        # doc_weight = config.get("TextSimilarity", "doc_weight")
        # doc_weight = "data/deep/embeddings/query.npy"
        logger.info(f"loading weight from: {weight_path}")
        self.rts.init_weight(weight_path)
        self.rts.init_ner(ner_path)

    def calculate_similarity(self, query, filter=None):
        res = self.rts.calculate_similarity(query, filter)
        return res
    
def new_ner():
    config = BERTBiLSTMCRFConfig()
    model_dir = "./data/deep/trained_models/BERTBiLSTMCRF79"
    labels = ['O', 'B-cons', 'I-cons', 'B-weak', 'I-weak']
    return NERPredict(config, model_dir, labels)

def new_text_similarity(docs_path: str, weight_path: str, ner_path: str) -> TextSimilarity:
    return TextSimilarity(docs_path, weight_path, ner_path)