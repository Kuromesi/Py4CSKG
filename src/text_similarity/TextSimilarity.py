from transformers import AutoTokenizer, AutoModel
import pandas as pd
import torch
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from tqdm import tqdm, trange
from TextSimilarity.predict import NERFactory
import os

class TextSimilarity():
    """def __init__(self, docs), docs are dataframe type object, can be CAPEC, ATT&CK etc.
    """    
    def __init__(self, docs, weight_path=None) -> None:
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased roberta-large-nli-stsb-mean-tokens all-MiniLM-L6-v2 bert-large-nli-stsb-mean-tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        # bert_config = BertConfig.from_pretrained(model_name)
        self.bert = AutoModel.from_pretrained(model_name)
        self.batch_size = 16
        self.device = "cpu" if torch.cuda.is_available() else "cpu"
        self.bert.to(self.device)
        self.docs = docs
        self.init_ner()
        self.init_weight(weight_path)
    
    def init_weight(self, weight_path=None):
        if weight_path:
            self.docs_embedding = np.load(weight_path)
        else:
            self.docs_weight = self.transform_tfidf(self.docs['processed'].tolist())
            self.docs_embedding = self.batch_embedding(self.docs['processed'].tolist(), self.docs_weight, weighted=True).detach().numpy()
               
    def init_ner(self):
        self.ner = NERFactory()

    def embedding(self, text, weight=None, weighted=False):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt", truncation=True, max_length=512).to(self.device)
        attention_mask = tokens['attention_mask'].to(self.device)
        tokens_ids = tokens['input_ids'].to(self.device)
        # FOR TEST ONLY
        decoded_text = self.tokenizer.decode(tokens_ids[0])
        decoded_text = decoded_text.split()
        
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
    
    def batch_weighted_embedding(self, text, weighted):
        step = len(text) // self.batch_size
        embedding = None
        for i in range(step):
            batch = text[i * self.batch_size: (i + 1) * self.batch_size]
            if embedding is not None:
                embedding = torch.cat((embedding, self.weighted_embedding(batch, weighted=weighted)['embedding'].to('cpu')), 0)
            else:
                embedding = self.weighted_embedding(batch, weighted=weighted)['embedding'].to('cpu')

        batch = text[step * self.batch_size: len(text)]
        embedding = torch.cat((embedding, self.weighted_embedding(batch, weighted=weighted)['embedding'].to('cpu')), 0)
        return embedding
    
    def transform_tfidf(self, corpus):
        tv=TfidfVectorizer()#初始化一个空的tv。
        corpus_vec = []
        for corp in corpus:
            text = ""
            if not isinstance(corp, str):
                corp = ""
            for i in self.tokenizer.encode(corp, truncation=True, max_length=512):
                text += str(i) + " "
            corpus_vec.append(text.strip())
        tv.fit_transform(corpus_vec)#用训练数据充实tv,也充实了tv_fit。
        features = tv.get_feature_names_out()
        tfidf = tv.idf_
        return {'feature': features, 'tfidf': tfidf}      
    
    def calculate_similarity(self, query):
        '''
        BERT
        '''
        query_embedding = self.weighted_embedding(query, weighted=True)['embedding'].detach().numpy()
        df = pd.DataFrame(columns=['id', 'name', 'description', 'similarity'])
        for i in range(len(self.docs_embedding)):
            doc_vec = self.docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = self.docs['id'].loc[i]
            doc_name = self.docs['name'].loc[i]
            doc_des = self.docs['description'].loc[i]
            df.loc[len(df.index)] = [doc_id, doc_name, doc_des, sim]
        df = df.sort_values(by='similarity', ascending=False)
        df.drop_duplicates(subset=['id'], keep='first', inplace=True)
        return df

    def create_embedding(self, docs, name, weighted=False):
        docs_weight = []
        if weighted:
            docs_weight = self.transform_tfidf(docs)
        docs_embedding = self.batch_embedding(docs, docs_weight, weighted=weighted).detach().numpy()
        np.save(os.path.join('data/embeddings', name + ".npy"), docs_embedding)