from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer, BertPreTrainedModel
import pandas as pd
import torch
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from ast import literal_eval
from sklearn.metrics import f1_score
from sklearn.feature_extraction.text import TfidfVectorizer
import spacy, re
from tqdm import tqdm, trange
from gensim import corpora
from gensim.models import TfidfModel
from utils.models import *

class NERPredict():
    def __init__(self) -> None:
        config = BERTBiLSTMCRFConfig()
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        model_dir = "./trained_models/BERTBiLSTMCRF"
        self.model = BERTBiLSTMCRF.from_pretrained(model_dir, config)
        self.model.to(self.device)
        self.labels = ['O', 'B-vul', 'I-vul', 'B-cons', 'I-cons']

    def idx2tag(self, id):
        tags = [[self.labels[y] for y in x if y > -1] for x in id]
        return tags

    def predict(self, sentence):
        tokenized = self.tokenizer(sentence, return_tensors="pt", padding=True, truncation=True, max_length=256)
        text_vec = tokenized['input_ids'].to(self.device)
        input_token_starts = []
        for i in range(len(text_vec)):
            word_ids = tokenized.word_ids(i)
            input_token_starts.append([1 if i != None else 0 for i in word_ids])
        input_token_starts = torch.tensor(input_token_starts, dtype=torch.long).to(self.device)
        attention_mask = tokenized['attention_mask'].to(self.device)
        logits = self.model((text_vec, input_token_starts), attention_mask=attention_mask, use_crf=True)
        ids = self.model.crf.decode(emissions=logits[0])
        tags = self.idx2tag(ids)
        tokens = [self.tokenizer.tokenize(sent) for sent in sentence]
        res = [list(zip(tokens[i], tags[i])) for i in range(len(tags))] 
        weight = []
        for i in range(len(ids)):
            temp = []
            for j in range(len(ids[i])):
                if ids[i][j] != 0:
                    temp.append(j + 1)
            weight.append(temp)
        return {'res': res, 'ids': ids, 'weight': weight}

class CVE2CAPEC():
    def __init__(self) -> None: 
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        bert_config = BertConfig.from_pretrained(model_name)
        self.bert = BertModel.from_pretrained(model_name, config=bert_config)
        self.batch_size = 32
        self.ner = NERPredict()

    def embedding(self, text, weight=None, weighted=True):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt", truncation=True, max_length=512)
        attention_mask = tokens['attention_mask']
        tokens_ids = tokens['input_ids']
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
            weight = torch.tensor(weight)
            weight = weight.unsqueeze(-1).expand(embedding.size()).float()
            masked_embeddings = embedding * mask * weight
        else:
            masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return {'embedding': mean_pooled}

    def batch_weighted_embedding(self, text, weighted):
        step = len(text) // self.batch_size
        embedding = None
        for i in range(step):
            batch = text[i * self.batch_size: (i + 1) * self.batch_size]
            if embedding is not None:
                embedding = torch.cat((embedding, self.weighted_embedding(batch, weighted=weighted)['embedding']), 0)
            else:
                embedding = self.weighted_embedding(batch, weighted=weighted)['embedding']

        batch = text[step * self.batch_size: len(text)]
        embedding = torch.cat((embedding, self.weighted_embedding(batch, weighted=weighted)['embedding']), 0)
        return embedding

    def weighted_embedding(self, text, weighted=False):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt", truncation=True, max_length=256)
        attention_mask = tokens['attention_mask']
        tokens = tokens['input_ids']
        embedding = self.bert(tokens)[0]
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        if isinstance(text, list):
            if weighted:
                weight = torch.ones(tokens.size())
                res = self.ner.predict(text)
                l = res['weight']
                for i in range(len(weight)):
                    weight[i][l[i]] = 10
                weight = weight.unsqueeze(-1).expand(embedding.size()).float()
                masked_embeddings = embedding * mask * weight
            else:
                masked_embeddings = embedding * mask
        else:
            if weighted:
                weight = torch.ones(tokens.size(1))
                res = self.ner.predict(text)
                l = res['weight']
                weight[l] = 1000
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
        for i in range(step):
            batch = text[i * self.batch_size: (i + 1) * self.batch_size]
            if embedding is not None:
                embedding = torch.cat((embedding, self.embedding(batch, weight, weighted=weighted)['embedding']), 0)
            else:
                embedding = self.embedding(batch, weight, weighted=weighted)['embedding']

        batch = text[step * self.batch_size: len(text)]
        embedding = torch.cat((embedding, self.embedding(batch, weight, weighted=weighted)['embedding']), 0)
        return embedding
    
    def transform_tfidf(self, corpus):
        tv=TfidfVectorizer()#初始化一个空的tv。
        corpus_vec = []
        for corp in corpus:
            text = ""
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
        docs = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
        docs_weight = self.transform_tfidf(docs['processed'].tolist())
        docs_embedding = self.batch_embedding(docs['processed'].tolist(), docs_weight, weighted=True).detach().numpy()
        query_embedding = self.weighted_embedding(query, weighted=True)['embedding'].detach().numpy()
        df = pd.DataFrame(columns=['id', 'name', 'description', 'similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = docs['id'].loc[i]
            doc_name = docs['name'].loc[i]
            doc_des = docs['description'].loc[i]
            df.loc[len(df.index)] = [doc_id, doc_name, doc_des, sim]
        df = df.sort_values(by='similarity', ascending=False)
        return df

if __name__ == '__main__':
    cve2capec = CVE2CAPEC()
    text = "Buffer overflow in sccw allows local users to gain root access via the HOME environmental variable."
    cve2capec.calculate_similarity(text)