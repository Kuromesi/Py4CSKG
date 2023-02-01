from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer
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
from predict import *

class TextSimilarity():
    def __init__(self) -> None: 
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        bert_config = BertConfig.from_pretrained(model_name)
        self.bert = BertModel.from_pretrained(model_name, config=bert_config)
        self.batch_size = 32

    def init_ner(self):
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

    def weighted_embedding(self, text, weighted=False):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt")
        attention_mask = tokens['attention_mask']
        tokens = tokens['input_ids']
        embedding = self.bert(tokens)[0]
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        if weighted:
            weight = torch.ones(tokens.size(1))
            res = self.ner.predict(text)
            l = res['weight']
            weight[l] = 20
            weight = weight.unsqueeze(-1).expand(embedding.size()).float()
            masked_embeddings = embedding * mask * weight
        else:
            masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return mean_pooled
        
    def batch_embedding(self, text, weight=None, weighted=False):
        step = len(text) // self.batch_size
        tail = len(text) % self.batch_size
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

    def calculate_similarity(self, docs:pd.DataFrame, query):
        '''
        BERT
        '''
        # name_embedding = self.batch_embedding(docs['name'].tolist()).detach().numpy()
        # docs_embedding = self.batch_embedding(docs['description'].tolist()).detach().numpy()
        # docs_embedding = self.embedding(docs['description'].tolist()).detach().numpy()
        # docs_embedding = (1 * name_embedding + docs_embedding) / 2
        
        # t = [doc.split() for doc in docs['processed'].tolist()]
        # dictionary = corpora.Dictionary([doc.split() for doc in docs['processed'].tolist()])
        # corpus = [dictionary.doc2bow(doc.split()) for doc in docs['processed'].tolist()]
        # tv = TfidfModel(corpus)
        # tfidf = tv['employ']
        cves = pd.read_csv('./myData/learning/CVE2CAPEC/cve_nlp.csv', index_col=0)

        docs_weight = self.transform_tfidf(docs['processed'].tolist())
        # query_weight = self.transform_tfidf(cves['des'].tolist())

        docs_embedding = self.batch_embedding(docs['processed'].tolist(), docs_weight, weighted=False).detach().numpy()
        query_embedding = self.weighted_embedding(query, weighted=True).detach().numpy()
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = docs['id'].loc[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)

    def precision_test(self, fuzzy_num=0):
        '''
        Predict corresponding CAPEC of CVE
        '''
        capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
        cve_df = pd.read_csv('./myData/learning/CVE2CAPEC/cve_nlp.csv', index_col=0)
        
        cves = []
        true = []
        true_des = []
        pred = []
        pred_des = []
        for i in range(len(capec_df.index)):
            cur = literal_eval(capec_df['cve'].loc[i])
            true += [capec_df['id'].loc[i]] * len(cur)
            true_des += [capec_df['name'].loc[i]] * len(cur)
            cves += cur
        query = cve_df.loc[cves]['des'].to_list()
        docs = capec_df['processed'].tolist()
        docs_weight = self.transform_tfidf(docs)
        query_weight = self.transform_tfidf(cve_df['des'].tolist())

        docs_embedding = self.batch_embedding(docs, docs_weight, weighted=True).detach().numpy()
        # name_embedding = ts.batch_embedding(capec_df['name'].tolist()).detach().numpy()
        # docs_embedding = (1 * name_embedding + docs_embedding) / 2
        query_embedding = self.batch_embedding(query, query_weight, weighted=True).detach().numpy()
        sim = cosine_similarity(docs_embedding, query_embedding)
        
        if fuzzy_num:
            index = np.argsort(np.transpose(sim), axis=1)
            for i in range(len(index)):
                ind = index[i][-fuzzy_num: ]
                true_id = capec_df[capec_df['id'] == true[i]].index.to_list()[0]
                if true_id in ind:
                    pred.append(capec_df['id'].loc[true_id])
                    pred_des.append(capec_df['name'].loc[true_id])
                else:
                    pred.append(capec_df['id'].loc[ind[-1]])
                    pred_des.append(capec_df['name'].loc[ind[-1]])
        else:
            index = np.argmax(sim, axis=0)
            for i in index:
                pred.append(capec_df['id'].loc[i])
                pred_des.append(capec_df['name'].loc[i])
        result_df = pd.DataFrame({'id': cves, 'true': true, 'pred': pred, 'true_name': true_des, 'pred_name': pred_des, 'cve_des': query})
        result_df.to_csv('./myData/learning/CVE2CAPEC/result_weight.csv', index=False)

    def _calculate_similarity(self, docs:pd.DataFrame, query):
        '''
        Sentence-BERT
        '''
        model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')
        docs_vec = model.encode(docs['description'].tolist())
        query_vec = model.encode(query)
        df = pd.DataFrame(columns=['id', 'name', 'similarity'])
        for i in range(len(docs_vec)):
            doc_vec = docs_vec[i]
            sim = self.cosine_distance(doc_vec, query_vec)
            doc_id = docs['id'].loc[i]
            doc_name = docs['name'].loc[i]
            df.loc[len(df.index)] = [doc_id, doc_name, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)

class TFIDFSimilarity():
    
    def calculate(self, df, query, fuzzy_num=0):
        docs = df['processed'].tolist()
        tv = TfidfVectorizer()
        sents = docs + [query]
        tv.fit_transform(sents)
        docs_vec = tv.transform(docs).toarray()
        query_vec = tv.transform([query]).toarray()
        sim = cosine_similarity(query_vec, docs_vec)
        if fuzzy_num:
            pass
        else:
            index = np.argmax(sim, axis=1)
        id = df['id'].loc[index]
        print(id)




def calculate_precision():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/result_weight.csv')
    t = f1_score(y_true=df['true'].tolist(), y_pred=df['pred'].tolist(), average='micro')
    print(t)


def preprocess(text):
    # Official model
    text = NLP(text)
    tmp = ""
    # for token in text:
    #     if not token.is_stop and token.is_alpha:
    #         tmp += token.lemma_.lower() + " "
    for token in text:
            tmp += token.lemma_.lower() + " "
    return tmp.strip()

def tfidf():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    corpus = df['description'].tolist()
    bar = trange(len(corpus))
    for i in bar:
        bar.set_postfix(ID=df['id'].loc[i])
        corpus[i] = preprocess(corpus[i])
    df['processed'] = corpus
    df.to_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv', index=False)
    tv=TfidfVectorizer()#初始化一个空的tv。
    tv_fit=tv.fit_transform(corpus)#用训练数据充实tv,也充实了tv_fit。
    print("fit后，所有的词汇如下：")
    print(tv.get_feature_names())
    print("fit后，训练数据的向量化表示为：")
    a = tv_fit.toarray()
    print(tv_fit.toarray())


if __name__ == '__main__':

# model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')

#Our sentences we like to encode
    # df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    # ts = TextSimilarity()
    # text = "The International Domain Name (IDN) support in Epiphany allows remote attackers to spoof domain names using punycode encoded domain names that are decoded in URLs and SSL certificates in a way that uses homograph characters from other character sets, which facilitates phishing attacks."
    # ts.calculate_similarity(df, text)
#Sentences are encoded by calling model.encode()
# embeddings = model.encode(sentences)
# print(cosine_distance(embeddings[0], embeddings[1]))
#Print the embeddings
# for sentence, embedding in zip(sentences, embeddings):
#     print("Sentence:", sentence)
#     print("Embedding:", embedding)
#     print("")
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    ts = TextSimilarity()
    text = "IIS 4.0 and 5.0 allows remote attackers to read documents outside of the web root, and possibly execute arbitrary commands, via malformed URLs that contain UNICODE encoded characters, aka the \"Web Server Folder Traversal\" vulnerability."
    ts.init_ner()
    ts.calculate_similarity(df, text)
    # precision_test()
    # calculate_precision()
    # tfidf()
    # print()


    # PRECISION TEST
    # spacy.prefer_gpu()
    # NLP = spacy.load('en_core_web_trf')
    # ts = TextSimilarity()
    # ts.precision_test(fuzzy_num=0)
    # calculate_precision()

    # TFIDF SIMILARITY
    # df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    # tis = TFIDFSimilarity()
    # query = "Directory traversal vulnerability in CesarFTP 0.98b and earlier allows remote authenticated users (such as anonymous) to read arbitrary files via a GET with a filename that contains a ...%5c (modified dot dot)."
    # tis.calculate(df, query)