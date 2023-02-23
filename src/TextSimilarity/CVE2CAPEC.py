from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer, AutoModel
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
import os

class TextSimilarity():
    def __init__(self) -> None: 
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased roberta-large-nli-stsb-mean-tokens all-MiniLM-L6-v2 bert-large-nli-stsb-mean-tokens
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        # bert_config = BertConfig.from_pretrained(model_name)
        self.bert = AutoModel.from_pretrained(model_name)
        self.batch_size = 16
        self.device = "cpu" if torch.cuda.is_available() else "cpu"
        self.bert.to(self.device)

    def init_ner(self):
        self.ner = NERPredict()

    def embedding(self, text, weight=None, weighted=True):
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
                    weight[i][l[i]] = 10
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

        docs_embedding = self.batch_embedding(docs['processed'].tolist(), docs_weight, weighted=True).detach().numpy()
        # np.save('./data/capec_embedding.npy', docs_embedding)
        query_embedding = self.weighted_embedding(query, weighted=True)['embedding'].detach().numpy()
        df = pd.DataFrame(columns=['id', 'name','similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = docs['id'].loc[i]
            doc_name = docs['name'].loc[i]
            df.loc[len(df.index)] = [doc_id, doc_name, sim]
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
        query = cve_df.loc[cves]['processed'].to_list()
        docs = capec_df['processed'].tolist()
        docs_weight = self.transform_tfidf(docs + query)
        # query_weight = self.transform_tfidf(cve_df['processed'].tolist())

        docs_embedding = self.batch_embedding(docs, docs_weight, weighted=True).detach().numpy()
        # name_embedding = ts.batch_embedding(capec_df['name'].tolist()).detach().numpy()
        # docs_embedding = (1 * name_embedding + docs_embedding) / 2
        query_embedding = self.batch_embedding(query, docs_weight, weighted=False).detach().numpy()
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
        return {'true': true, 'sim': sim}

    def _precision_test(self, fuzzy_num=0):
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

        docs_embedding = self.batch_embedding(docs, docs_weight, weighted=True).detach().numpy()
        name_embedding = self.batch_embedding(capec_df['name'].tolist()).detach().numpy()
        docs_embedding = 8e-01 * name_embedding + docs_embedding
        query_embedding = self.batch_weighted_embedding(query, weighted=False).detach().numpy()

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
        return {'true': true, 'sim': sim}


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

    def create_embedding(self, docs, name, weighted=False):
        docs_weight = []
        if weighted:
            docs_weight = self.transform_tfidf(docs)
        docs_embedding = self.batch_embedding(docs, docs_weight, weighted=weighted).detach().numpy()
        np.save(os.path.join('data/embeddings', name + ".npy"), docs_embedding)

    def calculate_similarity_for_all(self, docs, query):
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

        # docs_weight = self.transform_tfidf(docs['processed'].tolist())
        # query_weight = self.transform_tfidf(cves['des'].tolist())

        docs_embedding = self.batch_embedding(docs, None, weighted=False).cpu().detach().numpy()
        # np.save('./data/capec_embedding.npy', docs_embedding)
        query_embedding = self.weighted_embedding(query, weighted=False)['embedding'].cpu().detach().numpy()
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = docs[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)

class TFIDFSimilarity():
    
    def calculate(self, docs, query):
        tv = TfidfVectorizer()
        sents = docs + [query]
        tv.fit_transform(sents)
        docs_vec = tv.transform(docs).toarray()
        query_vec = tv.transform([query]).toarray()
        sim = cosine_similarity(query_vec, docs_vec)
        return sim

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
        query = cve_df.loc[cves]['processed'].to_list()
        docs = capec_df['processed'].tolist()
        names = capec_df['name'].tolist()
        doc_name = []
        for i in range(len(docs)):
            doc_name.append(docs[i] + " " + names[i])

        sim = np.empty((0, len(docs)))
        for q in query:
            sim = np.append(sim, self.calculate(doc_name, q), axis=0)
        
        if fuzzy_num:
            index = np.argsort(sim, axis=1)
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
            index = np.argmax(sim, axis=1)
            for i in index:
                pred.append(capec_df['id'].loc[i])
                pred_des.append(capec_df['name'].loc[i])
        result_df = pd.DataFrame({'id': cves, 'true': true, 'pred': pred, 'true_name': true_des, 'pred_name': pred_des, 'cve_des': query})
        result_df.to_csv('./myData/learning/CVE2CAPEC/result_tfidf.csv', index=False)
        
        return {'true': true, 'sim': sim}
    
    def calculate_similarity(self, query):
        capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
        docs = capec_df['processed'].tolist()
        names = capec_df['name'].tolist()
        doc_name = []
        for i in range(len(docs)):
            doc_name.append(docs[i] + " " + names[i])
        query = preprocess(query)
        sents = docs + [query]
        tv = TfidfVectorizer()
        tv.fit_transform(sents)
        docs_vec = tv.transform(docs).toarray()
        query_vec = tv.transform([query]).toarray()
        sim = cosine_similarity(query_vec, docs_vec)
        df = pd.DataFrame(columns=['id', 'name','similarity'])
        index = np.argsort(sim, axis=1)
        for ind in index[0]:
            df.loc[len(df.index)] = [capec_df['id'].loc[ind], capec_df['name'].loc[ind], sim[0][ind]]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)
        



def calculate_precision():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/result_weight.csv')
    t = f1_score(y_true=df['true'].tolist(), y_pred=df['pred'].tolist(), average='micro')
    print(t)

def preprocess(text):
    # Official model
    NLP = spacy.load('en_core_web_trf')
    text = NLP(text)
    tmp = ""
    for token in text:
        if not token.is_stop and token.is_alpha:
            tmp += token.lemma_.lower() + " "
    # for token in text:
    #         tmp += token.lemma_.lower() + " "
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

def calculate(sim, capec_df, fuzzy_num, true):
    pred = []
    index = np.argsort(sim, axis=1)
    for i in range(len(index)):
        ind = index[i][-fuzzy_num: ]
        true_id = capec_df[capec_df['id'] == true[i]].index.to_list()[0]
        if true_id in ind:
            pred.append(capec_df['id'].loc[true_id])
        else:
            pred.append(capec_df['id'].loc[ind[-1]])
    f1 = f1_score(y_true=true, y_pred=pred, average='micro')
    return {'f1': f1}

def comparison_result():
    '''
    Generate comparison result between TF-IDF and SBERT
    '''
    spacy.prefer_gpu()
    NLP = spacy.load('en_core_web_trf')
    capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    tis = TFIDFSimilarity()
    ts = TextSimilarity()
    ts.init_ner()
    f1_bert = []
    f1_tfidf = []
    res = ts._precision_test(fuzzy_num=1)
    sim_ts = np.transpose(res['sim'])
    true = res['true']
    res = tis.precision_test(fuzzy_num=1)
    sim_tis = res['sim']
    for i in trange(30):
        f1_bert.append(calculate(sim_ts, capec_df, i + 1, true)['f1'])
        f1_tfidf.append(calculate(sim_tis, capec_df, i + 1, true)['f1'])
    df = pd.DataFrame({'f1_bert': f1_bert, 'f1_tfidf': f1_tfidf})
    df.to_csv('./myData/learning/CVE2CAPEC/comparison.csv', index=False)

def comparison_result_single():
    '''
    Generate comparison result between TF-IDF and SBERT
    '''
    spacy.prefer_gpu()
    NLP = spacy.load('en_core_web_trf')
    capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    ts = TextSimilarity()
    ts.init_ner()
    f1_bert = []
    res = ts._precision_test(fuzzy_num=1)
    sim_ts = np.transpose(res['sim'])
    true = res['true']
    sim_tis = res['sim']
    for i in trange(30):
        f1_bert.append(calculate(sim_ts, capec_df, i + 1, true)['f1'])
    df = pd.read_csv('./myData/learning/CVE2CAPEC/comparison.csv')
    df['bert_weight20'] = f1_bert
    df.to_csv('./myData/learning/CVE2CAPEC/comparison.csv', index=False)

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
    # df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    # ts = TextSimilarity()
    # text = "switch"
    # ts.init_ner()
    # ts.calculate_similarity(df, text)
    # precision_test()
    # calculate_precision()
    # tfidf()
    # print()
    # comparison_result()

    # PRECISION TEST
    # spacy.prefer_gpu()
    # NLP = spacy.load('en_core_web_trf')
    # ts = TextSimilarity()
    # ts.init_ner()
    # ts._precision_test(fuzzy_num=1)
    # calculate_precision()

    # TFIDF SIMILARITY
    # df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    # tis = TFIDFSimilarity()
    # query = "In setSyncSampleParams of SampleTable.cpp, there is possible resource exhaustion due to a missing bounds check. This could lead to remote denial of service with no additional execution privileges needed."
    # tis.calculate_similarity(query)
    # tis.precision_test(fuzzy_num=30)
    # calculate_precision()
    # comparison_result_single()

    # df = pd.read_csv('./data/CVE/product.csv')
    # docs = df['product'].to_list()
    # ts = TextSimilarity()
    # ts.create_embedding(docs, "product")

    query = "crash"
    df = pd.read_csv('./myData/learning/CVE2Technique/attack.csv')
    ts = TextSimilarity()
    ts.init_ner()
    ts.calculate_similarity_for_all(df['name'].to_list(), query)