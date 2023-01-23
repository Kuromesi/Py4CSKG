from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer
import pandas as pd
import torch
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from ast import literal_eval
from sklearn.metrics import f1_score

class TextSimilarity():
    def __init__(self) -> None: 
        model_name = "sentence-transformers/all-MiniLM-L6-v2" # jackaduma/SecBERT bert-base-uncased
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        bert_config = BertConfig.from_pretrained(model_name)
        self.bert = BertModel.from_pretrained(model_name, config=bert_config)
        self.batch_size = 32

    def embedding(self, text):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt")
        attention_mask = tokens['attention_mask']
        tokens = tokens['input_ids']
        decoded_text = self.tokenizer.decode(tokens[0])
        decoded_text = decoded_text.split()
        embedding = self.bert(tokens)[0]
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return mean_pooled

    def weighted_embedding(self, text, weight=[]):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt")
        attention_mask = tokens['attention_mask']
        tokens = tokens['input_ids']
        decoded_text = self.tokenizer.tokenize(text)
        
        weight = torch.ones(61)
        l = [i for i in range(18, 52)] + [i for i in range(53, 58)]
        weight[l] = 50
        embedding = self.bert(tokens)[0]
        weight = weight.unsqueeze(-1).expand(embedding.size()).float()
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        masked_embeddings = embedding * mask * weight
        # masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return mean_pooled
        
    def batch_embedding(self, text):
        step = len(text) // self.batch_size
        tail = len(text) % self.batch_size
        embedding = None
        for i in range(step):
            batch = text[i * self.batch_size: (i + 1) * self.batch_size]
            if embedding is not None:
                embedding = torch.cat((embedding, self.embedding(batch)), 0)
            else:
                embedding = self.embedding(batch)

        batch = text[step * self.batch_size: len(text)]
        embedding = torch.cat((embedding, self.embedding(batch)), 0)
        return embedding
    
    def calculate_similarity(self, docs:pd.DataFrame, query):
        '''
        BERT
        '''
        name_embedding = self.batch_embedding(docs['name'].tolist()).detach().numpy()
        docs_embedding = self.batch_embedding(docs['description'].tolist()).detach().numpy()
        # docs_embedding = self.embedding(docs['description'].tolist()).detach().numpy()
        
        # docs_embedding = (1 * name_embedding + docs_embedding) / 2
        query_embedding = self.weighted_embedding(query).detach().numpy()
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = cosine_similarity([doc_vec], [query_embedding[0]])[0][0]
            doc_id = docs['id'].loc[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)

    def batch_calculate_similarity(self, docs:pd.DataFrame, query):
        name_embedding = self.batch_embedding(docs['name'].tolist()).detach().numpy()
        docs_embedding = self.batch_embedding(docs['description'].tolist()).detach().numpy()
        docs_embedding = (1 * name_embedding + docs_embedding) / 2
        query_embedding = self.batch_embedding(query).detach().numpy()

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

def precision_test():
    '''
    Predict corresponding CAPEC of CVE
    '''
    capec_df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    cve_df = pd.read_csv('./myData/learning/CVE2CAPEC/cve.csv', index_col=0)
    
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
    ts = TextSimilarity()
    docs_embedding = ts.batch_embedding(capec_df['description'].tolist()).detach().numpy()
    # name_embedding = ts.batch_embedding(capec_df['name'].tolist()).detach().numpy()
    # docs_embedding = (1 * name_embedding + docs_embedding) / 2
    query_embedding = ts.batch_embedding(query).detach().numpy()
    sim = cosine_similarity(docs_embedding, query_embedding)
    index = np.argmax(sim, axis=0)
    for i in index:
        pred.append(capec_df['id'].loc[i])
        pred_des.append(capec_df['name'].loc[i])
    result_df = pd.DataFrame({'id': cves, 'true': true, 'pred': pred, 'true_name': true_des, 'pred_name': pred_des, 'cve_des': query})
    result_df.to_csv('./myData/learning/CVE2CAPEC/result.csv', index=False)

def calculate_precision():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/result.csv')
    t = f1_score(y_true=df['true'].tolist(), y_pred=df['pred'].tolist(), average='micro')
    print(t)


if __name__ == '__main__':

# model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')

#Our sentences we like to encode
    df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    ts = TextSimilarity()
    text = "The International Domain Name (IDN) support in Epiphany allows remote attackers to spoof domain names using punycode encoded domain names that are decoded in URLs and SSL certificates in a way that uses homograph characters from other character sets, which facilitates phishing attacks."
    ts.calculate_similarity(df, text)
#Sentences are encoded by calling model.encode()
# embeddings = model.encode(sentences)
# print(cosine_distance(embeddings[0], embeddings[1]))
#Print the embeddings
# for sentence, embedding in zip(sentences, embeddings):
#     print("Sentence:", sentence)
#     print("Embedding:", embedding)
#     print("")
    df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    ts = TextSimilarity()
    text = "Dave Nielsen and Patrick Breitenbach PayPal Web Services (aka PHP Toolkit) 0.50, and possibly earlier versions, allows remote attackers to enter false payment entries into the log file via HTTP POST requests to ipn_success.php."
    ts.calculate_similarity(df, text)
    # precision_test()
    # calculate_precision()