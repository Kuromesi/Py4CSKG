from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer
import pandas as pd
import torch
import numpy as np

class TextSimilarity():
    def __init__(self) -> None:
        model_name = "bert-base-uncased" # jackaduma/SecBERT
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        bert_config = BertConfig.from_pretrained(model_name)
        self.bert = BertModel.from_pretrained(model_name, config=bert_config)

    def embedding(self, text):
        tokens = self.tokenizer(text, padding=True, return_tensors="pt")
        attention_mask = tokens['attention_mask']
        tokens = tokens['input_ids']
        embedding = self.bert(tokens)[0]
        mask = attention_mask.unsqueeze(-1).expand(embedding.size()).float()
        masked_embeddings = embedding * mask
        summed = torch.sum(masked_embeddings, 1)
        torch.Size([4, 768])
        summed_mask = torch.clamp(mask.sum(1), min=1e-9)
        mean_pooled = summed / summed_mask
        return mean_pooled
        


    def cosine_distance(self, x, y):
        return np.dot(x, y.T) / (np.linalg.norm(x) * np.linalg.norm(y))
    
    def calculate_similarity(self, docs:pd.DataFrame, query):
        '''
        BERT
        '''
        docs_embedding = self.embedding(docs).detach().numpy()
        query_embedding = self.embedding(query).detach().numpy()
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_embedding)):
            doc_vec = docs_embedding[i]
            sim = self.cosine_distance(doc_vec, query_embedding)[0]
            doc_id = docs['id'].loc[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)

    def _calculate_similarity(self, docs:pd.DataFrame, query):
        '''
        Sentence-BERT
        '''
        model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')
        docs_vec = model.encode(docs['description'].tolist())
        query_vec = model.encode(query)
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_vec)):
            doc_vec = docs_vec[i]
            sim = self.cosine_distance(doc_vec, query_vec)
            doc_id = docs['id'].loc[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)


if __name__ == '__main__':

# model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')

#Our sentences we like to encode
    df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    ts = TextSimilarity()
    text = "firewall"
    ts.calculate_similarity(df, text)
#Sentences are encoded by calling model.encode()
# embeddings = model.encode(sentences)
# print(cosine_distance(embeddings[0], embeddings[1]))
#Print the embeddings
# for sentence, embedding in zip(sentences, embeddings):
#     print("Sentence:", sentence)
#     print("Embedding:", embedding)
#     print("")