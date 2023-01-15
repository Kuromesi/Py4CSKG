# from sentence_transformers import SentenceTransformer
from transformers import BertModel, BertConfig, AutoTokenizer
import pandas as pd

import numpy as np

class TextSimilarity():
    def __init__(self) -> None:
        model_name = "bert-base-uncased" # jackaduma/SecBERT
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.bert = BertModel.from_pretrained(model_name, config=BertConfig.from_pretrained(model_name))

    def cosine_distance(self, x, y):
        return np.dot(x, y.T) / (np.linalg.norm(x) * np.linalg.norm(y))
    
    def calculate_similarity(self, docs:pd.DataFrame, query):
        docs_vec = self.tokenizer(docs['description'].tolist(), padding=True, return_tensors="pt")
        attention_mask = docs_vec['attention_mask']
        docs_vec = docs_vec['input_ids']
        docs_vec = self.bert(docs_vec, attention_mask=attention_mask)[1].detach().numpy()
        query_vec = self.tokenizer(query, return_tensors="pt")['input_ids']
        query_vec = self.bert(query_vec)[1].detach().numpy()
        df = pd.DataFrame(columns=['id', 'similarity'])
        for i in range(len(docs_vec)):
            doc_vec = docs_vec[i]
            sim = self.cosine_distance(doc_vec, query_vec)[0]
            doc_id = docs['id'].loc[i]
            df.loc[len(df.index)] = [doc_id, sim]
        df = df.sort_values(by='similarity', ascending=False)
        print(df)



if __name__ == '__main__':

# model = SentenceTransformer('all-MiniLM-L6-v2', device='cuda')

#Our sentences we like to encode
    df = pd.read_csv('./myData/learning/CVE2CAPEC/CVE2CAPEC.csv')
    ts = TextSimilarity()
    text = "SQL injection vulnerability allows remote attackers execute arbitrary SQL commands via the username parameter."
    ts.calculate_similarity(df, text)
#Sentences are encoded by calling model.encode()
# embeddings = model.encode(sentences)
# print(cosine_distance(embeddings[0], embeddings[1]))
#Print the embeddings
# for sentence, embedding in zip(sentences, embeddings):
#     print("Sentence:", sentence)
#     print("Embedding:", embedding)
#     print("")