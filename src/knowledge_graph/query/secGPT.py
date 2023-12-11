import torch
from transformers import AutoModel, AutoTokenizer
from scipy.spatial.distance import cosine
import pandas as pd

# Get our models - The package will take care of downloading the models automatically
# For best performance: Muennighoff/SGPT-5.8B-weightedmean-msmarco-specb-bitfit
tokenizer = AutoTokenizer.from_pretrained("Muennighoff/SGPT-125M-weightedmean-msmarco-specb-bitfit")
model = AutoModel.from_pretrained("Muennighoff/SGPT-125M-weightedmean-msmarco-specb-bitfit")
# Deactivate Dropout (There is no dropout in the above models so it makes no difference here but other SGPT models may have dropout)
model.eval()

batch_size = 32

queries = [
    "ssh",
]

df = pd.read_csv("myData/learning/CVE2CAPEC/capec_nlp.csv")
docs = df['description'].to_list()

# docs = [
#     "Neptune is the eighth and farthest-known Solar planet from the Sun. In the Solar System, it is the fourth-largest planet by diameter, the third-most-massive planet, and the densest giant planet. It is 17 times the mass of Earth, slightly more massive than its near-twin Uranus.",
#     "TRAPPIST-1d, also designated as 2MASS J23062928-0502285 d, is a small exoplanet (about 30% the mass of the earth), which orbits on the inner edge of the habitable zone of the ultracool dwarf star TRAPPIST-1 approximately 40 light-years (12.1 parsecs, or nearly 3.7336×1014 km) away from Earth in the constellation of Aquarius.",
#     "A harsh desert world orbiting twin suns in the galaxy’s Outer Rim, Tatooine is a lawless place ruled by Hutt gangsters. Many settlers scratch out a living on moisture farms, while spaceport cities such as Mos Eisley and Mos Espa serve as home base for smugglers, criminals, and other rogues.",
# ]

SPECB_QUE_BOS = tokenizer.encode("[", add_special_tokens=False)[0]
SPECB_QUE_EOS = tokenizer.encode("]", add_special_tokens=False)[0]

SPECB_DOC_BOS = tokenizer.encode("{", add_special_tokens=False)[0]
SPECB_DOC_EOS = tokenizer.encode("}", add_special_tokens=False)[0]

def get_doc_embeddings(docs, loaded=False):
    if not loaded:
        doc_embeddings = None
        docs_batches = []
        for i in range(0, len(docs), batch_size):
            if i + batch_size <= len(docs):
                docs_batches.append(docs[i: i + batch_size])
            else:
                docs_batches.append(docs[i: ])
        for doc_batch in docs_batches:
            tmp = get_weightedmean_embedding(tokenize_with_specb(doc_batch, is_query=False), model)
            
            if doc_embeddings == None:
                doc_embeddings = tmp
            else:
                doc_embeddings = torch.cat((doc_embeddings, tmp), dim=0)
        torch.save(doc_embeddings, "doc_embeddings.pt")
    else:
        doc_embeddings = torch.load("doc_embeddings.pt")
    return doc_embeddings

def get_query_embeddings(queries):
    return get_weightedmean_embedding(tokenize_with_specb(queries, is_query=True), model)

def tokenize_with_specb(texts, is_query):
    # Tokenize without padding
    batch_tokens = tokenizer(texts, padding=False, truncation=True)   
    # Add special brackets & pay attention to them
    for seq, att in zip(batch_tokens["input_ids"], batch_tokens["attention_mask"]):
        if is_query:
            seq.insert(0, SPECB_QUE_BOS)
            seq.append(SPECB_QUE_EOS)
        else:
            seq.insert(0, SPECB_DOC_BOS)
            seq.append(SPECB_DOC_EOS)
        att.insert(0, 1)
        att.append(1)
    # Add padding
    batch_tokens = tokenizer.pad(batch_tokens, padding=True, return_tensors="pt")
    return batch_tokens

def get_weightedmean_embedding(batch_tokens, model):
    # Get the embeddings
    with torch.no_grad():
        # Get hidden state of shape [bs, seq_len, hid_dim]
        last_hidden_state = model(**batch_tokens, output_hidden_states=True, return_dict=True).last_hidden_state

    # Get weights of shape [bs, seq_len, hid_dim]
    weights = (
        torch.arange(start=1, end=last_hidden_state.shape[1] + 1)
        .unsqueeze(0)
        .unsqueeze(-1)
        .expand(last_hidden_state.size())
        .float().to(last_hidden_state.device)
    )

    # Get attn mask of shape [bs, seq_len, hid_dim]
    input_mask_expanded = (
        batch_tokens["attention_mask"]
        .unsqueeze(-1)
        .expand(last_hidden_state.size())
        .float()
    )

    # Perform weighted mean pooling across seq_len: bs, seq_len, hidden_dim -> bs, hidden_dim
    sum_embeddings = torch.sum(last_hidden_state * input_mask_expanded * weights, dim=1)
    sum_mask = torch.sum(input_mask_expanded * weights, dim=1)

    embeddings = sum_embeddings / sum_mask

    return embeddings


query_embeddings = get_query_embeddings(queries)
doc_embeddings = get_doc_embeddings(docs, loaded=True)

# doc_batch_embeddings = [get_weightedmean_embedding(tokenize_with_specb(doc_batch, is_query=False), model) for doc_batch in docs_batches]
# doc_embeddings = get_weightedmean_embedding(tokenize_with_specb(docs, is_query=False), model)

# Calculate cosine similarities
# Cosine similarities are in [-1, 1]. Higher means more similar
# cosine_sim_0_1 = 1 - cosine(query_embeddings[0], doc_embeddings[0])
# cosine_sim_0_2 = 1 - cosine(query_embeddings[0], doc_embeddings[1])
# cosine_sim_0_3 = 1 - cosine(query_embeddings[0], doc_embeddings[2])

# print("Cosine similarity between \"%s\" and \"%s\" is: %.3f" % (queries[0], docs[0][:20] + "...", cosine_sim_0_1))
# print("Cosine similarity between \"%s\" and \"%s\" is: %.3f" % (queries[0], docs[1][:20] + "...", cosine_sim_0_2))
# print("Cosine similarity between \"%s\" and \"%s\" is: %.3f" % (queries[0], docs[2][:20] + "...", cosine_sim_0_3))

res_df = pd.DataFrame(columns=['capec-id', 'capec-name', 'cosine_sim'])
cnt = 0
for doc_embedding in doc_embeddings:
    cosine_sim = 1 - cosine(query_embeddings[0], doc_embedding)
    res_df.loc[len(res_df.index)] = [df['id'][cnt], df['name'][cnt], cosine_sim]
    cnt += 1
res_df = res_df.sort_values(by='cosine_sim', ascending=False)
print(df)