import spacy

nlp = spacy.load('./data/v1\output\model-best')
txt = "A flaw exists in Trading Technologies Messaging 7.1.28.3 (ttmd.exe) due to improper validation of user-supplied data when processing a type 8 message sent to default TCP RequestPort 10200. An unauthenticated, remote attacker can exploit this issue, via a specially crafted message, to terminate ttmd.exe."
tmp = nlp(txt)
for ent in tmp.ents:
        print(ent.text, ent.label_)

# nlp_en = spacy.load('en_core_web_lg')
# print (nlp_en.vocab['cat'].vector)

