import spacy

nlp = spacy.load('./data/v1\output\model-best')
txt = "vRealize Operations (7.x before 7.0.0.11287810, 6.7.x before 6.7.0.11286837 and 6.6.x before 6.6.1.11286876) contains a local privilege escalation vulnerability due to improper permissions of support scripts"
tmp = nlp(txt)
for ent in tmp.ents:
        print(ent.text, ent.label_)W
