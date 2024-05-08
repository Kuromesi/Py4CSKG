import pandas as pd
import numpy as np
import nltk
from nltk.tokenize import word_tokenize
from nltk import pos_tag
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.preprocessing import LabelEncoder
from collections import defaultdict
from nltk.corpus import wordnet as wn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import model_selection, naive_bayes, svm
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

#Set Random seed
np.random.seed(500)
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')
nltk.download('omw-1.4')
nltk.download('averaged_perceptron_tagger')

# Add the Data using pandas
train_corpus = pd.read_csv(r"myData/learning/CVE2CWE/base/cve_test.csv",encoding='latin-1',engine='python')

# Step - 1: Data Pre-processing - This will help in getting better results through the classification algorithms

# Step - 1a : Remove blank rows if any.
train_corpus['text'].dropna(inplace=True)

# Step - 1b : Change all the text to lower case. This is required as python interprets 'dog' and 'DOG' differently
train_corpus['text'] = [entry.lower() for entry in train_corpus['text']]

# Step - 1c : Tokenization : In this each entry in the train_corpus will be broken into set of words
train_corpus['text']= [word_tokenize(entry) for entry in train_corpus['text']]

# Step - 1d : Remove Stop words, Non-Numeric and perfom Word Stemming/Lemmenting.

# WordNetLemmatizer requires Pos tags to understand if the word is noun or verb or adjective etc. By default it is set to Noun
tag_map = defaultdict(lambda : wn.NOUN)
tag_map['J'] = wn.ADJ
tag_map['V'] = wn.VERB
tag_map['R'] = wn.ADV


for index,entry in enumerate(train_corpus['text']):
    # Declaring Empty List to store the words that follow the rules for this step
    Final_words = []
    # Initializing WordNetLemmatizer()
    word_Lemmatized = WordNetLemmatizer()
    # pos_tag function below will provide the 'tag' i.e if the word is Noun(N) or Verb(V) or something else.
    for word, tag in pos_tag(entry):
        # Below condition is to check for Stop words and consider only alphabets
        if word not in stopwords.words('english') and word.isalpha():
            word_Final = word_Lemmatized.lemmatize(word,tag_map[tag[0]])
            Final_words.append(word_Final)
    # The final processed set of words for each iteration will be stored in 'text_final'
    train_corpus.loc[index,'text_final'] = str(Final_words)

#print(train_corpus['text_final'].head())

# Step - 2: Split the model into Train and Test Data set
Train_X, Test_X, Train_Y, Test_Y = model_selection.train_test_split(train_corpus['text_final'],train_corpus['label'],test_size=0.3)

# Step - 3: Label encode the target variable  - This is done to transform Categorical data of string type in the data set into numerical values
Encoder = LabelEncoder()
Train_Y = Encoder.fit_transform(Train_Y)
Test_Y = Encoder.fit_transform(Test_Y)

# Step - 4: Vectorize the words by using TF-IDF Vectorizer - This is done to find how important a word in document is in comaprison to the train_corpus
Tfidf_vect = TfidfVectorizer(max_features=20000)
Tfidf_vect.fit(train_corpus['text_final'])

Train_X_Tfidf = Tfidf_vect.transform(Train_X)
Test_X_Tfidf = Tfidf_vect.transform(Test_X)


# Step - 5: Now we can run different algorithms to classify out data check for accuracy

# Classifier - Algorithm - Naive Bayes
# fit the training dataset on the classifier
Naive = naive_bayes.MultinomialNB()
Naive.fit(Train_X_Tfidf,Train_Y)

# predict the labels on validation dataset
predictions_NB = Naive.predict(Test_X_Tfidf)

# Use accuracy_score function to get the accuracy
print("Naive Bayes Accuracy Score -> ",accuracy_score(predictions_NB, Test_Y)*100)
print("Naive Bayes Precision Score -> ", precision_score(predictions_NB, Test_Y, average='weighted')*100)
print("Naive Bayes F1 Score -> ", f1_score(predictions_NB, Test_Y, average='weighted')*100)
print("Naive Bayes Recall Score -> ", recall_score(predictions_NB, Test_Y, average='weighted')*100)

# Classifier - Algorithm - SVM
# fit the training dataset on the classifier
SVM = svm.SVC(C=1.0, kernel='linear', degree=3, gamma='auto')
SVM.fit(Train_X_Tfidf,Train_Y)

# predict the labels on validation dataset
predictions_SVM = SVM.predict(Test_X_Tfidf)

# Use accuracy_score function to get the accuracy
print("SVM Accuracy Score -> ",accuracy_score(predictions_SVM, Test_Y)*100)
print("SVM Precision Score -> ", precision_score(predictions_SVM, Test_Y, average='weighted')*100)
print("SVM F1 Score -> ", f1_score(predictions_SVM, Test_Y, average='weighted')*100)
print("SVM Recall Score -> ", recall_score(predictions_SVM, Test_Y, average='weighted')*100)

# predict the labels on validation dataset
lr = LogisticRegression()
lr.fit(Train_X_Tfidf, Train_Y)
predictions_lr = lr.predict(Test_X_Tfidf)

# Use accuracy_score function to get the accuracy
print("Logistic Regression Accuracy Score -> ",accuracy_score(predictions_lr, Test_Y)*100)
print("Logistic Regression Precision Score -> ", precision_score(predictions_lr, Test_Y, average='weighted')*100)
print("Logistic Regression F1 Score -> ", f1_score(predictions_lr, Test_Y, average='weighted')*100)
print("Logistic Regression Recall Score -> ", recall_score(predictions_lr, Test_Y, average='weighted')*100)

rf = RandomForestClassifier()
rf.fit(Train_X_Tfidf, Train_Y)
predictions_rf = rf.predict(Test_X_Tfidf)

print("Random Forest Accuracy Score -> ",accuracy_score(predictions_rf, Test_Y)*100)
print("Random Forest Precision Score -> ", precision_score(predictions_rf, Test_Y, average='weighted')*100)
print("Random Forest F1 Score -> ", f1_score(predictions_rf, Test_Y, average='weighted')*100)
print("Random Forest Recall Score -> ", recall_score(predictions_rf, Test_Y, average='weighted')*100)