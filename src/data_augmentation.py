# import nlpaug.augmenter.char as nac
# import nlpaug.augmenter.word as naw
# import nlpaug.augmenter.sentence as nas
# import nlpaug.flow as nafc

# from nlpaug.util import Action

# text = 'this is a test.'
# aug = naw.
# aug = naw.WordEmbsAug(
#     model_type='word2vec', model_path='./data/embed/vulner_embedding.bin',
#     action="insert")
# augmented_text = aug.augment(text)
# print("Original:")
# print(text)
# print("Augmented Text:")
# print(augmented_text)

from transformers import pipeline
generator = pipeline('text-generation', model='gpt2')

input_text = "SA BSAFE Crypto-J versions prior to 6.2.5 are vulnerable to a Missing Required Cryptographic Step vulnerability. A malicious remote attacker could potentially exploit this vulnerability to coerce two parties into computing the same predictable shared key."
input_length = len(input_text.split())
num_new_words = 5
output_length = input_length + num_new_words
gpt_output = generator(input_text, max_length=80, num_return_sequences=5)
augmented_text = gpt_output[0]['generated_text']
print("Augmented text->",augmented_text)