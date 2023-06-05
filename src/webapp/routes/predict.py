from flask import Blueprint
from flask import request, render_template
import json
from TextSimilarity.cve2capec import *
from webapp.utils.draw import *
from analyzer.analyze import *

predict = Blueprint('predict', __name__)

def cve2capecFactory():
    df = pd.read_csv('./myData/learning/CVE2CAPEC/capec_nlp.csv')
    return TextSimilarity(df, weight_path='./data/embeddings/capec_embedding.npy')

@predict.route('/predict', methods=['GET'])
def predict_page():
    return render_template("predict.html")

cve2capec = cve2capecFactory()
@predict.route('/predict/submit', methods=['POST'])
def predict_submit():
    cve = request.get_data()
    cve = json.loads(cve)
    res = cve2capec.calculate_similarity(cve['cve'])
    graph = create_cve2net(res, cve['cve'])
    # graph = ""
    return graph