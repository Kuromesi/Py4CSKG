from flask import Blueprint
from flask import request, render_template
import json
from webapp.utils.project import *
from webapp.utils.prediction import *
from webapp.utils.draw import *
from webapp.utils.search import *
from webapp.utils.analyze import *

predict = Blueprint('predict', __name__)

@predict.route('/predict', methods=['GET'])
def predict_page():
    return render_template("predict.html")

cve2capec = CVE2CAPEC()
@predict.route('/predict/submit', methods=['POST'])
def predict_submit():
    cve = request.get_data()
    cve = json.loads(cve)
    res = cve2capec.calculate_similarity(cve['cve'])
    graph = create_cve2net(res, cve['cve'])
    # graph = ""
    return graph