from flask import Blueprint
from flask import request, render_template
import json
from webapp.utils.project import *
from webapp.utils.draw import *
from webapp.utils.search import *
from analyzer.analyze import *
from flask_login import login_required

model = Blueprint('model', __name__, url_prefix="/model")
@model.route("/", methods=['GET'])
# @login_required
def model_page():
    # project = load_project('./src/webapp/data/test_project')
    # nodes = project['nodes']
    # edges = project['edges']
    return render_template("model.html")

@model.route('/submit', methods=['POST'])
# @login_required
def model_submit():
    data = json.loads(request.get_data())
    graph = data['graph']
    path = os.path.join('./src/webapp/data/', data['path'])
    if not os.path.exists(path):
        os.mkdir(path)
    with open(os.path.join(path, "graph.json"), 'w', encoding='utf-8') as f:
        json.dump(graph, f)
    return "Saved!"

@model.route('/list', methods=['POST'])
# @login_required
def model_list():
    projects = os.listdir('./src/webapp/data/')
    return projects

@model.route('/load', methods=['POST'])
# @login_required
def model_load():
    path = request.get_data().decode("utf-8")
    project = load_project(os.path.join('./src/webapp/data', path))
    return project

@model.route('/keyword', methods=['POST'])
# @login_required
def model_keyword():
    data = json.loads(request.get_data())
    query = data['query']
    recommended = search_product(query)
    return recommended

# ma = ModelAnalyzer()
@model.route('/analyze', methods=['POST'])
# @login_required
def model_analyze():
    data = json.loads(request.get_data())
    return "ok"