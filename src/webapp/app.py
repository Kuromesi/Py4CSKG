from flask import Flask
from flask import request, render_template
import json, html
from service.utils import *
from utils.prediction import *
from utils.draw import *
from utils.search import *

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    return '<h1>Home</h1>'

@app.route('/signin', methods=['GET'])
def signin_form():
    return '''<form action="/signin" method="post">
              <p><input name="username"></p>
              <p><input name="password" type="password"></p>
              <p><button type="submit">Sign In</button></p>
              </form>'''

@app.route('/signin', methods=['POST'])
def signin():
    # 需要从request对象读取表单内容：
    if request.form['username']=='admin' and request.form['password']=='password':
        return '<h3>Hello, admin!</h3>'
    return '<h3>Bad username or password.</h3>'

@app.route('/model', methods=['GET'])
def model():
    # project = load_project('./src/webapp/data/test_project')
    # nodes = project['nodes']
    # edges = project['edges']
    return render_template("model.html")

@app.route('/model/submit', methods=['POST'])
def model_submit():
    data = json.loads(request.get_data())
    graph = data['graph']
    path = os.path.join('./src/webapp/data/', data['path'])
    if not os.path.exists(path):
        os.mkdir(path)
    with open(os.path.join(path, "graph.json"), 'w', encoding='utf-8') as f:
        json.dump(graph, f)
    return "Saved!"

@app.route('/model/list', methods=['POST'])
def model_list():
    projects = os.listdir('./src/webapp/data/')
    return projects

@app.route('/model/load', methods=['POST'])
def model_load():
    path = request.get_data().decode("utf-8")
    project = load_project(os.path.join('./src/webapp/data', path))
    return project

@app.route('/model/keyword', methods=['POST'])
def model_keyword():
    data = json.loads(request.get_data())
    query = data['query']
    recommended = search_product(query)
    return recommended

@app.route('/test', methods=['GET'])
def test():
    return render_template("test.html")

@app.route('/predict', methods=['GET'])
def predict():
    return render_template("predict.html")

# cve2capec = CVE2CAPEC()
@app.route('/predict/submit', methods=['POST'])
def predict_submit():
    # cve = request.get_data()
    # cve = json.loads(cve)
    # res = cve2capec.calculate_similarity(cve['cve'])
    # graph = create_cve2net(res, cve['cve'])
    graph = ""
    return graph

@app.errorhandler(404)
def show_404(e):
    return render_template("404.html")

if __name__ == '__main__':
    app.run()