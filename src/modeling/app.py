from flask import Flask
from flask import request, render_template
import json, html
from service.utils import *

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
    project = load_project('./src/modeling/data/test_project')
    nodes = project['nodes']
    edges = project['edges']
    return render_template("create_demo.html", nodes=nodes, edges=edges)

@app.route('/test', methods=['GET'])
def test():
    return render_template("test.html")

@app.errorhandler(404)
def show_404(e):
    return render_template("404.html")

if __name__ == '__main__':
    app.run()