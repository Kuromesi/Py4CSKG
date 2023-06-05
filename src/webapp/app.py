import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from flask import Flask
from flask import request, render_template
import json, html
from webapp.utils.project import *
from webapp.utils.prediction import *
from webapp.utils.draw import *
from webapp.utils.search import *
from webapp.utils.analyze import *
from webapp.routes import *

app = Flask(__name__)

def init_blueprint():
    app.register_blueprint(model)
    app.register_blueprint(predict)

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

@app.route('/test', methods=['GET'])
def test():
    return render_template("test.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

if __name__ == '__main__':
    init_blueprint()
    app.run(host="0.0.0.0", port=4000)