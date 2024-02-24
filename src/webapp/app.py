import sys, os
BASE_DIR=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR))

from flask import Flask
from flask import request, render_template, redirect, url_for
from flask_login import current_user
# from webapp.utils.project import *
# from webapp.utils.prediction import *
# from webapp.utils.draw import *
# from webapp.utils.search import *
# from webapp.utils.analyze import *
from webapp.routes import *
from webapp.exts import db, login_manager
from webapp.routes.sign import sign
from webapp.model.user import User

app = Flask(__name__)


# WIN = sys.platform.startswith('win')
# if WIN:  # 如果是 Windows 系统，使用三个斜线
#     prefix = 'sqlite:///'
# else:  # 否则使用四个斜线
#     prefix = 'sqlite:////'
# app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
# app.config['SESSION_TYPE'] = 'filesystem'
# app.config['SECRET_KEY'] = os.urandom(24)
# db.init_app(app)
# login_manager.init_app(app)
# login_manager.login_view = 'sign.signin_form'

# @login_manager.user_loader
# def load_user(user_id):  # 创建用户加载回调函数，接受用户 ID 作为参数
#     user = User.query.get(int(user_id))  # 用 ID 作为 User 模型的主键查询对应的用户
#     return user  # 返回用户对象

# with app.app_context():
#     db.create_all()

app.register_blueprint(sign)
app.register_blueprint(model)
app.register_blueprint(predict)

@app.context_processor
def inject_user():
    if current_user.is_anonymous:
        return {'user': "anonymous"}
    return {'user': current_user.name}

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return render_template("home.html")
    return redirect(url_for("sign.signin_form"))

@app.route('/test', methods=['GET'])
def test():
    return render_template("test.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)