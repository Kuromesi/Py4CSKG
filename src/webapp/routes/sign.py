from flask import Blueprint, flash
from flask import request, render_template
from webapp.model.user import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required

sign = Blueprint('sign', __name__)

@sign.route('/signin', methods=['GET'])
def signin_form():
    return '''<form action="/signin" method="post">
              <p><input name="username"></p>
              <p><input name="password" type="password"></p>
              <p><button type="submit">Sign In</button></p>
              </form>'''

@sign.route('/signin', methods=['POST'])
def signin():
    # 需要从request对象读取表单内容：
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter(User.name == username).first()
    if user:
        if user.validate_password(password):
            login_user(user)
            flash("Login success.")
            return '<h3>Hello, %s!</h3>'%user.name
    flash("Invalid username or password.")
    return '''<form action="/signin" method="post">
              <p><input name="username"></p>
              <p><input name="password" type="password"></p>
              <p><button type="submit">Sign In</button></p>
              </form>'''

@sign.route('/logout')
@login_required 
def logout():
    logout_user()
    flash("Goodbye.")
    return '''<form action="/signin" method="post">
              <p><input name="username"></p>
              <p><input name="password" type="password"></p>
              <p><button type="submit">Sign In</button></p>
              </form>'''