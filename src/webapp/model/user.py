from webapp.exts import db
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    name = db.Column(db.String(20))  # 名字
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<User %r>' % self.name
    
    def set_password(self, password):  # 用来设置密码的方法，接受密码作为参数
        self.password_hash = generate_password_hash(password)  # 将生成的密码保持到对应字段

    def validate_password(self, password):  # 用于验证密码的方法，接受密码作为参数
        return check_password_hash(self.password_hash, password)  # 返回布尔值
    
    def set_name(self, name):
        self.name = name
    
    def get_name(self):
        return self.name