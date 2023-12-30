from flask import Flask, request, jsonify, make_response
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity, set_access_cookies,get_jwt
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from sqlalchemy.exc import SQLAlchemyError
import os


app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config["SQLALCHEMY_POOL_RECYCLE"] = 1800
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {'pool_pre_ping': True}
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://test:your_password@116.204.120.5/admin_backend'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # 更换为强密钥
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=int(os.environ.get('JWT_EXPIRATION_MINUTES', 30)))
jwt = JWTManager(app)
blacklist = set()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

######################## ADMIN #################################
class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # 添加其他需要的字段
    password_hash = db.Column(db.String(128))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username
            # 映射其他字段
        }

@app.route('/admin/getAdmin', methods=['GET'])
@jwt_required()
def get_admins():
    # current_user = get_jwt_identity()
    users = Admin.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/admin/getCurrentAdmin', methods=['GET'])
@jwt_required()
def get_current_admin():
    current_user_username = get_jwt_identity()
    user = Admin.query.filter_by(username=current_user_username).first()
    if user:
        return jsonify(user.to_dict())
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/admin/register', methods=['POST'])
@jwt_required()
def register_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # 检查用户名和密码是否提供
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    # 检查用户名是否已经存在
    if Admin.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    # 创建新用户并保存到数据库
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Admin(username=username, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Admin registered successfully'}), 201

@app.route('/admin/login', methods=['POST'])
def login_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # 检查用户名和密码是否提供
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    user = Admin.query.filter_by(username=username).first()

    # 检查用户是否存在并验证密码
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=username)
        response = jsonify({'message': 'Login successful','token':access_token})
        set_access_cookies(response, access_token, max_age=30*60)
        return response, 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

######################## USER #################################

ma = Marshmallow(app)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(10), nullable=False)

class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "gender")

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        all_users = User.query.all()
        result = users_schema.dump(all_users)
        return jsonify(result), 200
    except SQLAlchemyError as e:
        return jsonify(error=str(e)), 500

@app.route('/adduser', methods=['POST'])
@jwt_required()
def add_user():
    try:
        username = request.json['username']
        gender = request.json['gender']
        new_user = User(username=username, gender=gender)
        db.session.add(new_user)
        db.session.commit()
        return user_schema.jsonify(new_user), 201
    except SQLAlchemyError as e:
        return jsonify(error=str(e)), 500

@app.route('/edit/<int:id>', methods=['PUT'])
@jwt_required()
def edit_user(id):
    try:
        user = User.query.get(id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        username = request.json['username']
        gender = request.json['gender']

        user.username = username
        user.gender = gender

        db.session.commit()
        return user_schema.jsonify(user), 200
    except SQLAlchemyError as e:
        return jsonify(error=str(e)), 500

@app.route('/delete/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    try:
        user = User.query.get(id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    except SQLAlchemyError as e:
        return jsonify(error=str(e)), 500

################### logout#####################
@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    response = make_response("Logged out")
    # 清除 cookie
    response.set_cookie('access_token_cookie', '', expires=0)
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return response

# 在每个请求中检查 token 是否在黑名单中
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

if __name__ == '__main__':
    app.run(debug=True)