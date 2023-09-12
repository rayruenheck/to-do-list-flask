from ..model import User
from flask import request, jsonify, session
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash
from botocore.exceptions import ClientError
import boto3
from boto3.dynamodb.conditions import Attr
from . import users_bp
import bcrypt


session = boto3.Session(profile_name='default')

dynamodb = session.resource('dynamodb')

table_name = 'user_table'

table = dynamodb.Table(table_name)

def new_user(user_id, username, userpassword):
    
    item = table.get_item(Key={'email': user_id})
    if 'Item' in item:
        return False

    password_hash = generate_password_hash(userpassword)

    table_item = {
                'email': user_id,
                'username': username,
                'password_hash': password_hash,
                
            }

    table.put_item(Item=table_item)
    return True



@users_bp.route('/api/register-user', methods=['POST'])
def register_user():
    if request.method == 'POST':
        data = request.json
        try:
            user_id = data.get('email', 0)
            username = data.get('username', '') 
            userpassword = data.get('password', '') 
            
            
            
            if not new_user(user_id, username, userpassword):
                return jsonify({'error': 'Username already exists'}), 400
            
            user = User(user_id, username)
            login_user(user)
            
            
            
            
            
            return jsonify({'message': 'user created successfully'}), 201
        except ClientError as e:
            return jsonify({'error': 'Failed to create user', 'details': str(e)}), 500
        

@users_bp.route('/api/login-users', methods=['POST'])
def user_login():
    if request.method == 'POST':
        data = request.json
        user_id= data.get('email')
        password = data.get('password')

        user = User(user_id)
        if user.verify_password(password):       

            login_user(user)
            
            response_data = {'message': 'Login Successful', 'username': user_id}
            return jsonify(response_data), 200  
        
        return jsonify({'error': 'Invalid username or password'}), 401


@users_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout Successful'}), 200



        