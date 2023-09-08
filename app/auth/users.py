from ..model import User
from flask import request, jsonify, session
from flask_login import login_required, login_user, logout_user, current_user
from botocore.exceptions import ClientError
import boto3
from boto3.dynamodb.conditions import Attr
from . import users_bp
import bcrypt


session = boto3.Session(profile_name='default')

dynamodb = session.resource('dynamodb')

table_name = 'user_table'

table = dynamodb.Table(table_name)



@users_bp.route('/api/register-user', methods=['POST'])
def register_user():
    if request.method == 'POST':
        data = request.json
        try:
            user_id = data.get('user_id', 0)
            email = data.get('email', '')
            username = data.get('username', '') 
            password = data.get('password', '') 
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) 
            
            existing_user = User.get_user_by_username(username)
            if existing_user:
                return jsonify({'error': 'Username already exists'}), 400
            
            
            
            
            table.put_item(Item={
                'user_id' : user_id,
                'email' : email,
                'username' : username,
                'password' : hashed_password.decode('utf-8')
            })
            return jsonify({'message': 'user created successfully'}), 201
        except ClientError as e:
            return jsonify({'error': 'Failed to create user', 'details': str(e)}), 500
        

@users_bp.route('/api/login-users', methods=['POST'])
def user_login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Invalid username or password'}), 401

        
        response = table.scan(
            FilterExpression=Attr('username').eq(username)
        )
        user_items = response.get('Items', [])

        if not user_items:
            return jsonify({'error': 'User not found'}), 404

        user = user_items[0]  

        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            user_instance = User(
                user_id=user['user_id'],
                email=user['email'],
                username=user['username'],
                password=user['password']
            )

            login_user(user_instance)
            
            response_data = {'message': 'Login Successful', 'username': user['username']}
            return jsonify(response_data), 200  
        
        return jsonify({'error': 'Invalid username or password'}), 401


@users_bp.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout Successful'}), 200



        