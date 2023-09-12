from flask_login import UserMixin
import boto3
from boto3.dynamodb.conditions import Attr, Key 
from werkzeug.security import check_password_hash



session = boto3.Session(profile_name='default')

dynamodb = session.resource('dynamodb')

table_name = 'user_table'

table = dynamodb.Table(table_name)





class TodoItem:
    def __init__(self, title, description, dt, task_id=0, is_completed=False):
        self.dt = dt
        self.task_id = task_id
        self.title = title
        self.description = description        
        self.is_completed = is_completed


    def to_dict(self):
        return {
            'task_id' : self.task_id,
            'dt' : self.dt,
            'title': self.title,
            'description': self.description,                       
            'is_completed': self.is_completed
        }

class User(UserMixin):
    def __init__(self, user_id, username=None):
        self.dynamodb = dynamodb
        self.table = table
        self.id = user_id
        
        if username:
            self.username = username
        else:
            item = self.table.get_item(Key={'email': user_id})
            self.username = item['Item']['username']
            self.password_hash = item['Item']['password_hash']
            
    
    def to_dict(self):
        return {
            'email' : self.id,
            'username' : self.username,
            'password' : self.password
        }
    def get_user_by_username(username):
        response = table.scan(FilterExpression=Attr('username').eq(username))
        
        if 'Items' in response:
            return response['Items'][0] if response['Items'] else None
    
    def get_user_by_id(self):
        response = table.scan(FilterExpression=Attr('user_id').eq(self.user_id))
        
        if 'Items' in response:
            return response['Items'][0] if response['Items'] else None
    
    def get_id(self):
        return str(self.id)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    
    
    
    
