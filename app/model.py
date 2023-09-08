from flask_login import UserMixin
import boto3
from boto3.dynamodb.conditions import Attr 



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
    def __init__(self, user_id, email, username, password):
        self.user_id = user_id
        self.email = email
        self.username = username
        self.password = password
    
    def to_dict(self):
        return {
            'user_id' : self.user_id,
            'email' : self.email,
            'username' : self.username,
            'password' : self.password
        }
    def get_user_by_username(username):
        response = table.scan(FilterExpression=Attr('username').eq(username))
        
        if 'Items' in response:
            return response['Items'][0] if response['Items'] else None
    
    def get_id(self):
        return str(self.user_id)
    
    
    
    
    @classmethod
    def get_user_by_id(cls, user_id):
        session_user_id = session.get('user_id')

        if session_user_id and session_user_id == user_id:
        
            return cls(
                user_id=session_user_id,
                email=session['email'],  
                username=session['username'],  
                password=session['password']  
            )
    
        return None