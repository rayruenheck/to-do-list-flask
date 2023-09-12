from flask import Flask
from app.config import Config
from app.model import User
from app.routes.tasks import tasks_bp
from app.auth.users import users_bp
from dotenv import load_dotenv
from flask_cors import CORS
from flask_login import LoginManager
from boto3.dynamodb.conditions import Key 
import boto3


session = boto3.Session(profile_name='default')

dynamodb = session.resource('dynamodb')

table_name = 'user_table'

table = dynamodb.Table(table_name)

app = Flask(__name__)


load_dotenv()


app.config.from_object(Config)


CORS(app, supports_credentials=True)


login_manager = LoginManager(app)
login_manager.init_app(app)


from app.routes import tasks
from app.auth import users

app.register_blueprint(tasks_bp)
app.register_blueprint(users_bp)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User(user_id)
    except:
        return None



if __name__ == '__main__':
    app.run(debug=True)