from flask import Flask
from app.config import Config
from app.model import User
from app.routes.tasks import tasks_bp
from app.auth.users import users_bp
from dotenv import load_dotenv
from flask_cors import CORS
from flask_login import LoginManager

app = Flask(__name__)


load_dotenv()


app.config.from_object(Config)


CORS(app, supports_credentials=True)


login_manager = LoginManager()
login_manager.init_app(app)


from app.routes import tasks
from app.auth import users

app.register_blueprint(tasks_bp)
app.register_blueprint(users_bp)

@login_manager.user_loader
def load_user(user_id):
    
    user = User.get_user_by_id(user_id)
    return user


if __name__ == '__main__':
    app.run(debug=True)