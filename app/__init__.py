from flask import Flask
from app.routes.tasks import tasks_bp
from dotenv import load_dotenv
from flask_cors import CORS

app = Flask(__name__)

load_dotenv()

CORS(app)


from app.routes import tasks

app.register_blueprint(tasks_bp)

if __name__ == '__main__':
    app.run(debug=True)