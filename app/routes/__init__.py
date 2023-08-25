from flask import Blueprint

tasks_bp = Blueprint('tasks', __name__)

from app.routes import tasks