import os

class Config:
    SECRET_KEY = os.urandom(12).hex()