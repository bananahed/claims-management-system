import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv('C:/Users/joeya/Desktop/cms-final/cms-backend/.env')

MONGO_URI = os.getenv('MONGO_URI')
DB_NAME = os.getenv('db')
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

SECRET_KEY = os.getenv('SECRET_KEY')
if not isinstance(SECRET_KEY,str):
    raise ValueError("Invalid secret key")

JWT_ALGORITHM = 'HS256'

TOKEN_EXPIRATION = 3600

# db.blacklisted_token.create_index('expire_at', expireAfterSeconds=TOKEN_EXPIRATION)