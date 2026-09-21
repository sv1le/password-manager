import os
from dotenv import load_dotenv

load_dotenv()
class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
    DB_NAME = 'password_manager'
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key')
    JWT_EXPIRATION_HOURS = 24
    CORS_ORIGINS = ['http://127.0.0.1:5500', 'http://localhost:5500']
    
    # Add this for 2FA
    APP_NAME = 'PasswordManager'  # Will show in Google Authenticator

COLLECTIONS = {
    'users': 'users',
    'vaults': 'vaults'
}