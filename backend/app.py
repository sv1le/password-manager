from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from config import Config
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
import pyotp
import qrcode
from io import BytesIO
import base64
from bson import ObjectId
import uuid

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=Config.CORS_ORIGINS)

# MongoDB connection
client = MongoClient(Config.MONGO_URI)
db = client[Config.DB_NAME]
users_collection = db['users']
vaults_collection = db['vaults']

# Create shares collection and TTL index
shares_collection = db['shares']
shares_collection.create_index("expires_at", expireAfterSeconds=0)

# ============================================
# HEALTH CHECK API
# ============================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'success',
        'message': '✅ Password Manager API is running!',
        'timestamp': datetime.now().isoformat()
    }), 200

# ============================================
# AUTHENTICATION APIS
# ============================================
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({'status': 'error', 'message': 'User already exists'}), 400
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user = {
            'email': email,
            'password_hash': hashed_password,
            'created_at': datetime.now(),
            'updated_at': datetime.now(),
            'twofa_secret': None,
            'twofa_enabled': False
        }
        
        result = users_collection.insert_one(user)
        return jsonify({'status': 'success', 'message': 'User registered successfully', 'user_id': str(result.inserted_id)}), 201
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Content-Type must be application/json'}), 415
            
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400
        
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401
        
        # 2FA Verification
        if user.get('twofa_enabled', False):
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({'status': '2fa_required', 'message': '2FA verification required'}), 200
            
            secret = user.get('twofa_secret')
            totp = pyotp.TOTP(secret)
            if not totp.verify(totp_code):
                return jsonify({'status': 'error', 'message': 'Invalid 2FA code'}), 401
        
        # Generate JWT token
        token_data = {
            'user_id': str(user['_id']),
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        token = jwt.encode(token_data, Config.JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'token': token,
            'user': {'email': user['email'], 'user_id': str(user['_id'])}
        }), 200
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Middleware to verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# ============================================
# VAULT APIS
# ============================================
@app.route('/api/vault', methods=['POST'])
def save_vault():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        iv = data.get('iv')
        salt = data.get('salt')
        
        if not encrypted_data or not iv or not salt:
            return jsonify({'status': 'error', 'message': 'encrypted_data, iv, and salt are required'}), 400
        
        vaults_collection.update_one(
            {'user_id': user_id},
            {'$set': {'encrypted_data': encrypted_data, 'iv': iv, 'salt': salt, 'updated_at': datetime.now()}},
            upsert=True
        )
        return jsonify({'status': 'success', 'message': 'Vault saved successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/vault', methods=['GET'])
def get_vault():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        vault = vaults_collection.find_one({'user_id': user_id})
        if not vault:
            return jsonify({'status': 'success', 'data': None, 'message': 'No vault found for this user'}), 200
        
        return jsonify({
            'status': 'success',
            'data': {'encrypted_data': vault['encrypted_data'], 'iv': vault['iv'], 'salt': vault['salt']}
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================
# 2FA APIS
# ============================================
@app.route('/api/2fa/status', methods=['GET'])
def get_2fa_status():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        return jsonify({
            'status': 'success',
            'enabled': user.get('twofa_enabled', False),
            'has_secret': user.get('twofa_secret') is not None
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/2fa/setup', methods=['POST'])
def setup_2fa():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        secret = pyotp.random_base32()
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'twofa_secret': secret}})
        
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user['email'], issuer_name=Config.APP_NAME)
        
        qr = qrcode.make(provisioning_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({'status': 'success', 'secret': secret, 'qr_code': qr_base64, 'provisioning_uri': provisioning_uri}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/2fa/enable', methods=['POST'])
def enable_2fa():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        data = request.get_json()
        totp_code = data.get('totp_code')
        if not totp_code: return jsonify({'status': 'error', 'message': 'TOTP code is required'}), 400
        
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        secret = user.get('twofa_secret')
        if not secret: return jsonify({'status': 'error', 'message': '2FA not set up for this user'}), 400
        
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code):
            return jsonify({'status': 'error', 'message': 'Invalid 2FA code'}), 401
        
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'twofa_enabled': True}})
        return jsonify({'status': 'success', 'message': '2FA enabled successfully!'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/2fa/disable', methods=['POST'])
def disable_2fa():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Authorization token required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        
        users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'twofa_enabled': False}})
        return jsonify({'status': 'success', 'message': '2FA disabled successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================
# SHARING APIS
# ============================================
@app.route('/api/share', methods=['POST'])
def create_share():
    try:
        token = request.headers.get('Authorization')
        if not token: return jsonify({'status': 'error', 'message': 'Auth required'}), 401
        if token.startswith('Bearer '): token = token[7:]
        
        user_id = verify_token(token)
        if not user_id: return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        data = request.get_json()
        shared_blob = data.get('shared_blob')
        receiver_email = data.get('receiver_email')
        hours_valid = data.get('hours_valid', 24)

        share_id = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=hours_valid)

        shares_collection.insert_one({
            '_id': share_id,
            'sender_id': user_id,
            'receiver_email': receiver_email,
            'shared_blob': shared_blob,
            'expires_at': expires_at
        })

        return jsonify({
            'status': 'success',
            'share_url': f"https://password-manager-personal-7075.vercel.app/share.html?id={share_id}"
        }), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/share/<share_id>', methods=['GET'])
def get_share(share_id):
    try:
        share = shares_collection.find_one({'_id': share_id})
        if not share:
            return jsonify({'status': 'error', 'message': 'Share not found or expired'}), 404
            
        return jsonify({
            'status': 'success',
            'data': {
                'shared_blob': share['shared_blob'],
                'receiver_email': share['receiver_email']
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)