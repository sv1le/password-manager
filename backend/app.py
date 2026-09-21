from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from config import Config
import jwt
import bcrypt
from datetime import datetime, timedelta
import os
import pyotp          # ← NEW for 2FA
import qrcode         # ← NEW for QR code
from io import BytesIO
import base64
from bson import ObjectId  # ← ADD THIS

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=Config.CORS_ORIGINS)

# MongoDB connection - LOCAL (NO SSL!)
# MongoDB connection
client = MongoClient(Config.MONGO_URI)
db = client[Config.DB_NAME]
users_collection = db['users']
vaults_collection = db['vaults']

# ... (rest of your APIs stay the same)

# ============================================
# HEALTH CHECK API (Test if server is running)
# ============================================
@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple endpoint to check if server is running"""
    return jsonify({
        'status': 'success',
        'message': '✅ Password Manager API is running!',
        'timestamp': datetime.now().isoformat()
    }), 200

# ============================================
# REGISTER API (Create new user)
# ============================================
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        # Get data from request
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')  # This is the MASTER password hash from client
        
        # Validate input
        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email and password are required'
            }), 400
        
        # Check if user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({
                'status': 'error',
                'message': 'User already exists'
            }), 400
        
        # Hash the password hash (double hash for security)
        # The client sends a derived key, we hash it again before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user document
        user = {
            'email': email,
            'password_hash': hashed_password,
            'created_at': datetime.now(),
            'updated_at': datetime.now(),
            'twofa_secret': None,      # ← NEW: will store secret when user enables 2FA
            'twofa_enabled': False     # ← NEW: track if 2FA is active
        }
        
        # Insert into database
        result = users_collection.insert_one(user)
        
        return jsonify({
            'status': 'success',
            'message': 'User registered successfully',
            'user_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ============================================
# RUN THE SERVER
# ============================================
# ============================================
# LOGIN API (Authenticate user)
# ============================================
@app.route('/api/login', methods=['POST'])
def login():
    """Login user and return JWT token"""
    try:
        # Check if request is JSON
        if not request.is_json:
            return jsonify({
                'status': 'error',
                'message': 'Content-Type must be application/json'
            }), 415
            
        # Get data from request
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')  # This is the master password hash from client
        
        # Validate input
        if not email or not password:
            return jsonify({
                'status': 'error',
                'message': 'Email and password are required'
            }), 400
        
        # Find user in database
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'Invalid email or password'
            }), 401
        
        # Check password (bcrypt comparison)
        # The client sends a derived key, we compare it with stored hash
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            return jsonify({
                'status': 'error',
                'message': 'Invalid email or password'
            }), 401
                # ============ 2FA VERIFICATION ============
        # Check if 2FA is enabled for this user
        if user.get('twofa_enabled', False):
            # Get TOTP code from request
            totp_code = data.get('totp_code')
            
            if not totp_code:
                return jsonify({
                    'status': '2fa_required',
                    'message': '2FA verification required'
                }), 200  # ← Special response for 2FA
            
            # Verify the code
            secret = user.get('twofa_secret')
            totp = pyotp.TOTP(secret)
            
            if not totp.verify(totp_code):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid 2FA code'
                }), 401
        # ============ END 2FA VERIFICATION ============
        
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
            'user': {
                'email': user['email'],
                'user_id': str(user['_id'])
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

    # ============================================
# VAULT APIs (Store/Retrieve encrypted data)
# ============================================

# Initialize vault collection
vaults_collection = db['vaults']

# Middleware to verify JWT token
def verify_token(token):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/api/vault', methods=['POST'])
def save_vault():
    """Save encrypted vault data for a user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Verify token
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Get data from request
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        iv = data.get('iv')
        salt = data.get('salt')
        
        if not encrypted_data or not iv or not salt:
            return jsonify({
                'status': 'error',
                'message': 'encrypted_data, iv, and salt are required'
            }), 400
        
        # Update or insert vault
        vaults_collection.update_one(
            {'user_id': user_id},
            {
                '$set': {
                    'encrypted_data': encrypted_data,
                    'iv': iv,
                    'salt': salt,
                    'updated_at': datetime.now()
                }
            },
            upsert=True
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Vault saved successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
# ============================================
# 2FA STATUS API (Check if user has 2FA enabled)
# ============================================
@app.route('/api/2fa/status', methods=['GET'])
def get_2fa_status():
    """Get 2FA status for current user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Find user
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        return jsonify({
            'status': 'success',
            'enabled': user.get('twofa_enabled', False),
            'has_secret': user.get('twofa_secret') is not None
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    # ============================================
# 2FA DISABLE API
# ============================================
@app.route('/api/2fa/disable', methods=['POST'])
def disable_2fa():
    """Disable 2FA for current user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Disable 2FA
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_enabled': False}}
        )
        
        return jsonify({
            'status': 'success',
            'message': '2FA disabled successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
@app.route('/api/vault', methods=['GET'])
def get_vault():
    """Retrieve encrypted vault data for a user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Verify token
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Find vault for user
        vault = vaults_collection.find_one({'user_id': user_id})
        
        if not vault:
            return jsonify({
                'status': 'success',
                'data': None,
                'message': 'No vault found for this user'
            }), 200
        
        return jsonify({
            'status': 'success',
            'data': {
                'encrypted_data': vault['encrypted_data'],
                'iv': vault['iv'],
                'salt': vault['salt']
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    # ============================================
# 2FA SETUP API (Generate QR Code)
# ============================================
@app.route('/api/2fa/setup', methods=['POST'])
def setup_2fa():
    """Generate 2FA secret and QR code for user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Find user
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Generate 2FA secret
        secret = pyotp.random_base32()
        
        # Store secret in database (but don't enable yet)
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_secret': secret}}
        )
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user['email'],
            issuer_name=Config.APP_NAME
        )
        
        # Create QR code as base64 image
        qr = qrcode.make(provisioning_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'status': 'success',
            'secret': secret,
            'qr_code': qr_base64,
            'provisioning_uri': provisioning_uri
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    # ============================================
# 2FA VERIFY & ENABLE API
# ============================================
@app.route('/api/2fa/enable', methods=['POST'])
def enable_2fa():
    """Verify TOTP code and enable 2FA for user"""
    try:
        # Get token from header
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        user_id = verify_token(token)
        if not user_id:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Get data
        data = request.get_json()
        totp_code = data.get('totp_code')
        
        if not totp_code:
            return jsonify({
                'status': 'error',
                'message': 'TOTP code is required'
            }), 400
        
        # Find user
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        secret = user.get('twofa_secret')
        if not secret:
            return jsonify({
                'status': 'error',
                'message': '2FA not set up for this user'
            }), 400
        
        # Verify the code
        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code):
            return jsonify({
                'status': 'error',
                'message': 'Invalid 2FA code'
            }), 401
        
        # Enable 2FA
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_enabled': True}}
        )
        
        return jsonify({
            'status': 'success',
            'message': '2FA enabled successfully!'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print("Starting Password Manager API...")
    print(f" Server running at: http://localhost:{port}")
    print(f" Health check: http://localhost:{port}/api/health")
    print("Press CTRL+C to stop")
    app.run(debug=True, host='0.0.0.0', port=port)