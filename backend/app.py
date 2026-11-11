from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from config import Config
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import pyotp
import qrcode
from io import BytesIO
import base64
from bson import ObjectId
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============================================
# INIT
# ============================================
app = Flask(__name__)
CORS(app, origins=Config.CORS_ORIGINS)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

client = MongoClient(Config.MONGO_URI)
db = client[Config.DB_NAME]
users_collection = db['users']
vaults_collection = db['vaults']

shares_collection = db['shares']
shares_collection.create_index("expires_at", expireAfterSeconds=0)

# Dead Man's Switch: how long (in days) of inactivity before triggering
SWITCH_TIMEOUT_DAYS = 90


# ============================================
# HELPERS
# ============================================
def utcnow():
    return datetime.now(timezone.utc)

def extract_token():
    token = request.headers.get('Authorization')
    if not token:
        return None
    if token.startswith('Bearer '):
        token = token[7:]
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
        return payload.get('user_id')
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def _iso_or_none(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def _hash_to_bytes(stored):
    if isinstance(stored, bytes):
        return bytes(stored)
    return str(stored).encode('utf-8')


# ============================================
# HEALTH
# ============================================
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'success',
        'message': '✅ Password Manager API is running!',
        'timestamp': utcnow().isoformat()
    }), 200


# ============================================
# AUTH
# ============================================
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')

        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400

        if users_collection.find_one({'email': email}):
            return jsonify({'status': 'error', 'message': 'User already exists'}), 400

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8')
        now = utcnow()

        user = {
            'email': email,
            'password_hash': hashed_password,
            'created_at': now,
            'updated_at': now,
            'twofa_secret': None,
            'twofa_enabled': False,
            'last_login': now,
            'switch_contact': None,
            'switch_blob': None,
            'switch_status': 'inactive',
            'switch_triggered_at': None,
            'switch_claimed_at': None,
        }

        result = users_collection.insert_one(user)
        return jsonify({
            'status': 'success',
            'message': 'User registered successfully',
            'user_id': str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Content-Type must be application/json'}), 415

        data = request.get_json()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password')

        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400

        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401

        stored_hash_bytes = _hash_to_bytes(user['password_hash'])
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash_bytes):
            return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401

        if user.get('twofa_enabled', False):
            totp_code = data.get('totp_code')
            if not totp_code:
                return jsonify({'status': '2fa_required', 'message': '2FA verification required'}), 200
            secret = user.get('twofa_secret')
            if not secret or not pyotp.TOTP(secret).verify(totp_code):
                return jsonify({'status': 'error', 'message': 'Invalid 2FA code'}), 401

        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': utcnow(), 'updated_at': utcnow()}}
        )

        token_data = {
            'user_id': str(user['_id']),
            'email': user['email'],
            'exp': utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
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


# ============================================
# VAULT
# ============================================
@app.route('/api/vault', methods=['POST'])
def save_vault():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        iv = data.get('iv')
        salt = data.get('salt')

        if not encrypted_data or not iv or not salt:
            return jsonify({'status': 'error', 'message': 'encrypted_data, iv, and salt are required'}), 400

        vaults_collection.update_one(
            {'user_id': user_id},
            {'$set': {
                'encrypted_data': encrypted_data,
                'iv': iv,
                'salt': salt,
                'updated_at': utcnow()
            }},
            upsert=True
        )
        return jsonify({'status': 'success', 'message': 'Vault saved successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/vault', methods=['GET'])
def get_vault():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        vault = vaults_collection.find_one({'user_id': user_id})

        if not vault:
            return jsonify({
                'status': 'not_found',
                'data': None,
                'message': 'No vault yet'
            }), 404

        return jsonify({
            'status': 'success',
            'data': {
                'encrypted_data': vault['encrypted_data'],
                'iv': vault['iv'],
                'salt': vault['salt']
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# 2FA
# ============================================
@app.route('/api/2fa/status', methods=['GET'])
def get_2fa_status():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

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
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        secret = pyotp.random_base32()
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_secret': secret, 'updated_at': utcnow()}}
        )

        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=user['email'], issuer_name=Config.APP_NAME
        )
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
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/2fa/enable', methods=['POST'])
def enable_2fa():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        data = request.get_json()
        totp_code = data.get('totp_code')
        if not totp_code:
            return jsonify({'status': 'error', 'message': 'TOTP code is required'}), 400

        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        secret = user.get('twofa_secret')
        if not secret:
            return jsonify({'status': 'error', 'message': '2FA not set up for this user'}), 400

        if not pyotp.TOTP(secret).verify(totp_code):
            return jsonify({'status': 'error', 'message': 'Invalid 2FA code'}), 401

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_enabled': True, 'updated_at': utcnow()}}
        )
        return jsonify({'status': 'success', 'message': '2FA enabled successfully!'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/2fa/disable', methods=['POST'])
def disable_2fa():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'twofa_enabled': False, 'updated_at': utcnow()}}
        )
        return jsonify({'status': 'success', 'message': '2FA disabled successfully'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# SHARING
# ============================================
@app.route('/api/share', methods=['POST'])
def create_share():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        data = request.get_json()
        shared_blob = data.get('shared_blob')
        receiver_email = data.get('receiver_email')
        hours_valid = data.get('hours_valid', 24)

        if not shared_blob:
            return jsonify({'status': 'error', 'message': 'shared_blob is required'}), 400

        share_id = str(uuid.uuid4())
        expires_at = utcnow() + timedelta(hours=hours_valid)

        shares_collection.insert_one({
            '_id': share_id,
            'sender_id': user_id,
            'receiver_email': receiver_email,
            'shared_blob': shared_blob,
            'created_at': utcnow(),
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
                'receiver_email': share.get('receiver_email')
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# RECOVERY KIT
# ============================================
@app.route('/api/recovery/setup', methods=['POST'])
def setup_recovery():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        data = request.get_json()
        encrypted_master_password = data.get('encrypted_master_password')
        if not encrypted_master_password:
            return jsonify({'status': 'error', 'message': 'encrypted_master_password is required'}), 400

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'recovery_blob': encrypted_master_password,
                'recovery_setup_at': utcnow(),
                'updated_at': utcnow()
            }}
        )
        return jsonify({'status': 'success', 'message': 'Recovery kit saved!'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# DEAD MAN'S SWITCH
# ============================================
@app.route('/api/switch/setup', methods=['POST'])
def setup_switch():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        data = request.get_json()
        contact_email = (data.get('contact_email') or '').strip().lower()
        encrypted_blob = data.get('encrypted_blob')

        if not contact_email or not encrypted_blob:
            return jsonify({'status': 'error', 'message': 'contact_email and encrypted_blob are required'}), 400

        sender = users_collection.find_one({'_id': ObjectId(user_id)})
        if not sender:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        if sender['email'] == contact_email:
            return jsonify({'status': 'error', 'message': 'Contact email cannot be your own email'}), 400

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'switch_contact': contact_email,
                'switch_blob': encrypted_blob,
                'switch_status': 'active',
                'switch_triggered_at': None,
                'switch_claimed_at': None,
                'last_login': utcnow(),
                'updated_at': utcnow()
            }}
        )
        return jsonify({
            'status': 'success',
            'message': "Dead Man's Switch activated!",
            'timeout_days': SWITCH_TIMEOUT_DAYS
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/switch/status', methods=['GET'])
def switch_status():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        last_login = user.get('last_login')
        deadline = None
        days_remaining = None
        if last_login and user.get('switch_status') == 'active':
            if last_login.tzinfo is None:
                last_login_aware = last_login.replace(tzinfo=timezone.utc)
            else:
                last_login_aware = last_login
            deadline = last_login_aware + timedelta(days=SWITCH_TIMEOUT_DAYS)
            days_remaining = max(0, (deadline - utcnow()).days)

        return jsonify({
            'status': 'success',
            'switch': {
                'state': user.get('switch_status', 'inactive'),
                'contact_email': user.get('switch_contact'),
                'last_login': _iso_or_none(last_login),
                'deadline': _iso_or_none(deadline),
                'days_remaining': days_remaining,
                'timeout_days': SWITCH_TIMEOUT_DAYS
            }
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/switch/disable', methods=['POST'])
def disable_switch():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'switch_contact': None,
                'switch_blob': None,
                'switch_status': 'inactive',
                'switch_triggered_at': None,
                'updated_at': utcnow()
            }}
        )
        return jsonify({'status': 'success', 'message': 'Switch disabled'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/switch/check', methods=['GET'])
def check_switch():
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        caller = users_collection.find_one({'_id': ObjectId(user_id)})
        if not caller:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        deadline = utcnow() - timedelta(days=SWITCH_TIMEOUT_DAYS)

        candidates = list(users_collection.find({
            'switch_contact': caller['email'],
            'switch_status': 'active'
        }))

        triggered = []
        for sw in candidates:
            last_login = sw.get('last_login')
            if last_login is None:
                continue
            if last_login.tzinfo is None:
                last_login = last_login.replace(tzinfo=timezone.utc)
            if last_login <= deadline:
                triggered.append(sw)

        results = []
        for sw in triggered:
            users_collection.update_one(
                {'_id': sw['_id']},
                {'$set': {'switch_status': 'triggered', 'switch_triggered_at': utcnow()}}
            )
            results.append({
                'sender_email': sw['email'],
                'sender_user_id': str(sw['_id']),
                'encrypted_blob': sw.get('switch_blob'),
                'last_login': _iso_or_none(sw.get('last_login')),
                'triggered_at': utcnow().isoformat()
            })

        return jsonify({
            'status': 'success',
            'triggered_switches': results,
            'timeout_days': SWITCH_TIMEOUT_DAYS
        }), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/switch/claim/<sender_user_id>', methods=['POST'])
def claim_switch(sender_user_id):
    try:
        user_id = extract_token()
        if not user_id:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401

        caller = users_collection.find_one({'_id': ObjectId(user_id)})
        if not caller:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        sender = users_collection.find_one({'_id': ObjectId(sender_user_id)})
        if not sender:
            return jsonify({'status': 'error', 'message': 'Sender not found'}), 404

        if (sender.get('switch_contact') or '').lower() != caller['email']:
            return jsonify({'status': 'error', 'message': 'Not authorized to claim this switch'}), 403

        if sender.get('switch_status') not in ('triggered', 'claimed'):
            return jsonify({'status': 'error', 'message': 'Switch has not been triggered'}), 400

        vault = vaults_collection.find_one({'user_id': sender_user_id})

        users_collection.update_one(
            {'_id': sender['_id']},
            {'$set': {'switch_status': 'claimed', 'switch_claimed_at': utcnow()}}
        )

        payload = {
            'sender_email': sender['email'],
            'encrypted_blob': sender.get('switch_blob'),
            'vault': None
        }
        if vault:
            payload['vault'] = {
                'encrypted_data': vault['encrypted_data'],
                'iv': vault['iv'],
                'salt': vault['salt']
            }

        return jsonify({'status': 'success', 'data': payload}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================
# RUN
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)