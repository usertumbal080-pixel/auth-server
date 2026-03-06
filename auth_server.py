from flask import Flask, request, jsonify
import jwt
import datetime
import hashlib
import os
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-secret-key-ganti-dengan-yang-kuat')
app.config['JWT_EXPIRATION_HOURS'] = int(os.getenv('JWT_EXPIRATION_HOURS', 24))

# Simulasi database users (dalam production pakai database sungguhan)
users_db = {
    "uid123": {
        "password_hash": hashlib.sha256("password123".encode()).hexdigest(),
        "ff_api_key": "ff_api_key_untuk_uid123"
    },
    "uid456": {
        "password_hash": hashlib.sha256("pass456".encode()).hexdigest(),
        "ff_api_key": "ff_api_key_lain"
    }
}

def hash_password(password):
    """Hash password dengan salt"""
    salt = app.config['SECRET_KEY'].encode()
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def token_required(f):
    """Decorator untuk proteksi endpoint dengan JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Hapus "Bearer " jika ada
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['uid']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/login', methods=['POST'])
def login():
    """Endpoint login, mengembalikan JWT token"""
    data = request.get_json()
    
    uid = data.get('uid')
    password = data.get('password')
    
    if not uid or not password:
        return jsonify({'message': 'UID and password required'}), 400
    
    # Cari user di database
    user = users_db.get(uid)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Verifikasi password
    password_hash = hash_password(password)
    if password_hash != user['password_hash']:
        return jsonify({'message': 'Invalid password'}), 401
    
    # Buat JWT token
    token = jwt.encode({
        'uid': uid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['JWT_EXPIRATION_HOURS']),
        'iat': datetime.datetime.utcnow()
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({
        'token': token,
        'expires_in': app.config['JWT_EXPIRATION_HOURS'] * 3600  # dalam detik
    })

@app.route('/refresh', methods=['POST'])
@token_required
def refresh(current_user):
    """Refresh token yang masih valid"""
    new_token = jwt.encode({
        'uid': current_user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['JWT_EXPIRATION_HOURS']),
        'iat': datetime.datetime.utcnow()
    }, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'token': new_token})

@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    """Contoh endpoint yang dilindungi"""
    return jsonify({'message': f'Hello {current_user}! This is protected data.'})

@app.route('/get_ff_api_key', methods=['GET'])
@token_required
def get_ff_api_key(current_user):
    """Mengembalikan API key Free Fire untuk user yang terautentikasi"""
    user = users_db.get(current_user)
    if user and 'ff_api_key' in user:
        return jsonify({'ff_api_key': user['ff_api_key']})
    else:
        return jsonify({'message': 'API key not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
