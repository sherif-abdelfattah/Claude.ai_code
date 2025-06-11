#!/usr/bin/env python3
"""
OAuth2 Identity Provider Server
Supports: client_credentials, authorization_code, refresh_token, and introspection
"""

import secrets
import hashlib
import base64
import json
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse, urlencode
from flask import Flask, request, jsonify, render_template_string, redirect, session
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
JWT_SECRET = secrets.token_hex(32)
ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
REFRESH_TOKEN_EXPIRY = 86400 * 30  # 30 days
AUTHORIZATION_CODE_EXPIRY = 600  # 10 minutes

# In-memory storage (use database in production)
clients = {}
users = {}
authorization_codes = {}
access_tokens = {}
refresh_tokens = {}

class Client:
    def __init__(self, client_id, client_secret, name, redirect_uris=None, grants=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.name = name
        self.redirect_uris = redirect_uris or []
        self.grants = grants or ['authorization_code', 'client_credentials', 'refresh_token']

class User:
    def __init__(self, username, password, email=None, scopes=None):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.email = email
        self.scopes = scopes or ['read', 'write']
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def init_demo_data():
    """Initialize with demo clients and users"""
    # Demo client
    clients['demo_client'] = Client(
        client_id='demo_client',
        client_secret='demo_secret',
        name='Demo Application',
        redirect_uris=['http://localhost:8080/callback', 'http://127.0.0.1:8080/callback','http://localhost:5000/']
    )
    clients['aveksa'] = Client(
        client_id='aveksa',
        client_secret='secret',
        name='G&L Application',
        redirect_uris=['https://localhost:8443/aveksa/callback','https://localhost:8443']
    )
    # Demo user
    users['demo_user'] = User(
        username='demo_user',
        password='demo_password',
        email='demo@example.com',
        scopes=['read', 'write', 'admin']
    )
    users['sherif_key'] = User(
            username = 'sherif_key',
            password = '1qaz2wsx',
            email = 'sherif_key@local',
            scopes = ['read', 'write']
            )

def generate_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)


def create_jwt_token(payload, expires_in=ACCESS_TOKEN_EXPIRY):
    """Create a JWT token"""
    payload.update({
        'iat': int(time.time()),
        'exp': int(time.time()) + expires_in
    })
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def authenticate_client():
    """Authenticate client using Basic Auth or form data"""
    auth = request.authorization
    if auth:
        client_id, client_secret = auth.username, auth.password
        print("auth_header:", client_id, client_secret)
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        print("form_client_data:", client_id, client_secret)
    
    if not client_id or not client_secret:
        return None
    
    client = clients.get(client_id)
    if client and client.client_secret == client_secret:
        return client
    return None

@app.route('/')
def home():
    """Home page with API documentation"""
    docs = """
    <h1>OAuth2 Identity Provider</h1>
    <h2>Endpoints:</h2>
    <ul>
        <li><strong>GET /authorize</strong> - Authorization endpoint</li>
        <li><strong>POST /token</strong> - Token endpoint</li>
        <li><strong>POST /introspect</strong> - Token introspection</li>
        <li><strong>POST /revoke</strong> - Token revocation</li>
        <li><strong>GET /userinfo</strong> - User information</li>
    </ul>
    
    <h2>Demo Credentials:</h2>
    <ul>
        <li><strong>Client ID:</strong> demo_client</li>
        <li><strong>Client Secret:</strong> demo_secret</li>
        <li><strong>Username:</strong> demo_user</li>
        <li><strong>Password:</strong> demo_password</li>
    </ul>
    
    <h2>Test Authorization Code Flow:</h2>
    <a href="/authorize?response_type=code&client_id=demo_client&redirect_uri=http://localhost:8080/callback&scope=read+write&state=test123">
        Start Authorization Flow
    </a>
    """
    return docs

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """Authorization endpoint for authorization code flow"""
    if request.method == 'GET':
        # Show login form
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope', '')
        state = request.args.get('state', '')
        response_type = request.args.get('response_type')
        
        if not client_id or response_type != 'code':
            return jsonify({'error': 'invalid_request'}), 400
        
        client = clients.get(client_id)
        if not client:
            return jsonify({'error': 'invalid_client'}), 400
        
        if redirect_uri not in client.redirect_uris:
            return jsonify({'error': 'invalid_redirect_uri'}), 400
        
        login_form = f"""
        <form method="post">
            <h2>Login to {client.name}</h2>
            <p>Scopes requested: {scope}</p>
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state}">
            <div>
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div>
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        """
        return login_form
    
    elif request.method == 'POST':
        # Process login and generate authorization code
        username = request.form.get('username')
        password = request.form.get('password')
        client_id = request.form.get('client_id')
        redirect_uri = request.form.get('redirect_uri')
        scope = request.form.get('scope', '')
        state = request.form.get('state', '')
        
        user = users.get(username)
        if not user or not user.check_password(password):
            return jsonify({'error': 'invalid_credentials'}), 401
        
        # Generate authorization code
        code = generate_token()
        authorization_codes[code] = {
            'client_id': client_id,
            'user_id': username,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'expires_at': time.time() + AUTHORIZATION_CODE_EXPIRY
        }
        
        # Redirect back to client
        params = {'code': code}
        if state:
            params['state'] = state
        
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return redirect(redirect_url)

@app.route('/token', methods=['POST'])
def token():
    """Token endpoint - handles all grant types"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'client_credentials':
        return handle_client_credentials()
    elif grant_type == 'authorization_code':
        return handle_authorization_code()
    elif grant_type == 'refresh_token':
        return handle_refresh_token()
    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

def handle_client_credentials():
    """Handle client credentials grant"""
    client = authenticate_client()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    
    if 'client_credentials' not in client.grants:
        return jsonify({'error': 'unauthorized_client'}), 400
    
    scope = request.form.get('scope', 'read')
    
    # Create access token
    token_data = {
        'client_id': client.client_id,
        'scope': scope,
        'token_type': 'Bearer'
    }
    
    access_token = create_jwt_token(token_data)
    
    # Store token for introspection
    access_tokens[access_token] = {
        'client_id': client.client_id,
        'scope': scope,
        'expires_at': time.time() + ACCESS_TOKEN_EXPIRY,
        'token_type': 'Bearer'
    }
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'scope': scope
    })

def handle_authorization_code():
    """Handle authorization code grant"""
    client = authenticate_client()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    
    if not code:
        return jsonify({'error': 'invalid_code'}), 400
    
    auth_code_data = authorization_codes.get(code)
    if not auth_code_data:
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Verify code hasn't expired
    if time.time() > auth_code_data['expires_at']:
        del authorization_codes[code]
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Verify client and redirect URI
    if (auth_code_data['client_id'] != client.client_id or 
        auth_code_data['redirect_uri'] != redirect_uri):
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Delete used authorization code
    del authorization_codes[code]
    
    user_id = auth_code_data['user_id']
    scope = auth_code_data['scope']
    
    # Create tokens
    access_token_data = {
        'client_id': client.client_id,
        'user_id': user_id,
        'scope': scope,
        'token_type': 'Bearer'
    }
    
    access_token = create_jwt_token(access_token_data)
    refresh_token = generate_token()
    
    # Store tokens
    access_tokens[access_token] = {
        'client_id': client.client_id,
        'user_id': user_id,
        'scope': scope,
        'expires_at': time.time() + ACCESS_TOKEN_EXPIRY,
        'token_type': 'Bearer'
    }
    
    refresh_tokens[refresh_token] = {
        'client_id': client.client_id,
        'user_id': user_id,
        'scope': scope,
        'expires_at': time.time() + REFRESH_TOKEN_EXPIRY
    }
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'refresh_token': refresh_token,
        'scope': scope
    })

def handle_refresh_token():
    """Handle refresh token grant"""
    client = authenticate_client()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    
    refresh_token = request.form.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'invalid_request'}), 400
    
    refresh_data = refresh_tokens.get(refresh_token)
    if not refresh_data:
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Check if refresh token has expired
    if time.time() > refresh_data['expires_at']:
        del refresh_tokens[refresh_token]
        return jsonify({'error': 'invalid_grant'}), 400
    
    # Verify client
    if refresh_data['client_id'] != client.client_id:
        return jsonify({'error': 'invalid_client'}), 401
    
    # Create new access token
    access_token_data = {
        'client_id': client.client_id,
        'user_id': refresh_data['user_id'],
        'scope': refresh_data['scope'],
        'token_type': 'Bearer'
    }
    
    access_token = create_jwt_token(access_token_data)
    
    # Store new access token
    access_tokens[access_token] = {
        'client_id': client.client_id,
        'user_id': refresh_data['user_id'],
        'scope': refresh_data['scope'],
        'expires_at': time.time() + ACCESS_TOKEN_EXPIRY,
        'token_type': 'Bearer'
    }
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'scope': refresh_data['scope']
    })

@app.route('/introspect', methods=['POST'])
def introspect():
    """Token introspection endpoint"""
    client = authenticate_client()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    
    token = request.form.get('token')
    if not token:
        return jsonify({'active': False})
    
    # Check access tokens
    token_data = access_tokens.get(token)
    if token_data:
        active = time.time() < token_data['expires_at']
        response = {
            'active': active,
            'client_id': token_data['client_id'],
            'scope': token_data['scope'],
            'token_type': token_data['token_type']
        }
        if 'user_id' in token_data:
            response['username'] = token_data['user_id']
        if active:
            response['exp'] = int(token_data['expires_at'])
        return jsonify(response)
    
    # Check refresh tokens
    refresh_data = refresh_tokens.get(token)
    if refresh_data:
        active = time.time() < refresh_data['expires_at']
        return jsonify({
            'active': active,
            'client_id': refresh_data['client_id'],
            'username': refresh_data['user_id'],
            'scope': refresh_data['scope'],
            'token_type': 'refresh_token',
            'exp': int(refresh_data['expires_at']) if active else None
        })
    
    return jsonify({'active': False})

@app.route('/revoke', methods=['POST'])
def revoke():
    """Token revocation endpoint"""
    client = authenticate_client()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401
    
    token = request.form.get('token')
    if not token:
        return jsonify({'error': 'invalid_request'}), 400
    
    # Remove from access tokens
    if token in access_tokens:
        del access_tokens[token]
    
    # Remove from refresh tokens
    if token in refresh_tokens:
        del refresh_tokens[token]
    
    return '', 200

@app.route('/userinfo', methods=['GET'])
def userinfo():
    """User information endpoint"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_header'}), 401
    
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    token_data = verify_jwt_token(token)
    
    if not token_data or 'user_id' not in token_data:
        print ("token_data:",token_data)
        return jsonify({'error': 'invalid_token'}), 401
    else:
        print ("token_data:",token_data)

    user = users.get(token_data['user_id'])
    if not user:
        return jsonify({'error': 'invalid_user'}), 401
    
    return jsonify({
        'sub': user.username,
        'username': user.username,
        'email': user.email,
        'scopes': user.scopes
    })


@app.route('/tokeninfo', methods=['GET'])
def tokeninfo():
    """Token information endpoint"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_header'}), 401

    token = auth_header[7:]  # Remove 'Bearer ' prefix
    token_data = verify_jwt_token(token)

    if not token_data:
        print ("token_data:",token_data)
        return jsonify({'error': 'invalid_token'}), 401
    print ("token_data:", token_data)

    return jsonify(token_data)




@app.route('/clients', methods=['POST'])
def register_client():
    """Client registration endpoint"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'invalid_request'}), 400
    
    client_id = generate_token()
    client_secret = generate_token()
    
    client = Client(
        client_id=client_id,
        client_secret=client_secret,
        name=data.get('client_name', 'Unnamed Client'),
        redirect_uris=data.get('redirect_uris', []),
        grants=data.get('grant_types', ['authorization_code', 'client_credentials', 'refresh_token'])
    )
    
    clients[client_id] = client
    
    return jsonify({
        'client_id': client_id,
        'client_secret': client_secret,
        'client_name': client.name,
        'redirect_uris': client.redirect_uris,
        'grant_types': client.grants
    })

@app.before_request
def log_request_info():
    app.logger.debug('Begin========================')
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())
    app.logger.debug('End==========================')

if __name__ == '__main__':
    init_demo_data()
    print("OAuth2 Identity Provider Server starting...")
    print("Demo Client ID: demo_client")
    print("Demo Client Secret: demo_secret")
    print("Demo Username: demo_user")
    print("Demo Password: demo_password")
    print("\nServer running on http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
