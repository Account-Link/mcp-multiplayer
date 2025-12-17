#!/usr/bin/env python3
"""
OAuth 2.1 proxy for MCP Multiplayer server
Adapted from buildatool ssl_proxy.py
"""

import json
import secrets
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify, Response
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from authlib.oauth2.rfc6749.models import ClientMixin, AuthorizationCodeMixin
from authlib.integrations.flask_oauth2 import AuthorizationServer
import requests
import logging
import os

# Allow HTTP for testing
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from pathlib import Path
import os

def get_base_url(request):
    """
    Generate the correct base URL for OAuth endpoints, handling:
    1. Direct HTTP access (local dev)
    2. Direct HTTPS access (USE_SSL=true)
    3. HTTPS proxy with internal HTTP (dstack/reverse proxy)
    4. Dynamic detection from Host header for dstack deployments
    """
    domain = os.getenv('DOMAIN', 'localhost')
    use_ssl = os.getenv('USE_SSL', 'false').lower() == 'true'

    # If DOMAIN is explicitly set to a real domain, use it
    if domain != 'localhost' and '.' in domain:
        return f"https://{domain}"

    # For dstack deployments, detect from Host header
    host = request.host
    if host and 'dstack-' in host and '.phala.network' in host:
        # This is a dstack deployment, use HTTPS with the actual host
        return f"https://{host}"

    # For localhost, respect USE_SSL setting
    scheme = 'https' if use_ssl else 'http'

    # For localhost, use the actual host from request
    if domain == 'localhost':
        return f"{scheme}://{host}"

    # Fallback to domain setting
    return f"{scheme}://{domain}"

# Simple in-memory storage with persistence
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_DIR.mkdir(exist_ok=True)
TOKENS_FILE = DATA_DIR / "tokens.json"

clients_db = {}
codes_db = {}
tokens_db = {}

def load_tokens():
    if TOKENS_FILE.exists():
        try:
            tokens_db.update(json.loads(TOKENS_FILE.read_text()))
        except:
            pass

def save_tokens():
    TOKENS_FILE.write_text(json.dumps(tokens_db, indent=2))

load_tokens()

class Client(ClientMixin):
    def __init__(self, client_id, client_secret, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uris = kwargs.get('redirect_uris', [])
        self.grant_types = kwargs.get('grant_types', ['authorization_code'])
        self.response_types = kwargs.get('response_types', ['code'])
        self.scope = kwargs.get('scope', '')
        self.client_name = kwargs.get('client_name', '')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else None

    def get_allowed_scope(self, scope):
        return scope

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        result = self.client_secret == client_secret
        logger.info(f"CLIENT_SECRET_CHECK: Expected: {self.client_secret[:8]}..., Got: {client_secret[:8]}..., Match: {result}")
        return result

    def check_token_endpoint_auth_method(self, method):
        result = method in ['client_secret_basic', 'client_secret_post', 'none']
        logger.info(f"AUTH_METHOD_CHECK: Method: {method}, Valid: {result}")
        return result

    def check_response_type(self, response_type):
        result = response_type in self.response_types
        logger.info(f"RESPONSE_TYPE_CHECK: Type: {response_type}, Valid: {result}")
        return result

    def check_grant_type(self, grant_type):
        result = grant_type in self.grant_types
        logger.info(f"GRANT_TYPE_CHECK: Type: {grant_type}, Allowed: {self.grant_types}, Valid: {result}")
        return result

    def check_endpoint_auth_method(self, method, endpoint):
        result = method in ['client_secret_basic', 'client_secret_post', 'none']
        logger.info(f"ENDPOINT_AUTH_METHOD_CHECK: Method: {method}, Endpoint: {endpoint}, Valid: {result}")
        return result

class AuthorizationCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope, user_id, **kwargs):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.user_id = user_id
        self.code_challenge = kwargs.get('code_challenge')
        self.code_challenge_method = kwargs.get('code_challenge_method')
        self.auth_time = time.time()

    def is_expired(self):
        return time.time() - self.auth_time > 600  # 10 minutes

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

class MyClientRegistrationEndpoint(ClientRegistrationEndpoint):
    def authenticate_token(self, request):
        return True

    def save_client(self, client_info, client_metadata, request):
        client_id = client_info['client_id']
        client_secret = client_info.get('client_secret')
        logger.info(f"💾 SAVING CLIENT:")
        logger.info(f"   Client ID: {client_id}")
        logger.info(f"   Client Secret: {client_secret[:8] if client_secret else 'None'}...")
        logger.info(f"   Metadata: {client_metadata}")

        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            **client_metadata
        )
        clients_db[client_id] = client
        logger.info(f"✅ CLIENT STORED: {len(clients_db)} total clients")
        return client

    def get_server_metadata(self):
        return {
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
        }

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['AUTHLIB_INSECURE_TRANSPORT'] = True  # Allow HTTP for testing

# OAuth2 server setup
authorization = AuthorizationServer()

def query_client(client_id):
    logger.error(f"🔥 QUERY_CLIENT CALLED BY OAUTH LIBRARY: client_id={client_id}")
    logger.error(f"🔥 QUERY_CLIENT: Available clients: {list(clients_db.keys())}")
    result = clients_db.get(client_id)
    logger.error(f"🔥 QUERY_CLIENT RESULT: {result}")
    return result

def save_authorization_code(code, request):
    codes_db[code] = AuthorizationCode(
        code=code,
        client_id=request.client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id='default_user',
        code_challenge=getattr(request, 'code_challenge', None),
        code_challenge_method=getattr(request, 'code_challenge_method', None)
    )

def query_authorization_code(code, client):
    auth_code = codes_db.get(code)
    if auth_code and auth_code.client_id == client.client_id:
        return auth_code
    return None

def delete_authorization_code(authorization_code):
    if authorization_code.code in codes_db:
        del codes_db[authorization_code.code]

def save_token(token, request):
    token_key = token['access_token']
    client = request.client
    tokens_db[token_key] = {
        'client_id': client.client_id,
        'client_name': client.client_name,
        'user_id': getattr(request, 'user_id', 'default_user'),
        'scope': token.get('scope', ''),
        'expires_at': time.time() + token.get('expires_in', 3600),
        'issued_at': time.time()
    }
    save_tokens()
    logger.info(f"TOKEN ISSUED: {client.client_name} | Client ID: {client.client_id[:8]}... | Token: {token_key[:8]}...")

logger.info(f"OAUTH_INIT: Initializing authorization server with query_client function")
authorization.init_app(app, query_client=query_client, save_token=save_token)
logger.info(f"OAUTH_INIT: Authorization server initialized")

# Add comprehensive debugging middleware
@app.before_request
def log_request():
    logger.info(f"🌐 INCOMING REQUEST: {request.method} {request.path}")
    logger.info(f"   Headers: {dict(request.headers)}")
    if request.method in ['POST', 'PUT', 'PATCH']:
        try:
            body = request.get_json() or request.form or request.get_data()
            logger.info(f"   Body: {body}")
        except:
            pass

# Register authorization code grant
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        save_authorization_code(code, request)

    def query_authorization_code(self, code, client):
        return query_authorization_code(code, client)

    def delete_authorization_code(self, authorization_code):
        delete_authorization_code(authorization_code)

    def authenticate_user(self, authorization_code):
        return {'id': authorization_code.user_id}

authorization.register_grant(AuthorizationCodeGrant)
authorization.register_grant(ClientCredentialsGrant)

# Register client registration endpoint
client_registration = MyClientRegistrationEndpoint()
authorization.register_endpoint(client_registration)

# Target MCP server
MCP_PORT = os.getenv("MCP_PORT", "9201")
MCP_SERVER_URL = f"http://127.0.0.1:{MCP_PORT}/mcp"

def verify_token(token):
    """Verify the access token"""
    if not token:
        return False

    token_info = tokens_db.get(token)
    if not token_info:
        return False

    if time.time() > token_info['expires_at']:
        del tokens_db[token]
        return False

    return True

# Removed get_session_from_token - session IDs are client-provided, not server-generated

# OAuth discovery endpoints
@app.route('/.well-known/oauth-authorization-server')
def oauth_authorization_server():
    logger.info("🔍 OAUTH DISCOVERY: Client requesting authorization server metadata")
    base_url = get_base_url(request)
    return jsonify({
        "issuer": base_url,
        "authorization_endpoint": base_url + "/oauth/authorize",
        "token_endpoint": base_url + "/token",
        "registration_endpoint": base_url + "/register",
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
    })

@app.route('/.well-known/oauth-protected-resource')
def oauth_protected_resource():
    base_url = get_base_url(request)
    return jsonify({
        "resource": base_url,
        "authorization_servers": [base_url]
    })

# OAuth endpoints
@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    logger.info(f"AUTHORIZATION REQUEST: Method: {request.method} | Args: {dict(request.args)}")

    if request.method == 'GET':
        try:
            client_id = request.args.get('client_id')
            if client_id:
                client = clients_db.get(client_id)
                client_name = client.client_name if client else 'Unknown'
                logger.info(f"AUTHORIZATION FOR: {client_name} | Client ID: {client_id[:8]}...")

                # Auto-approve Claude clients - no user interaction needed
                if client and client.client_name == 'Claude':
                    logger.info(f"AUTO-APPROVING CLAUDE CLIENT: {client_id[:8]}...")
                    grant = authorization.get_consent_grant(end_user='default_user')
                    response = authorization.create_authorization_response(grant=grant, grant_user='default_user')
                    return response

            grant = authorization.get_consent_grant(end_user='default_user')
            response = authorization.create_authorization_response(grant=grant, grant_user='default_user')
            return response
        except OAuth2Error as error:
            logger.error(f"AUTHORIZATION ERROR: {error}")
            return jsonify(error.get_body()), error.status_code
    return jsonify({"error": "invalid_request"}), 400

@app.route('/oauth/token', methods=['POST'])
def issue_token_oauth():
    logger.info(f"OAUTH TOKEN REQUEST: Form: {dict(request.form)} | Headers: {dict(request.headers)}")
    try:
        response = authorization.create_token_response()
        logger.info(f"OAUTH TOKEN RESPONSE: {response}")
        return response
    except Exception as e:
        logger.error(f"OAUTH TOKEN ERROR: {e}")
        import traceback
        logger.error(f"OAUTH TOKEN TRACEBACK: {traceback.format_exc()}")
        return jsonify({"error": "server_error"}), 500

@app.route('/token', methods=['POST'])
def issue_token():
    logger.info(f"TOKEN REQUEST: Form: {dict(request.form)} | Headers: {dict(request.headers)}")

    # Debug clients_db state
    logger.info(f"CLIENTS_DB_STATE: {len(clients_db)} clients registered")
    for client_id, client in clients_db.items():
        logger.info(f"CLIENTS_DB_CLIENT: {client_id} -> {client.client_name}")

    # Debug the OAuth request object
    try:
        oauth_request = authorization.create_oauth2_request(request)
        logger.info(f"OAUTH_REQUEST: client_id={oauth_request.client_id}, grant_type={oauth_request.grant_type}")

        # Test query_client function directly
        logger.info(f"DIRECT_QUERY_TEST: Calling query_client directly with client_id={oauth_request.client_id}")
        direct_result = query_client(oauth_request.client_id)
        logger.info(f"DIRECT_QUERY_RESULT: {direct_result}")

    except Exception as e:
        logger.error(f"OAUTH_REQUEST_ERROR: {e}")

    try:
        response = authorization.create_token_response()
        logger.info(f"TOKEN RESPONSE: {response}")
        return response
    except Exception as e:
        logger.error(f"TOKEN ERROR: {e}")
        import traceback
        logger.error(f"TOKEN TRACEBACK: {traceback.format_exc()}")
        return jsonify({"error": "server_error"}), 500

@app.route('/register', methods=['POST'])
def register_client():
    try:
        data = request.get_json() or {}

        client_id = secrets.token_urlsafe(32)
        client_secret = secrets.token_hex(24)

        redirect_uris = data.get('redirect_uris', ['https://claude.ai/api/mcp/auth_callback'])
        grant_types = data.get('grant_types', ['authorization_code', 'client_credentials'])
        response_types = data.get('response_types', ['code'])
        client_name = data.get('client_name', 'MCP Multiplayer Client')

        user_agent = request.headers.get('User-Agent', 'Unknown')
        logger.info(f"CLIENT REGISTRATION: {client_name} | User-Agent: {user_agent} | Client ID: {client_id[:8]}...")

        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            response_types=response_types,
            scope=data.get('scope', ''),
            client_name=client_name
        )
        clients_db[client_id] = client

        response = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "token_endpoint_auth_method": "client_secret_basic"
        }

        if data.get('client_name'):
            response['client_name'] = data['client_name']
        if data.get('scope'):
            response['scope'] = data['scope']

        # Auto-issue token for Claude clients
        if client_name == 'Claude':
            logger.info(f"AUTO-ISSUING TOKEN FOR CLAUDE CLIENT: {client_id[:8]}...")
            access_token = secrets.token_urlsafe(32)
            tokens_db[access_token] = {
                'client_id': client_id,
                'client_name': client_name,
                'user_id': 'claude_user',
                'scope': data.get('scope', ''),
                'expires_at': time.time() + 3600,  # 1 hour
                'issued_at': time.time()
            }
            save_tokens()
            logger.info(f"AUTO-ISSUED TOKEN: {client_name} | Token: {access_token[:8]}...")

            # Add token info to registration response
            response.update({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": data.get('scope', '')
            })

        return jsonify(response), 201

    except Exception as e:
        logger.error(f"Client registration error: {e}")
        return jsonify({"error": "server_error", "error_description": str(e)}), 500

def get_client_info_from_token(token):
    """Get client information from token"""
    token_info = tokens_db.get(token)
    if token_info:
        return {
            'client_name': token_info.get('client_name', 'Unknown'),
            'client_id': token_info.get('client_id', 'Unknown')[:8] + '...',
            'user_id': token_info.get('user_id', 'Unknown')
        }
    return None

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_to_mcp(path):
    # Skip auth for OAuth endpoints
    if (path.startswith('.well-known/') or
        path.startswith('oauth/') or
        path == 'register' or
        path == 'token'):
        return jsonify({"error": "not_found"}), 404

    # Check authentication
    auth_header = request.headers.get('Authorization', '')
    client_info = None

    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        if verify_token(token):
            client_info = get_client_info_from_token(token)
            logger.info(f"AUTHENTICATED MCP REQUEST: {client_info['client_name']} | Method: {request.method} | Path: /{path}")
        else:
            logger.warning(f"INVALID TOKEN: {request.remote_addr} | Path: /{path} | Token: {token[:8]}...")
            return jsonify({"error": "invalid_token"}), 401
    else:
        logger.info(f"NO AUTH TOKEN - rejecting request from {request.remote_addr}")
        return jsonify({"error": "authentication_required", "description": "OAuth token required"}), 401

    try:
        url = f"{MCP_SERVER_URL}/{path}" if path else MCP_SERVER_URL

        # Build headers for the proxied request
        headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'authorization']}
        # Pass through all client headers including Mcp-Session-Id

        # DEBUG: Log the forwarded request details
        logger.info(f"🔄 FORWARDING REQUEST:")
        logger.info(f"   URL: {url}")
        logger.info(f"   Method: {request.method}")
        logger.info(f"   Headers: {dict(headers)}")
        logger.info(f"   JSON: {request.get_json() if request.is_json else None}")
        logger.info(f"   Data: {request.get_data() if not request.is_json else None}")

        # Check if this is a streaming request (SSE)
        is_streaming = request.headers.get('Accept') == 'text/event-stream'

        # Make the request to MCP server
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            json=request.get_json() if request.is_json else None,
            data=request.get_data() if not request.is_json else None,
            params=request.args,
            cookies=request.cookies,
            allow_redirects=False,
            stream=is_streaming
        )

        # Build response headers
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in resp.headers.items()
                          if name.lower() not in excluded_headers]

        if is_streaming:
            # For SSE, stream the response
            def generate():
                for chunk in resp.iter_content(chunk_size=None):
                    if chunk:
                        yield chunk
            logger.info(f"🔙 MCP SSE STREAM STARTED: {resp.status_code}")
            return Response(generate(), resp.status_code, response_headers)
        else:
            # For regular requests, return full response
            logger.info(f"🔙 MCP RESPONSE: {resp.status_code} | Content: {resp.text[:200]}...")
            response = Response(resp.content, resp.status_code, response_headers)
            return response

    except Exception as e:
        logger.error(f"PROXY ERROR: {client_info['client_name'] if client_info else 'Unknown'} | Error: {str(e)}")
        return jsonify({"error": "server_error", "error_description": str(e)}), 500

if __name__ == "__main__":
    import os
    from dotenv import load_dotenv

    load_dotenv()

    host = os.getenv("PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("PROXY_PORT", "8100"))
    domain = os.getenv("DOMAIN", "localhost")
    use_ssl = os.getenv("USE_SSL", "false").lower() == "true"

    ssl_cert = os.getenv("SSL_CERT_PATH", f"./certs/live/{domain}/fullchain.pem")
    ssl_key = os.getenv("SSL_KEY_PATH", f"./certs/live/{domain}/privkey.pem")

    if use_ssl and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        logger.info(f"Starting OAuth+SSL proxy on {host}:{port} with HTTPS for domain {domain}")
        app.run(host=host, port=port, debug=False, ssl_context=(ssl_cert, ssl_key))
    else:
        logger.info(f"Starting OAuth proxy on {host}:{port} without HTTPS")
        app.run(host=host, port=port, debug=False)