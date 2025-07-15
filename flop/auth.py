# auth.py - Reusable OAuth authentication module
import os
import functools
import yaml
from flask import Blueprint, session, redirect, url_for, request, jsonify, current_app
from authlib.integrations.flask_client import OAuth
from werkzeug.exceptions import Unauthorized
from dotenv import load_dotenv

# OAuth Provider Configurations
OAUTH_PROVIDERS = {
    'google': {
        'server_metadata_url': 'https://accounts.google.com/.well-known/openid-configuration',
        'client_kwargs': {'scope': 'openid email profile'}
    },
    'github': {
        'access_token_url': 'https://github.com/login/oauth/access_token',
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'api_base_url': 'https://api.github.com/',
        'client_kwargs': {'scope': 'user:email'}
    }
}

class FlaskAuth:
    """Reusable OAuth authentication for Flask microservices"""
    
    def __init__(self, app=None, users_file='users.yaml', providers=None, protect_all_routes=False):
        self.oauth = None
        self.providers = {}
        self.users_file = users_file
        self.users_db = {}
        self.enabled_providers = providers or ['google', 'github']  # Default providers
        self.protect_all_routes = protect_all_routes
        self.public_routes = set()  # Store public route endpoints
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the authentication with Flask app"""
        # Load environment variables from .env file in app's directory
        env_path = None
        if hasattr(app, 'root_path') and app.root_path:
            env_path = os.path.join(app.root_path, '.env')
        else:
            env_path = os.path.join(os.getcwd(), '.env')
        
        if os.path.exists(env_path):
            load_dotenv(env_path)
        
        self.oauth = OAuth(app)
        
        # Default configuration
        app.config.setdefault('AUTH_REDIRECT_URL', '/dashboard')
        app.config.setdefault('AUTH_LOGIN_URL', '/auth/login')
        app.config.setdefault('AUTH_LOGOUT_URL', '/auth/logout')
        app.config.setdefault('AUTH_REQUIRED_SCOPE', 'openid email profile')
        app.config.setdefault('AUTH_USERS_FILE', self.users_file)
        
        # Load users database - make path relative to app's root or current working directory
        users_file_path = app.config['AUTH_USERS_FILE']
        if not os.path.isabs(users_file_path):
            # Try app root path first, fall back to current working directory
            if hasattr(app, 'root_path') and app.root_path:
                users_file_path = os.path.join(app.root_path, users_file_path)
            else:
                users_file_path = os.path.join(os.getcwd(), users_file_path)
        self.users_file = users_file_path
        self.load_users()
        
        # Register OAuth providers
        self._setup_providers()
        
        # Create authentication blueprint
        auth_bp = self._create_auth_blueprint()
        app.register_blueprint(auth_bp, url_prefix='/auth')
        
        # Store reference in app for access in decorators
        app.auth = self
        
        # Set up global route protection if enabled
        if self.protect_all_routes:
            app.before_request(self._check_global_auth)
    
    def load_users(self):
        """Load users from YAML file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    self.users_db = data.get('users', {})
                    print(f"Loaded {len(self.users_db)} authorized users from {self.users_file}")
            else:
                print(f"Warning: Users file {self.users_file} not found. No users will be authorized until you create this file.")
                self.users_db = {}
                # No users file found - users must create users.yaml manually
        except Exception as e:
            print(f"Error loading users file: {e}")
            self.users_db = {}
    
    def is_user_authorized(self, email):
        """Check if user email is in the authorized database"""
        return email.lower() in self.users_db
    
    def get_user_data(self, email):
        """Get user data from database"""
        return self.users_db.get(email.lower(), {})
    
    def _setup_providers(self):
        """Setup OAuth providers from configuration"""
        for provider_name in self.enabled_providers:
            if provider_name.lower() in OAUTH_PROVIDERS:
                provider_config = OAUTH_PROVIDERS[provider_name.lower()].copy()
                provider_config.update({
                    'name': provider_name,
                    'client_id': os.getenv(f'{provider_name.upper()}_CLIENT_ID'),
                    'client_secret': os.getenv(f'{provider_name.upper()}_CLIENT_SECRET'),
                })
                
                # Only register if credentials are available
                if provider_config['client_id'] and provider_config['client_secret']:
                    self.providers[provider_name] = self.oauth.register(**provider_config)
                    print(f"Registered OAuth provider: {provider_name}")
                else:
                    print(f"Skipping {provider_name} - missing credentials")
    
    def _check_global_auth(self):
        """Global authentication check for all routes"""
        from flask import request, session, redirect, url_for, current_app
        
        # Skip auth routes and static files
        if (request.endpoint and 
            (request.endpoint.startswith('auth.') or 
             request.endpoint == 'static')):
            return None
        
        # Check if route is marked as public
        if request.endpoint:
            view_func = current_app.view_functions.get(request.endpoint)
            if view_func and getattr(view_func, '_is_public', False):
                return None
            
        # Check if user is authenticated
        if not session.get('authenticated'):
            session['next_page'] = request.url
            return redirect(url_for('auth.login'))
        
        return None
    
    def _create_auth_blueprint(self):
        """Create the authentication blueprint with routes"""
        auth_bp = Blueprint('auth', __name__)
        
        @auth_bp.route('/login')
        def login():
            return self._render_login_page()
        
        @auth_bp.route('/login/<provider>')
        def provider_login(provider):
            if provider not in self.providers:
                return f"Provider {provider} not configured", 400
            
            client = self.providers[provider]
            redirect_uri = url_for('auth.callback', provider=provider, _external=True)
            return client.authorize_redirect(redirect_uri)
        
        @auth_bp.route('/callback/<provider>')
        def callback(provider):
            if provider not in self.providers:
                return f"Provider {provider} not configured", 400
            
            client = self.providers[provider]
            token = client.authorize_access_token()
            
            # Get user info
            if provider.lower() == 'google':
                user_info = token.get('userinfo')
                if not user_info:
                    resp = client.parse_id_token(token)
                    user_info = resp
            elif provider.lower() == 'github':
                resp = client.get('user', token=token)
                user_info = resp.json()
                # Get email separately for GitHub
                email_resp = client.get('user/emails', token=token)
                emails = email_resp.json()
                primary_email = next((e['email'] for e in emails if e['primary']), None)
                user_info['email'] = primary_email
            else:
                user_info = {}
            
            email = user_info.get('email')
            if not email:
                return self._render_error_page("No email found in OAuth response"), 400
            
            # Check if user is authorized
            if not self.is_user_authorized(email):
                return self._render_unauthorized_page(email), 403
            
            # Get user data from our database
            db_user = self.get_user_data(email)
            
            # Check if user is active
            if not db_user.get('active', True):
                return self._render_error_page("Account is deactivated"), 403
            
            # Store user in session (merge OAuth data with our database)
            session['user'] = {
                'id': user_info.get('sub') or user_info.get('id'),
                'email': email,
                'name': db_user.get('name') or user_info.get('name'),
                'picture': user_info.get('picture') or user_info.get('avatar_url'),
                'provider': provider,
                'roles': db_user.get('roles', ['user']),
                'notes': db_user.get('notes')
            }
            session['authenticated'] = True
            
            # Redirect to originally requested page or default
            next_page = session.pop('next_page', None)
            return redirect(next_page or current_app.config['AUTH_REDIRECT_URL'])
        
        @auth_bp.route('/logout')
        def logout():
            session.clear()
            return redirect(current_app.config['AUTH_LOGOUT_URL'])
        
        @auth_bp.route('/user')
        def user_info():
            """API endpoint to get current user info"""
            if 'user' in session:
                return jsonify(session['user'])
            return jsonify({'error': 'Not authenticated'}), 401
        
        
        return auth_bp
    
    def _render_unauthorized_page(self, email):
        """Render page for unauthorized users"""
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Access Denied</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 100px;">
            <h2>Access Denied</h2>
            <p>The email address <strong>{email}</strong> is not authorized to access this application.</p>
            <p>Please contact your administrator if you believe this is an error.</p>
            <a href="/auth/logout">Try Different Account</a>
        </body>
        </html>
        '''
    
    def _render_error_page(self, message):
        """Render generic error page"""
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Authentication Error</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 100px;">
            <h2>Authentication Error</h2>
            <p>{message}</p>
            <a href="/auth/login">Try Again</a>
        </body>
        </html>
        '''
    
    def _render_login_page(self):
        """Render a simple login page with available providers"""
        if not self.providers:
            return f'''
            <!DOCTYPE html>
            <html>
            <head><title>Login - Configuration Error</title></head>
            <body style="font-family: Arial; text-align: center; margin-top: 100px;">
                <h2>Authentication Configuration Error</h2>
                <p style="color: #d32f2f; margin: 20px;">No OAuth providers are configured.</p>
                <div style="background: #f5f5f5; padding: 20px; margin: 20px auto; max-width: 600px; text-align: left;">
                    <h3>To fix this issue:</h3>
                    <ol>
                        <li>Set up OAuth credentials for at least one provider</li>
                        <li>Add environment variables (e.g., GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)</li>
                        <li>Restart your application</li>
                    </ol>
                    <p><strong>Supported providers:</strong> {', '.join(self.enabled_providers)}</p>
                </div>
            </body>
            </html>
            '''
        
        providers_html = ""
        for provider_name in self.providers.keys():
            providers_html += f'''
                <a href="/auth/login/{provider_name}" 
                   style="display: inline-block; margin: 10px; padding: 10px 20px; 
                          background: #4285f4; color: white; text-decoration: none; 
                          border-radius: 5px;">
                    Login with {provider_name.title()}
                </a>
            '''
        
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 100px;">
            <h2>Authentication Required</h2>
            <p>Please choose a login method:</p>
            {providers_html}
        </body>
        </html>
        '''

# Decorators for protecting routes
def login_required(f):
    """Decorator to require authentication for a route"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            # Store the requested page to redirect after login
            session['next_page'] = request.url
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_roles = user.get('roles', [])
            if role not in user_roles:
                raise Unauthorized(f'Access restricted - {role} role required')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_any_role(roles):
    """Decorator to require any of the specified roles"""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_roles = user.get('roles', [])
            if not any(role in user_roles for role in roles):
                raise Unauthorized(f'Access restricted - one of {roles} roles required')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_email_domain(domain):
    """Decorator to require specific email domain"""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_email = user.get('email', '')
            if not user_email.endswith(f'@{domain}'):
                raise Unauthorized(f'Access restricted to {domain} email addresses')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_email(allowed_emails):
    """Decorator to require specific email addresses"""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_email = user.get('email', '')
            if user_email not in allowed_emails:
                raise Unauthorized('Access restricted')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Utility functions
def get_current_user():
    """Get the current authenticated user"""
    return session.get('user')

def is_authenticated():
    """Check if user is authenticated"""
    return session.get('authenticated', False)

def has_role(role):
    """Check if current user has specific role"""
    user = session.get('user', {})
    return role in user.get('roles', [])

def public_route(f):
    """Decorator to mark a route as public (bypasses global auth protection)"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    # Mark this function as public
    decorated_function._is_public = True
    return decorated_function