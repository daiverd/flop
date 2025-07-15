# Flop

Streamlined OAuth authentication library for Flask with automatic provider setup and YAML-based user management.

## Features

- 🔐 **Auto-configure OAuth** - Google & GitHub providers from environment variables
- 👥 **YAML user management** - No database needed, edit users.yaml directly  
- 🌐 **Global protection mode** - Protect all routes by default or use per-route decorators
- 🎭 **Role-based access** - Built-in roles with flexible decorators
- 🛡️ **Session security** - Secure session management and email-based authorization

## Quick Start

```bash
# Install
uv sync  # or pip install -r requirements.txt

# Configure OAuth providers
cp .env.example .env  # Add your OAuth credentials

# Run demo
uv run python example_app.py
# Visit http://localhost:5000
```

## Usage

### Per-Route Protection

```python
from flask import Flask
from flop import FlaskAuth, login_required, require_role

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
auth = FlaskAuth(app, users_file='users.yaml')

@app.route('/dashboard')
@login_required
def dashboard():
    return "Protected dashboard"

@app.route('/admin')
@require_role('admin') 
def admin():
    return "Admin only"
```

### Global Protection Mode

```python
# Protect ALL routes by default
auth = FlaskAuth(app, protect_all_routes=True)

@app.route('/')
@public_route  # Explicit exception
def home():
    return "Public page"

@app.route('/dashboard')  
def dashboard():
    return "Auto-protected"  # No decorator needed
```

### User Management

Edit `users.yaml` directly:

```yaml
users:
  user@example.com:
    name: "User Name"
    roles: ["user", "admin"]
    active: true
```

### Decorators

- `@login_required` - Authentication required
- `@require_role('admin')` - Specific role required  
- `@require_any_role(['admin', 'manager'])` - Any role required
- `@require_email_domain('company.com')` - Email domain restriction
- `@public_route` - Bypass global protection

## Configuration

### OAuth Providers

Add credentials to `.env`:

```bash
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
FLASK_SECRET_KEY=your_secret_key
```

Providers auto-register when credentials are available.

### Global Protection

```python
# Enable via constructor
auth = FlaskAuth(app, protect_all_routes=True)

# Or via environment variable
PROTECT_ALL_ROUTES=true
```

## OAuth Setup

### Google OAuth
1. [Google Cloud Console](https://console.developers.google.com/) → Create project
2. Enable Google+ API → Create OAuth 2.0 credentials  
3. Redirect URI: `http://localhost:5000/auth/callback/google`

### GitHub OAuth
1. [GitHub Developer Settings](https://github.com/settings/applications/new) → New OAuth App
2. Callback URL: `http://localhost:5000/auth/callback/github`

## API Endpoints

Auto-registered routes:
- `GET /auth/login` - Login page with provider options
- `GET /auth/login/<provider>` - Initiate OAuth flow  
- `GET /auth/callback/<provider>` - OAuth callback handler
- `GET /auth/logout` - Logout and clear session
- `GET /auth/user` - Current user info (JSON)

## License

MIT License - see LICENSE file for details.