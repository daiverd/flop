#!/usr/bin/env python3
"""
Example Flask application demonstrating the flop OAuth authentication library.

Setup:
1. Copy .env.example to .env and fill in your OAuth credentials
2. uv run python example_app.py

Visit http://localhost:5000 to test all authentication features.
"""

import os
from flask import Flask, render_template_string, session, jsonify, request, redirect, url_for
from flop import (FlaskAuth, login_required, require_role, require_any_role, 
                  require_email_domain, get_current_user, is_authenticated, has_role, public_route)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-change-in-production')
    
    # Initialize authentication with global protection enabled
    # Try with protect_all_routes=True to see the difference!
    protect_all = os.getenv('PROTECT_ALL_ROUTES', 'false').lower() == 'true'
    auth = FlaskAuth(app, users_file='users.yaml', protect_all_routes=protect_all)
    
    # Common HTML template
    def render_page(title, content):
        user = get_current_user()
        protection_status = "🌐 Global Protection ON" if protect_all else "🔓 Per-Route Protection"
        nav_links = [
            ('/', 'Home (@public_route)'),
            ('/dashboard', '🔒 Dashboard (@login_required)'),
            ('/admin', '👑 Admin (@require_role)'),
            ('/management', '📊 Management (@require_any_role)'),
            ('/company-only', '🏢 Company (@require_email_domain)'),
            ('/auto-protected', '🤖 Auto-Protected (no decorator)'),
            ('/public-demo', '🌍 Public Demo (@public_route)'),
            ('/api/user-info', '📱 API (JSON)'),
        ]
        
        nav_html = ' | '.join([f'<a href="{url}">{text}</a>' for url, text in nav_links])
        
        return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head><title>{title} - Flop Auth Demo</title></head>
        <body style="font-family: Arial; margin: 20px; line-height: 1.6;">
            <h1>🔐 Flop OAuth Demo</h1>
            <div style="background: #fff3cd; padding: 10px; margin: 10px 0; border: 1px solid #ffeaa7; border-radius: 5px;">
                <strong>{protection_status}</strong> - Set PROTECT_ALL_ROUTES=true to test global protection
            </div>
            <nav style="background: #f0f0f0; padding: 10px; margin: 10px 0;">{nav_html}</nav>
            
            {"" if not is_authenticated() else f'''
            <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 10px 0;">
                👋 <strong>{user.name}</strong> ({user.email}) | Roles: {", ".join(user.roles)} | 
                <a href="/auth/logout">Logout</a>
            </div>
            '''}
            
            <h2>{title}</h2>
            {content}
        </body>
        </html>
        """)
    
    @app.route('/')
    @public_route  # This route is always public
    def home():
        mode_explanation = f"""
        <div style="background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <h3>Current Protection Mode: {protection_status}</h3>
            {'<p><strong>Global Protection ON:</strong> All routes require authentication by default. Use <code>@public_route</code> for exceptions.</p>' if protect_all else '<p><strong>Per-Route Protection:</strong> Only routes with <code>@login_required</code> or role decorators are protected.</p>'}
            <p><strong>Toggle:</strong> Set <code>PROTECT_ALL_ROUTES=true</code> in .env to try global protection mode.</p>
        </div>
        """
        
        if is_authenticated():
            user = get_current_user()
            content = f"""
            {mode_explanation}
            <p>✅ <strong>Authenticated!</strong> Try the different routes above to see protection in action.</p>
            <h4>Your Access Levels:</h4>
            <ul>
                <li>{'✅' if has_role('admin') else '❌'} Admin access</li>
                <li>{'✅' if has_role('manager') else '❌'} Manager access</li>
                <li>{'✅' if has_role('readonly') else '❌'} Readonly access</li>
                <li>{'✅' if user.email.endswith('@company.com') else '❌'} Company email domain (@company.com)</li>
            </ul>
            <p><strong>Key routes to test:</strong></p>
            <ul>
                <li><strong>Auto-Protected</strong> - Shows how global protection works</li>
                <li><strong>Public Demo</strong> - Always accessible with <code>@public_route</code></li>
                <li><strong>Admin/Management</strong> - Role-based access control</li>
            </ul>
            """
        else:
            content = f"""
            {mode_explanation}
            <p>🔓 <strong>Not logged in.</strong></p>
            <p><a href="/auth/login" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Login with OAuth</a></p>
            <p>After login, you can test different protection scenarios using the navigation above.</p>
            """
        
        return render_page('Flop OAuth Demo', content)
    
    @app.route('/dashboard')
    @login_required  # Explicit login required (works in both modes)
    def dashboard():
        decorator_info = "@login_required (explicit)" if not protect_all else "@login_required (redundant when global=True)"
        return render_page('Dashboard', f'<p>✅ This page requires authentication</p><p><code>{decorator_info}</code></p>')
    
    @app.route('/admin')
    @require_role('admin')  # Role decorators automatically include login check
    def admin():
        return render_page('Admin Area', '<p>👑 This page requires "admin" role</p><p><code>@require_role("admin")</code></p>')
    
    @app.route('/management')
    @require_any_role(['admin', 'manager'])
    def management():
        return render_page('Management', '<p>📊 This page requires "admin" OR "manager" role</p><p><code>@require_any_role(["admin", "manager"])</code></p>')
    
    @app.route('/company-only')
    @require_email_domain('company.com')
    def company_only():
        return render_page('Company Only', '<p>🏢 This page requires @company.com email</p><p><code>@require_email_domain("company.com")</code></p>')
    
    @app.route('/auto-protected')
    def auto_protected():
        """This route has no decorators - behavior depends on global setting"""
        if protect_all:
            content = '<p>🌐 <strong>Auto-protected by global setting!</strong></p><p>No decorators needed when <code>protect_all_routes=True</code></p>'
        else:
            content = '<p>🔓 <strong>This route is currently public</strong></p><p>Would be protected if <code>protect_all_routes=True</code></p>'
        return render_page('Auto-Protected Route', content)
    
    @app.route('/public-demo')
    @public_route  # This route is always accessible
    def public_demo():
        content = f'''
        <p>🌍 <strong>This is a public route!</strong></p>
        <p>Always accessible regardless of global protection setting.</p>
        <p><code>@public_route</code> decorator bypasses all authentication.</p>
        <p><strong>Current mode:</strong> {protection_status}</p>
        '''
        return render_page('Public Demo', content)
    
    @app.route('/api/user-info')
    @login_required
    def api_user_info():
        user = get_current_user()
        return jsonify({
            'authenticated': is_authenticated(),
            'user': {
                'name': user.name,
                'email': user.email,
                'roles': user.roles,
                'provider': user.provider
            },
            'permissions': {
                'is_admin': has_role('admin'),
                'is_manager': has_role('manager'),
                'is_readonly': has_role('readonly')
            }
        })
    
    return app

# Create app instance for gunicorn
app = create_app()

if __name__ == '__main__':
    # Load environment variables from .env file if it exists
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        print("python-dotenv not installed. Set environment variables manually.")
    
    app.run(debug=True, host='0.0.0.0', port=5000)