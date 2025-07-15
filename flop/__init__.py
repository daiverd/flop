"""
Flop - Streamlined OAuth authentication library for Flask microservices
"""

from .auth import (
    FlaskAuth,
    OAUTH_PROVIDERS,
    login_required,
    require_role,
    require_any_role,
    require_email_domain,
    require_email,
    public_route,
    get_current_user,
    is_authenticated,
    has_role,
)

__version__ = "0.1.0"
__all__ = [
    "FlaskAuth",
    "OAUTH_PROVIDERS", 
    "login_required",
    "require_role",
    "require_any_role",
    "require_email_domain",
    "require_email",
    "public_route",
    "get_current_user",
    "is_authenticated",
    "has_role",
]