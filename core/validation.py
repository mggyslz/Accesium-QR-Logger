# core/validation.py (OPTIMIZED RATE LIMITING)
import re
from typing import Tuple, Optional
from functools import wraps
from flask import request, jsonify, session
import time
from collections import defaultdict
import secrets

# -------------------------
# Input Length Limits
# -------------------------
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3
MAX_NAME_LENGTH = 100
MIN_NAME_LENGTH = 2
MAX_EMAIL_LENGTH = 255
MAX_ROLE_LENGTH = 50

# -------------------------
# Password Requirements
# -------------------------
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# -------------------------
# Rate Limiting (OPTIMIZED)
# -------------------------
RATE_LIMIT_WINDOW = 60  
RATE_LIMIT_MAX_REQUESTS = 10  
_rate_limit_store = defaultdict(list)
_session_rate_limits = defaultdict(lambda: {'count': 0, 'reset_time': 0})


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validate username with flexible rules.
    Returns (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < MIN_USERNAME_LENGTH:
        return False, f"Username must be at least {MIN_USERNAME_LENGTH} characters"
    
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must not exceed {MAX_USERNAME_LENGTH} characters"
    
    # Allow alphanumeric, underscore, hyphen, and period
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False, "Username can only contain letters, numbers, dots, underscores, and hyphens"
    
    # Must start with a letter or number
    if not username[0].isalnum():
        return False, "Username must start with a letter or number"
    
    # Must end with a letter or number
    if not username[-1].isalnum():
        return False, "Username must end with a letter or number"
    
    # No consecutive special characters
    if re.search(r'[._-]{2,}', username):
        return False, "Username cannot contain consecutive special characters"
    
    return True, None


def validate_name(name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate full name with strict rules.
    Returns (is_valid, error_message)
    """
    if not name:
        return False, "Name is required"
    
    name = name.strip()
    
    if len(name) < MIN_NAME_LENGTH:
        return False, f"Name must be at least {MIN_NAME_LENGTH} characters"
    
    if len(name) > MAX_NAME_LENGTH:
        return False, f"Name must not exceed {MAX_NAME_LENGTH} characters"
    
    # Allow letters, spaces, hyphens, apostrophes, and periods
    if not re.match(r"^[a-zA-Z\s.'-]+$", name):
        return False, "Name can only contain letters, spaces, periods, hyphens, and apostrophes"
    
    # Must contain at least one letter
    if not re.search(r'[a-zA-Z]', name):
        return False, "Name must contain at least one letter"
    
    # No more than 2 consecutive spaces
    if re.search(r'\s{3,}', name):
        return False, "Name cannot contain more than 2 consecutive spaces"
    
    return True, None


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Validate email with RFC 5322 compliant regex (simplified).
    Returns (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    email = email.strip().lower()
    
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email must not exceed {MAX_EMAIL_LENGTH} characters"
    
    # RFC 5322 compliant email regex (simplified but robust)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    local_part, domain = email.rsplit('@', 1)
    
    if len(local_part) > 64:
        return False, "Email local part too long"
    
    if local_part.startswith('.') or local_part.endswith('.'):
        return False, "Email cannot start or end with a period"
    
    if '..' in local_part:
        return False, "Email cannot contain consecutive periods"
    
    if len(domain) > 253:
        return False, "Email domain too long"
    
    if domain.startswith('-') or domain.endswith('-'):
        return False, "Invalid email domain"
    
    if not re.search(r'\.[a-zA-Z]{2,}$', domain):
        return False, "Invalid email domain extension"
    
    return True, None


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password with reasonable requirements (8 char minimum).
    Returns (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters"
    
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    
    if not re.search(r'[\d!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
        return False, "Password must contain at least one number or special character"
    
    weak_patterns = [
        r'12345', r'password', r'qwerty', r'abc123',
        r'letmein', r'welcome', r'admin', r'user'
    ]
    
    password_lower = password.lower()
    for pattern in weak_patterns:
        if pattern in password_lower:
            return False, f"Password contains common weak pattern"
    
    return True, None


def validate_role(role: str) -> Tuple[bool, Optional[str]]:
    """
    Validate role against allowed values.
    Returns (is_valid, error_message)
    """
    if not role:
        return False, "Role is required"
    
    if len(role) > MAX_ROLE_LENGTH:
        return False, f"Role must not exceed {MAX_ROLE_LENGTH} characters"
    
    ALLOWED_ROLES = ['Student', 'Staff', 'Teacher', 'Faculty', 'Admin', 'Guest', 'Visitor', 'Employee', 'Other']
    
    if role not in ALLOWED_ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(ALLOWED_ROLES)}"
    
    return True, None


def sanitize_input(text: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize text input by stripping and limiting length.
    """
    if not text:
        return ""
    
    text = text.strip()
    
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text


# -------------------------
# CSRF Protection
# -------------------------
def generate_csrf_token() -> str:
    """Generate a secure CSRF token or return existing one."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token from request."""
    session_token = session.get('csrf_token')
    if not session_token or not token:
        return False
    
    if secrets.compare_digest(session_token, token):
        return True
    
    try:
        if '.' in token:
            parts = token.split('.')
            if len(parts) == 3:
                import base64
                import json

                encoded_token = parts[0]
                padding = 4 - len(encoded_token) % 4
                if padding != 4:
                    encoded_token += '=' * padding
                
                decoded_bytes = base64.urlsafe_b64decode(encoded_token)
                decoded_token = decoded_bytes.decode('utf-8')
                if decoded_token.startswith('"') and decoded_token.endswith('"'):
                    decoded_token = json.loads(decoded_token)
                
                if secrets.compare_digest(session_token, decoded_token):
                    return True
    except Exception:
        pass
    
    return False

def csrf_protect(f):
    """Decorator to protect routes with CSRF validation."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip CSRF for session extension endpoints
        if request.endpoint == 'auth.resend_code':
            return f(*args, **kwargs)
            
        if request.method == 'POST':
            # Get token from form or header
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            
            if not token:
                return jsonify({"status": "error", "message": "CSRF token missing"}), 403
            
            if not session.get('csrf_token'):
                return jsonify({"status": "error", "message": "Session expired - please refresh"}), 403
            
            if not validate_csrf_token(token):
                return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
        
        return f(*args, **kwargs)
    return decorated_function


# -------------------------
# Rate Limiting (OPTIMIZED)
# -------------------------
def check_rate_limit(identifier: str, max_requests: int = RATE_LIMIT_MAX_REQUESTS, 
                    window: int = RATE_LIMIT_WINDOW, use_session: bool = False) -> Tuple[bool, int]:
    """
    Check if identifier has exceeded rate limit.
    Returns (is_allowed, seconds_until_reset)
    
    Args:
        identifier: IP address or session ID
        max_requests: Maximum number of requests allowed
        window: Time window in seconds
        use_session: If True, use more lenient session-based rate limiting for authenticated users
    """
    current_time = time.time()
    
    if use_session and ('user_id' in session or 'admin_id' in session):
        session_id = session.get('user_id') or session.get('admin_id')
        rate_key = f"session_{session_id}"
        
        session_limit = _session_rate_limits[rate_key]
        
        if current_time > session_limit['reset_time']:
            session_limit['count'] = 0
            session_limit['reset_time'] = current_time + window

        if session_limit['count'] >= max_requests:
            seconds_until_reset = int(session_limit['reset_time'] - current_time) + 1
            return False, seconds_until_reset
        
        session_limit['count'] += 1
        return True, 0
    
    _rate_limit_store[identifier] = [
        t for t in _rate_limit_store[identifier] 
        if current_time - t < window
    ]
    
    request_count = len(_rate_limit_store[identifier])
    
    if request_count >= max_requests:
        oldest_request = min(_rate_limit_store[identifier])
        seconds_until_reset = int(window - (current_time - oldest_request)) + 1
        return False, seconds_until_reset
    
    _rate_limit_store[identifier].append(current_time)
    return True, 0


def rate_limit(max_requests: int = RATE_LIMIT_MAX_REQUESTS, window: int = RATE_LIMIT_WINDOW):
    """
    Decorator to rate limit routes.
    Automatically uses session-based limiting for authenticated users.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            identifier = request.remote_addr or 'unknown'         
            is_authenticated = 'user_id' in session or 'admin_id' in session
            allowed, wait_time = check_rate_limit(
                identifier, 
                max_requests, 
                window, 
                use_session=is_authenticated
            )
            
            if not allowed:
                return jsonify({
                    "status": "error",
                    "message": f"Too many requests. Please try again in {wait_time} seconds.",
                    "retry_after": wait_time
                }), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# -------------------------
# Combined Validation
# -------------------------
def validate_user_registration(username: str, email: str, name: str, 
                              password: str, role: str) -> Tuple[bool, Optional[str]]:
    """
    Validate all user registration inputs.
    Returns (is_valid, error_message)
    """
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    email = sanitize_input(email, MAX_EMAIL_LENGTH)
    name = sanitize_input(name, MAX_NAME_LENGTH)
    role = sanitize_input(role, MAX_ROLE_LENGTH)
    
    valid, error = validate_username(username)
    if not valid:
        return False, error
    
    valid, error = validate_email(email)
    if not valid:
        return False, error
    
    valid, error = validate_name(name)
    if not valid:
        return False, error
    
    valid, error = validate_password(password)
    if not valid:
        return False, error

    valid, error = validate_role(role)
    if not valid:
        return False, error
    
    return True, None


# -------------------------
# Utility Functions
# -------------------------
def get_client_ip() -> str:
    """Get client IP address, considering proxy headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'unknown'


def log_suspicious_activity(activity_type: str, details: dict):
    """Log suspicious activity for security monitoring."""
    from datetime import datetime
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': activity_type,
        'ip': get_client_ip(),
        'details': details
    }
    print(f"[SECURITY] {log_entry}")
    