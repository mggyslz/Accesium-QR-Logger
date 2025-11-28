from flask import Flask, render_template, send_from_directory, jsonify, request, redirect, session
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config.settings import QRCODE_DIR
from dotenv import load_dotenv
import os

load_dotenv()

from apps.routes_admin import admin_bp
from apps.routes_auth import auth_bp
from apps.routes_scanner import scanner_bp
from apps.routes_user import user_bp

# Check if routes_sse exists in apps folder, otherwise try root folder
try:
    from apps.routes_sse import sse_bp
except ImportError:
    try:
        from apps.routes_sse import sse_bp
    except ImportError:
        print("WARNING: routes_sse.py not found. SSE functionality will not work.")
        sse_bp = None

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing. Set it in your .env file.")

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# CSRF configuration - MUST be before CSRFProtect initialization
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_SSL_STRICT'] = False

csrf = CSRFProtect(app)

# Properly exempt scanner and SSE blueprints from CSRF protection
csrf.exempt(scanner_bp)
if sse_bp:
    csrf.exempt(sse_bp)  # Exempt SSE from CSRF (it's read-only)

from core.csrf_utils import inject_csrf_meta_tag, inject_csrf_input

@app.context_processor
def inject_csrf_helpers():
    return dict(csrf_token=generate_csrf,
                inject_csrf_meta_tag=inject_csrf_meta_tag,
                inject_csrf_input=inject_csrf_input)

@app.before_request
def force_https():
    if request.host.startswith(('localhost', '127.0.0.1')):
        return None
    if request.blueprint in ['scanner', 'sse']:  # Allow SSE in HTTP for local dev
        return None
    if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        return redirect(request.url.replace('http://', 'https://', 1), code=301)

@app.after_request
def set_security_headers(response):
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    })
    
    # More permissive CSP for SSE
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' blob:; "  # Added blob: for SSE
        "media-src 'self' blob:; "
        "frame-ancestors 'self';"
    )
    response.headers['Content-Security-Policy'] = csp

    protected_paths = ['/admin/', '/user/dashboard', '/user/profile', '/user/attendance']
    is_protected = any(request.path.startswith(p) for p in protected_paths)
    is_authenticated = 'admin_id' in session or 'user_id' in session

    if is_protected or is_authenticated:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    else:
        response.headers['Cache-Control'] = 'public, max-age=300'

    if request.blueprint == 'scanner':
        response.headers['Permissions-Policy'] = 'camera=(self), microphone=(), geolocation=()'
    else:
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    return response

@app.before_request
def validate_session():
    public_routes = ['/', '/health', '/login', '/signup', '/static', '/qrcodes', '/scanner', '/sse']
    if any(request.path.startswith(route) for route in public_routes):
        return None

    if request.path.startswith('/admin/'):
        if 'admin_id' not in session or not session.get('admin_name'):
            session.clear()
            return redirect('/login')
    elif request.path.startswith('/user/') and request.path != '/user/':
        if 'user_id' not in session or not session.get('username'):
            session.clear()
            return redirect('/user/')

    return None

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(scanner_bp, url_prefix="/scanner")
app.register_blueprint(user_bp, url_prefix="/user")
if sse_bp:
    app.register_blueprint(sse_bp, url_prefix="/sse")

# Apply rate limits to blueprints - EXEMPT SSE FROM RATE LIMITING
limiter.limit("100 per minute")(admin_bp)
limiter.limit("150 per minute")(user_bp)
limiter.limit("30 per minute")(auth_bp)
limiter.limit("200 per minute")(scanner_bp)

# Explicitly exempt SSE routes from rate limiting
if sse_bp:
    limiter.exempt(sse_bp)

@app.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit errors for both HTML and JSON requests"""
    if request.path.startswith(('/admin/', '/user/')) or \
       request.blueprint in ['admin', 'user']:
        # For admin/user pages, show the rate limit HTML page
        return render_template("rate_limit.html"), 429
    
    # For API/JSON requests, return JSON response
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'status': 'error', 
            'message': 'Rate limit exceeded. Please slow down and try again later.',
            'code': 429
        }), 429
    
    # Default fallback
    return render_template("rate_limit.html"), 429

@app.route("/rate-limit")
def rate_limit_page():
    return render_template("rate_limit.html")

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/documentation")
def documentation():
    return render_template("documentation.html")

@app.route("/developer")
def developer():
    return render_template("developer_docs.html")

@app.route("/qrcodes/<path:filename>")
def serve_qr(filename):
    return send_from_directory(QRCODE_DIR, filename)

@app.route("/health")
def health_check():
    from core.email_utils import is_smtp_configured
    is_authenticated = 'admin_id' in session or 'user_id' in session
    if request.args.get('check_auth') == 'true' and not is_authenticated:
        return jsonify({"status": "unauthorized"}), 401
    return jsonify({
        "status": "healthy",
        "authenticated": is_authenticated,
        "smtp_configured": is_smtp_configured(),
        "2fa_enabled": is_smtp_configured(),
        "csrf_enabled": True,
        "https_enabled": request.is_secure,
        "session_timeout": app.config['PERMANENT_SESSION_LIFETIME']
    })

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'error', 'message': 'CSRF token validation failed.', 'reason': str(e.description)}), 400
    return render_template('error.html', error_title='Security Error', error_message='CSRF token validation failed.', error_code=400), 400

@app.errorhandler(401)
def unauthorized(e):
    session.clear()
    if request.path.startswith('/admin/'):
        return redirect('/login')
    elif request.path.startswith('/user/'):
        return redirect('/user/')
    return render_template('error.html', error_title='Unauthorized', error_message='Please log in.', error_code=401), 401


if __name__ == "__main__":
    use_https = os.getenv('USE_HTTPS', 'false').lower() == 'true'
    if use_https:
        import ssl
        cert_file = 'cert.pem'
        key_file = 'key.pem'
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("HTTPS enabled but certificates not found!")
            exit(1)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)
    else:
        app.run(debug=True, host="0.0.0.0", port=5000)


# Design / Color Scheme
# - dark/light mode toggle

# - make the time 24 hour format consistent across the app

# Documentation
# - short setup guide and basic usage notes
# - brief explanation of database schema and routes
# - how to enable 2FA and whitelist configuration
# - future improvement notes (API, notifications, etc.)


"""
In case of database deletion and re-initialization:

python -m core.init_db

pip install flask-limiter

http://localhost:5000/user/signup
http://localhost:5000/user/dashboard
http://localhost:5000/user/
"""

'''idea project: AI-powered face identification with description and conversation log'''

