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

# Check if routes_sse exists
try:
    from apps.routes_sse import sse_bp
except ImportError:
    print("WARNING: routes_sse.py not found. SSE functionality will not work.")
    sse_bp = None

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing. Set it in your .env file.")

# ---- Production-Ready Rate Limiter ----
# Automatically uses Redis if REDIS_URL is set (Railway provides this)
# Falls back to memory storage for local development
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],  # Use specific blueprint limits only
    storage_uri=os.environ.get('REDIS_URL', 'memory://'),
    headers_enabled=True,  # Adds X-RateLimit-* headers to responses
    strategy="fixed-window",  # Can also use "moving-window" for more accuracy
)

# ---- Session Config ----
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('ENVIRONMENT') == 'production'  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# ---- CSRF Config ----
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_SSL_STRICT'] = False

csrf = CSRFProtect(app)

csrf.exempt(scanner_bp)
if sse_bp:
    csrf.exempt(sse_bp)

from core.csrf_utils import inject_csrf_meta_tag, inject_csrf_input

@app.context_processor
def inject_csrf_helpers():
    return dict(csrf_token=generate_csrf,
                inject_csrf_meta_tag=inject_csrf_meta_tag,
                inject_csrf_input=inject_csrf_input)

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

    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' blob:; "
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

# ---- Register Blueprints ----
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(scanner_bp, url_prefix="/scanner")
app.register_blueprint(user_bp, url_prefix="/user")
if sse_bp:
    app.register_blueprint(sse_bp, url_prefix="/sse")

# ---- Blueprint-Level Rate Limits ----
# These apply to ALL routes in each blueprint

# Auth routes - STRICT limits to prevent brute force attacks
limiter.limit("10 per minute")(auth_bp)

# Admin routes - Moderate limits for admin operations
limiter.limit("100 per minute")(admin_bp)

# User routes - Generous limits for regular users
limiter.limit("150 per minute")(user_bp)

# Scanner routes - High limits for QR scanning operations
limiter.limit("300 per minute")(scanner_bp)

# SSE routes - Exempt from rate limiting (real-time events)
if sse_bp:
    limiter.exempt(sse_bp)

@app.errorhandler(429)
def rate_limit_handler(e):
    """Enhanced rate limit handler with better logging"""
    from core.validation import log_suspicious_activity, get_client_ip
    
    # Log the rate limit violation
    log_suspicious_activity('rate_limit_exceeded', {
        'ip': get_client_ip(),
        'path': request.path,
        'method': request.method,
        'user_agent': request.headers.get('User-Agent', '')[:200]
    })
    
    if request.path.startswith(('/admin/', '/user/')) or request.blueprint in ['admin', 'user']:
        return render_template("rate_limit.html"), 429

    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'status': 'error',
            'message': 'Rate limit exceeded. Please slow down and try again later.',
            'code': 429,
            'retry_after': e.description if hasattr(e, 'description') else '60 seconds'
        }), 429

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

    return render_template(
        'error.html',
        error_title='Security Error',
        error_message='CSRF token validation failed.',
        error_code=400
    ), 400

@app.errorhandler(401)
def unauthorized(e):
    session.clear()
    if request.path.startswith('/admin/'):
        return redirect('/login')
    elif request.path.startswith('/user/'):
        return redirect('/user/')
    return render_template('error.html', error_title='Unauthorized', error_message='Please log in.', error_code=401), 401

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)