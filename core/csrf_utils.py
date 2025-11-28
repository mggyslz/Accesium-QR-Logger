from flask_wtf.csrf import generate_csrf
from flask import jsonify, request
from functools import wraps

def get_csrf_token():
    return generate_csrf()

def csrf_error_response(reason="CSRF token validation failed"):
    return jsonify({
        'status': 'error',
        'message': 'Security validation failed. Please refresh the page and try again.',
        'reason': str(reason)
    }), 400
def validate_csrf_ajax(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        
        
        return f(*args, **kwargs)
    return decorated_function


def inject_csrf_meta_tag():
    token = generate_csrf()
    return f'<meta name="csrf-token" content="{token}">'


def inject_csrf_input():

    token = generate_csrf()
    return f'<input type="hidden" name="csrf_token" value="{token}">'