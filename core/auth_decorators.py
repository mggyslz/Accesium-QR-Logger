from flask import session, redirect, url_for, request, make_response, flash
from functools import wraps
from datetime import datetime, timedelta
import secrets

def regenerate_session():
    """Regenerate session ID to prevent session fixation attacks"""
    session_data = dict(session)
    session.clear()
    for key, value in session_data.items():
        session[key] = value
    session.modified = True

def add_no_cache_headers(response):
    """Add headers to prevent caching of authenticated pages"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

def check_session_timeout():
    """
    Check if session has timed out based on system settings
    Returns True if session is valid, False if timed out
    """
    from core.settings_manager import SystemSettings
    timeout_minutes = SystemSettings.get_session_timeout()
    last_activity = session.get('last_activity')
    if not last_activity:  
        session['last_activity'] = datetime.now().isoformat()
        return True
    try:
        last_activity_time = datetime.fromisoformat(last_activity)
        timeout_threshold = timedelta(minutes=timeout_minutes)
        
        if datetime.now() - last_activity_time > timeout_threshold:
            return False    
        session['last_activity'] = datetime.now().isoformat()
        session.modified = True
        return True
    except (ValueError, TypeError):  
        session['last_activity'] = datetime.now().isoformat()
        return True


def admin_login_required(f):
    """Decorator for admin-only routes with session timeout"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('auth.login_page'))             
        if not check_session_timeout():
            session.clear()
            flash("Your session has expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for('auth.login_page'))    
        admin_id = session.get('admin_id')
        admin_name = session.get('admin_name') 
        if not admin_id or not admin_name:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for('auth.login_page'))   
        response = make_response(f(*args, **kwargs))
        response = add_no_cache_headers(response)  
        return response
    return decorated_function


def user_login_required(f):
    """Decorator for user-only routes with session timeout"""
    @wraps(f)
    def decorated_function(*args, **kwargs):  
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('user.login_page'))

        if not check_session_timeout():
            session.clear()
            flash("Your session has expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for('user.login_page'))
 
        user_id = session.get('user_id')
        username = session.get('username')
        
        if not user_id or not username:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for('user.login_page'))

        response = make_response(f(*args, **kwargs))
        response = add_no_cache_headers(response)
        return response
    return decorated_function


def logout_session(user_type='user'):
    """Properly clear all session data"""
    if user_type == 'admin':
        user_id = session.get('admin_id')
        username = session.get('admin_name')
    else:
        user_id = session.get('user_id')
        username = session.get('username')
    session.clear()
    session.modified = True
    return user_id, username


def create_logout_response(redirect_url, user_type='user'):
    """Create a proper logout response with cache headers"""
    response = make_response(redirect(redirect_url))
    response = add_no_cache_headers(response)
    response.set_cookie(
        'session',
        value='',
        max_age=0,
        expires=0,
        httponly=True,
        secure=request.is_secure,
        samesite='Lax'
    )
    return response