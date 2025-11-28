
from datetime import datetime   
from flask import Blueprint, render_template,jsonify, request, redirect, url_for, session, flash, make_response
from core.database import (
    get_admin_by_username_or_email, add_admin_with_email, get_conn,
    record_login_attempt, is_account_locked, clear_login_attempts
)
from core.security import verify_pin
from core.email_utils import (
    create_verification_code, verify_code, send_login_verification_email,
    send_welcome_email, send_account_locked_email, is_smtp_configured
)
from core.notification_utils import (
    notify_successful_login, notify_failed_login_attempt, notify_account_locked
)
from core.trusted_device_utils import (
    is_trusted_device, add_trusted_device, remove_trusted_device
)
from core.auth_decorators import (
    regenerate_session, admin_login_required, logout_session, 
    create_logout_response, add_no_cache_headers
)
from core.validation import csrf_protect, rate_limit

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login')
def login_page():
    """Admin login page - redirect if already logged in"""
    if 'admin_id' in session:
        return redirect(url_for('admin.dashboard'))
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        admin_count = cur.fetchone()[0]
    finally:
        conn.close()
    smtp_configured = is_smtp_configured()
    response = make_response(
        render_template('admin_login.html', 
                       admin_exists=(admin_count > 0), 
                       smtp_configured=smtp_configured)
    )
    response = add_no_cache_headers(response)
    return response

@auth_bp.route('/login', methods=['POST'])
@csrf_protect
def login():
    """Admin login endpoint"""
    identifier = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip_address = request.remote_addr

    print(f"[DEBUG] Admin login attempt - identifier: {identifier}")
    print(f"[DEBUG] All cookies: {dict(request.cookies)}")
    
    # Check if any admin accounts exist
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        admin_count = cur.fetchone()[0]
    finally:
        conn.close()
    
    if admin_count == 0:
        flash("No admin accounts exist. Please sign up first.", "info")
        return redirect(url_for("auth.signup_page"))

    # Check if account is locked
    if is_account_locked('admin', identifier):
        flash("Account temporarily locked due to multiple failed attempts. Please try again in 15 minutes.", "danger")
        return redirect(url_for("auth.login_page"))

    # Verify admin credentials
    admin = get_admin_by_username_or_email(identifier)
    if not admin:
        record_login_attempt('admin', identifier, False, ip_address)
        flash("Invalid username/email or password.", "danger")
        return redirect(url_for("auth.login_page"))
    
    admin_id, username, email, name, pass_hash, pass_salt, email_verified = admin
    
    # Verify password
    if not verify_pin(password, pass_salt, pass_hash):
        record_login_attempt('admin', identifier, False, ip_address)
        notify_failed_login_attempt('admin', admin_id, username)
        
        if is_account_locked('admin', identifier):
            notify_account_locked('admin', admin_id, username)
            send_account_locked_email(email, username)
            flash("Account locked due to multiple failed attempts. Check your email for details.", "danger")
        else:
            flash("Incorrect password.", "danger")
        
        return redirect(url_for("auth.login_page"))

    # Check for trusted device
    device_token = request.cookies.get('admin_device_token')
    is_device_trusted = False
    if device_token:
        print(f"[DEBUG] Admin device token found: {device_token[:20]}...")
        try:
            is_device_trusted = is_trusted_device(
                'admin', 
                admin_id, 
                device_token,
                ip_address=ip_address,
                user_agent=request.headers.get('User-Agent', '')
            )
            print(f"[DEBUG] Admin device token verified: {is_device_trusted}")
        except Exception as e:
            print(f" Error checking admin trusted device: {str(e)}")
            is_device_trusted = False
    else:
        print(f"[DEBUG] No admin device token found")

    # Check if 2FA is required by system settings
    from core.settings_manager import SystemSettings
    require_2fa = SystemSettings.is_2fa_required()

    # Trusted device - bypass 2FA
    if is_device_trusted:
        print(f"[DEBUG] Trusted admin device detected - bypassing 2FA")
        
        regenerate_session()
        session["admin_id"] = admin_id
        session["admin_username"] = username
        session["admin_name"] = name
        session["admin_email"] = email
        session.permanent = True
        
        record_login_attempt('admin', identifier, True, ip_address)
        clear_login_attempts('admin', identifier)
        notify_successful_login('admin', admin_id, username)
        
        flash(f"Welcome back, {name}!", "success")
        return redirect(url_for("admin.dashboard"))

    # 2FA required AND SMTP configured
    if require_2fa and is_smtp_configured():
        print(f"[DEBUG] 2FA is required - sending code")
        
        code = create_verification_code('admin', admin_id, email, 'login')
        send_login_verification_email(email, username, code)
        
        session['pending_admin_id'] = admin_id
        session['pending_admin_username'] = username
        session['pending_admin_name'] = name
        session['pending_admin_email'] = email
        
        flash("Verification code sent to your email. Please check your inbox.", "info")
        return redirect(url_for("auth.verify_2fa"))

    # 2FA required but SMTP not configured - allow with warning
    elif require_2fa and not is_smtp_configured():
        print(f"[WARNING] 2FA required but SMTP not configured - allowing login with warning")
        
        regenerate_session()
        session["admin_id"] = admin_id
        session["admin_username"] = username
        session["admin_name"] = name
        session["admin_email"] = email
        session.permanent = True
        
        record_login_attempt('admin', identifier, True, ip_address)
        clear_login_attempts('admin', identifier)
        notify_successful_login('admin', admin_id, username)
        
        flash(f"Welcome back, {name}! ⚠️ Warning: 2FA is required but email is not configured.", "warning")
        return redirect(url_for("admin.dashboard"))

    # 2FA not required - direct login
    else:
        print(f"[DEBUG] 2FA not required - direct login")
        
        regenerate_session()
        session["admin_id"] = admin_id
        session["admin_username"] = username
        session["admin_name"] = name
        session["admin_email"] = email
        session.permanent = True
        
        record_login_attempt('admin', identifier, True, ip_address)
        clear_login_attempts('admin', identifier)
        notify_successful_login('admin', admin_id, username)
        
        flash(f"Welcome back, {name}!", "success")
        return redirect(url_for("admin.dashboard"))


@auth_bp.route('/verify-2fa')
def verify_2fa_page():
    """2FA verification page"""
    if 'pending_admin_id' not in session:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('auth.login_page'))
    
    response = make_response(
        render_template('admin_verify_2fa.html', 
                       email=session.get('pending_admin_email', ''))
    )
    response = add_no_cache_headers(response)
    return response


@auth_bp.route('/verify-2fa', methods=['POST'])
@csrf_protect
def verify_2fa():
    """Verify 2FA code"""
    if 'pending_admin_id' not in session:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('auth.login_page'))
    
    code = request.form.get('code', '').strip()
    remember_device = request.form.get('remember_device') == 'on'
    admin_id = session['pending_admin_id']
    username = session['pending_admin_username']
    name = session.get('pending_admin_name', username)  
    email = session['pending_admin_email']
    
    print(f"[DEBUG] Admin verify 2FA - Remember device: {remember_device}")
    
    if verify_code('admin', admin_id, code, 'login'):
        
        session.pop('pending_admin_id', None)
        session.pop('pending_admin_username', None)
        session.pop('pending_admin_name', None)  
        session.pop('pending_admin_email', None)
        regenerate_session()
        session['admin_id'] = admin_id
        session['admin_username'] = username
        session['admin_name'] = name  
        session['admin_email'] = email
        session.permanent = True
        record_login_attempt('admin', email, True, request.remote_addr)
        clear_login_attempts('admin', email)
        notify_successful_login('admin', admin_id, username)
        resp = make_response(redirect(url_for('admin.dashboard')))
        if remember_device:
            try:
                device_token = add_trusted_device(
                    'admin',
                    admin_id,
                    request.remote_addr,
                    request.headers.get('User-Agent', ''),
                    days=30
                )
                print(f"[DEBUG] Setting admin trusted device cookie: {device_token[:10]}...")
                resp.set_cookie(
                    'admin_device_token',
                    device_token,
                    max_age=30*24*60*60,  
                    path='/',
                    httponly=True,
                    secure=request.is_secure,
                    samesite='Lax'
                )
                flash(f"Welcome back, {name}! This device will be remembered for 30 days.", "success")  
            except Exception as e:
                print(f"Error adding admin trusted device: {str(e)}")
                flash(f"Welcome back, {name}! (Could not remember device.)", "warning")  
        else:
            flash(f"Welcome back, {name}!", "success")  
        
        return resp
    else:
        flash("Invalid or expired verification code. Please try again.", "danger")
        return redirect(url_for('auth.verify_2fa_page'))

@auth_bp.route('/resend-code', methods=['POST'])
@csrf_protect  
def resend_code():
    """Resend 2FA verification code"""
    if 'pending_admin_id' not in session:
        return jsonify({"status": "error", "message": "Session expired"}), 400
    
    admin_id = session['pending_admin_id']
    username = session['pending_admin_username']
    email = session['pending_admin_email']
    
    code = create_verification_code('admin', admin_id, email, 'login')
    if send_login_verification_email(email, username, code):
        return jsonify({"status": "success", "message": "Code resent to your email"})
    else:
        return jsonify({"status": "error", "message": "Failed to send code"}), 500

@auth_bp.route('/remove-device/<int:device_id>', methods=['POST'])
@csrf_protect
@admin_login_required
def remove_device(device_id):
    """Remove a trusted device"""
    if 'admin_id' not in session:
        flash("Not authorized.", "danger")
        return redirect(url_for('auth.login_page'))
    
    try:
        # Verify the device belongs to this admin before deleting
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT device_id FROM trusted_devices 
                WHERE device_id = ? AND user_type = 'admin' AND user_id = ?
            """, (device_id, session['admin_id']))
            
            if not cur.fetchone():
                flash("Device not found or doesn't belong to you.", "danger")
                return redirect(url_for('admin.dashboard'))
        finally:
            conn.close()
        
        remove_trusted_device(device_id)
        flash("Device removed successfully.", "success")
    except Exception as e:
        print(f"Error removing device: {str(e)}")
        flash("Failed to remove device.", "danger")
    
    return redirect(url_for('admin.dashboard'))

@auth_bp.route('/signup', methods=['POST'])
@csrf_protect
def signup():
    """Create new admin account"""
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    name = request.form.get('name', '').strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    
    if not username or not email or not password:
        flash("Username, email, and password are required.", "danger")
        return redirect(url_for("auth.signup_page"))
    
    if '@' not in email:
        flash("Invalid email address.", "danger")
        return redirect(url_for("auth.signup_page"))
    
    if len(username) < 3:
        flash("Username must be at least 3 characters long.", "danger")
        return redirect(url_for("auth.signup_page"))
    
    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "danger")
        return redirect(url_for("auth.signup_page"))
    
    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("auth.signup_page"))
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        admin_count = cur.fetchone()[0]
    finally:
        conn.close()
    
    
    if admin_count > 0 and 'admin_id' not in session:
        flash("Unauthorized signup attempt.", "danger")
        return redirect(url_for('auth.login_page'))
    
    try:
        admin_id = add_admin_with_email(username, email, name, password)
        send_welcome_email(email, username, username)
        
        flash(f"Admin account created successfully! Welcome, {name}.", "success") 
        
        if admin_count == 0:
            regenerate_session()
            session["admin_id"] = admin_id
            session["admin_name"] = username
            session["admin_email"] = email
            session.permanent = True
            notify_successful_login('admin', admin_id, username)
            return redirect(url_for("admin.dashboard"))
        else:
            return redirect(url_for("admin.dashboard"))
            
    except ValueError as ve:
        flash(str(ve), "danger")
        return redirect(url_for("auth.signup_page"))
    except Exception as e:
        flash(f"Error creating admin account: {str(e)}", "danger")
        return redirect(url_for("auth.signup_page"))

@auth_bp.route('/signup')
def signup_page():
    """Admin signup page - only allow if no admins exist or logged in as admin"""
    # Check if admin already logged in
    if 'admin_id' in session:
        flash("You are already logged in.", "info")
        return redirect(url_for('admin.dashboard'))
    
    # Check if any admin accounts exist
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        admin_count = cur.fetchone()[0]
    finally:
        conn.close()
    
    # If admins exist, redirect to login
    if admin_count > 0:
        flash("Admin accounts already exist. Please login instead.", "info")
        return redirect(url_for('auth.login_page'))
    
    smtp_configured = is_smtp_configured()
    
    response = make_response(
        render_template('admin_signup.html', smtp_configured=smtp_configured)
    )
    response = add_no_cache_headers(response)
    return response

@auth_bp.route('/logout', methods=['GET', 'POST'])
@csrf_protect  # Use the decorator
def logout():
    """Admin logout - supports both GET and POST"""
    
    # Perform logout
    user_id, username = logout_session('admin')
    response = create_logout_response(url_for('auth.login_page'), 'admin')
    flash("Logged out successfully.", "info")
    return response

@auth_bp.route('/extend-session', methods=['POST'])
@csrf_protect 
@admin_login_required
def extend_session():
    """Extend the current admin session"""
    try:
        
        session.modified = True
        
        
        session['last_activity'] = datetime.now().isoformat()
        
        return jsonify({
            "status": "success",
            "message": "Session extended successfully"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to extend session: {str(e)}"
        }), 500