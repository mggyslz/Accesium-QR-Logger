
from flask import Blueprint, render_template, request, jsonify, url_for, session, redirect, flash, make_response
from core.database import (
    get_user_by_username_or_email, add_user_account_with_email, get_user_attendance,
    get_user_by_id, update_user_profile, get_conn, utc_to_ph_time,
    record_login_attempt, is_account_locked, clear_login_attempts, check_force_password_change,
    get_user_email, update_user_password_and_clear_flag, get_user_current_status,get_user_daily_scan_count
)
from core.security import verify_pin
from core.email_utils import (
    create_verification_code, verify_code, send_login_verification_email,
    send_welcome_email, send_account_locked_email, is_smtp_configured,
    send_password_changed_notification_email
)
from core.notification_utils import (
    notify_successful_login, notify_failed_login_attempt, notify_account_locked,
    notify_new_user_registered, notify_password_changed, get_user_notifications,
    get_unread_count, mark_notification_read, mark_all_read
)
from core.trusted_device_utils import (
    is_trusted_device, add_trusted_device, get_user_trusted_devices, remove_trusted_device
)
from core.validation import (
    validate_user_registration,
    validate_username,
    validate_email,
    validate_name,
    validate_role,
    validate_password,
    sanitize_input,
    csrf_protect,
    rate_limit,
    generate_csrf_token,
    get_client_ip,
    log_suspicious_activity,
    MAX_USERNAME_LENGTH,
    MAX_EMAIL_LENGTH,
    MAX_NAME_LENGTH
)
from core.auth_decorators import (
    user_login_required, regenerate_session, logout_session, 
    create_logout_response, add_no_cache_headers
)
from flask_wtf.csrf import generate_csrf, validate_csrf
from core.csrf_utils import inject_csrf_meta_tag, inject_csrf_input
from datetime import datetime
import re

user_bp = Blueprint('user', __name__, template_folder='../templates', url_prefix='/user')

@user_bp.context_processor
def inject_csrf_token():
    from markupsafe import Markup
    def get_csrf_token():
        return generate_csrf()
    return dict(
        csrf_token=get_csrf_token,
        inject_csrf_meta_tag=inject_csrf_meta_tag,
        inject_csrf_input=inject_csrf_input
    )
    
@user_bp.route('/')
def login_page():
    """User login page - redirect if already logged in"""
    if 'user_id' in session:
        return redirect(url_for('user.dashboard'))
    smtp_configured = is_smtp_configured()
    response = make_response(
        render_template('user_login.html', smtp_configured=smtp_configured)
    )
    response = add_no_cache_headers(response)
    return response

@user_bp.route('/login', methods=['POST'])
@csrf_protect
def login():
    """User login endpoint with trusted-device support and conditional 2FA"""
    identifier = sanitize_input(request.form.get('username', ''), MAX_USERNAME_LENGTH)
    password = request.form.get('password', '')  
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    print(f"[DEBUG] Login attempt - identifier: {identifier}, ip: {ip_address}, user_agent: {user_agent}")
    
    if not identifier or not password:
        log_suspicious_activity('empty_login_fields', {'identifier': identifier, 'ip': ip_address})
        flash("Username/email and password are required.", "danger")
        return redirect(url_for('user.login_page'))
    
    if '@' in identifier:
        valid, error = validate_email(identifier)
    else:
        valid, error = validate_username(identifier)
    
    if not valid:
        log_suspicious_activity('invalid_login_identifier', {
            'identifier': identifier,
            'error': error,
            'ip': ip_address
        })
        flash("Invalid username/email format.", "danger")
        return redirect(url_for('user.login_page'))
    
    if is_account_locked('user', identifier):
        log_suspicious_activity('locked_account_login_attempt', {
            'identifier': identifier,
            'ip': ip_address
        })
        flash("Account temporarily locked due to multiple failed attempts.", "danger")
        return redirect(url_for('user.login_page'))

    user = get_user_by_username_or_email(identifier)
    if not user:
        record_login_attempt('user', identifier, False, ip_address)
        log_suspicious_activity('user_not_found', {'identifier': identifier, 'ip': ip_address})
        flash("Invalid username/email or password.", "danger")
        return redirect(url_for('user.login_page'))
    
    user_id, username, email, name, role, password_hash, password_salt, status, qr_code, qr_token, email_verified = user
    print(f"[DEBUG] User found - user_id: {user_id}, status: {status}")
    
    if status != 'Active':
        log_suspicious_activity('inactive_account_login', {
            'user_id': user_id,
            'status': status,
            'ip': ip_address
        })
        flash("Your account is inactive. Please contact admin.", "danger")
        return redirect(url_for('user.login_page'))
    
    password_valid = verify_pin(password, password_salt, password_hash)
    print(f"[DEBUG] Password verification result: {password_valid}")

    if not password_valid:
        record_login_attempt('user', identifier, False, ip_address)
        notify_failed_login_attempt('user', user_id, name)
        log_suspicious_activity('failed_password_verification', {
            'user_id': user_id,
            'ip': ip_address
        })
        if is_account_locked('user', identifier):
            notify_account_locked('user', user_id, name)
            try:
                send_account_locked_email(email, name)
            except Exception as e:
                log_suspicious_activity('email_send_error', {
                    'type': 'account_locked',
                    'user_id': user_id,
                    'error': str(e)
                })
            flash("Account locked due to multiple failed attempts.", "danger")
        else:
            flash("Invalid username/email or password.", "danger")
        return redirect(url_for('user.login_page'))
    
    # Check force password change first
    if check_force_password_change(user_id):
        regenerate_session()
        session.update({
            'user_id': user_id,
            'username': username,
            'user_email': email,
            'name': name,
            'force_password_change': True
        })
        session.permanent = True
        record_login_attempt('user', identifier, True, ip_address)
        clear_login_attempts('user', identifier)
        notify_successful_login('user', user_id, name)

        flash("Welcome! For security reasons, please change your password.", "warning")
        return redirect(url_for('user.dashboard'))

    # Check device trust
    device_token = request.cookies.get('user_device_token')
    is_device_trusted = False
    if device_token:
        device_token = sanitize_input(device_token, 256)
        try:
            is_device_trusted = is_trusted_device(
                'user',
                user_id,
                device_token,
                ip_address=ip_address,
                user_agent=user_agent
            )
            print(f"[DEBUG] Trusted device check: {is_device_trusted}")
        except Exception as e:
            print(f"❌ Error checking trusted device: {e}")
            log_suspicious_activity('trusted_device_check_error', {
                'user_id': user_id,
                'error': str(e)
            })
    
    # ✅ CRITICAL FIX: Check system settings for 2FA requirement
    from core.settings_manager import SystemSettings
    require_2fa = SystemSettings.is_2fa_required()

    # If trusted device, bypass 2FA
    if is_device_trusted:
        print(f"[DEBUG] Trusted device detected - bypassing 2FA")
        regenerate_session()
        session.update({
            'user_id': user_id,
            'username': username,
            'user_email': email,
            'name': name
        })
        session.permanent = True

        record_login_attempt('user', identifier, True, ip_address)
        clear_login_attempts('user', identifier)
        notify_successful_login('user', user_id, name)

        flash(f"Welcome back, {name}! (Trusted device)", "success")
        return redirect(url_for('user.dashboard'))

    # 2FA required AND SMTP configured
    if require_2fa and is_smtp_configured():
        print(f"[DEBUG] 2FA is required - sending code")
        
        code = create_verification_code('user', user_id, email, 'login')
        if not send_login_verification_email(email, name, code):
            log_suspicious_activity('2fa_email_send_error', {
                'user_id': user_id,
                'email': email
            })
            flash("Failed to send verification code.", "danger")
            return redirect(url_for('user.login_page'))

        session.update({
            'pending_user_id': user_id,
            'pending_username': username,
            'pending_user_email': email,
            'pending_name': name
        })
        record_login_attempt('user', identifier, True, ip_address)
        clear_login_attempts('user', identifier)

        flash("Verification code sent to your email.", "info")
        return redirect(url_for('user.verify_2fa_page'))

    # 2FA required but SMTP not configured - allow with warning
    elif require_2fa and not is_smtp_configured():
        print(f"[WARNING] 2FA required but SMTP not configured - allowing login with warning")
        
        regenerate_session()
        session.update({
            'user_id': user_id,
            'username': username,
            'user_email': email,
            'name': name
        })
        session.permanent = True

        record_login_attempt('user', identifier, True, ip_address)
        clear_login_attempts('user', identifier)
        notify_successful_login('user', user_id, name)

        flash(f"Welcome back, {name}! ⚠️ Warning: 2FA is required but email is not configured.", "warning")
        return redirect(url_for('user.dashboard'))

    # 2FA not required - direct login
    else:
        print(f"[DEBUG] 2FA not required - direct login")
        
        regenerate_session()
        session.update({
            'user_id': user_id,
            'username': username,
            'user_email': email,
            'name': name
        })
        session.permanent = True

        record_login_attempt('user', identifier, True, ip_address)
        clear_login_attempts('user', identifier)
        notify_successful_login('user', user_id, name)

        flash(f"Welcome back, {name}!", "success")
        return redirect(url_for('user.dashboard'))

@user_bp.route('/verify-2fa')
def verify_2fa_page():
    """User 2FA verification page"""
    if 'pending_user_id' not in session:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('user.login_page'))

    response = make_response(
        render_template('user_verify_2fa.html', 
                       email=session.get('pending_user_email', ''))
    )
    response = add_no_cache_headers(response)
    return response

@user_bp.route('/verify-2fa', methods=['POST'])
@csrf_protect
def verify_2fa():
    """Verify user 2FA code and optionally remember device as trusted"""
    if 'pending_user_id' not in session:
        log_suspicious_activity('2fa_no_pending_session', {'ip': get_client_ip()})
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('user.login_page'))

    code = sanitize_input(request.form.get('code', ''), 10)
    remember_device = request.form.get('remember_device') == 'on'
    user_id = session['pending_user_id']
    username = session.get('pending_username')
    email = session.get('pending_user_email')
    name = session.get('pending_name')

    print(f"[DEBUG] Verify 2FA - Remember device: {remember_device}")
    print(f"[DEBUG] Verify 2FA - User ID: {user_id}")

    if not code or not re.match(r'^\d{6}$', code):
        log_suspicious_activity('invalid_2fa_code_format', {
            'user_id': user_id,
            'ip': get_client_ip()
        })
        flash("Invalid verification code format.", "danger")
        return redirect(url_for('user.verify_2fa_page'))

    if verify_code('user', user_id, code, 'login'):
        pending_data = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'name': name
        }
        session.pop('pending_user_id', None)
        session.pop('pending_username', None)
        session.pop('pending_user_email', None)
        session.pop('pending_name', None)
        regenerate_session()
        session['user_id'] = pending_data['user_id']
        session['username'] = pending_data['username']
        session['user_email'] = pending_data['email']
        session['name'] = pending_data['name']
        session.permanent = True

        record_login_attempt('user', email or username, True, get_client_ip())
        clear_login_attempts('user', email or username)
        notify_successful_login('user', pending_data['user_id'], pending_data['name'])
        resp = make_response(redirect(url_for('user.dashboard')))
        if remember_device:
            try:
                device_token = add_trusted_device(
                    'user',
                    pending_data['user_id'],
                    get_client_ip(),
                    request.headers.get('User-Agent', '')[:500],
                    days=30
                )
                
                print(f"[DEBUG] Setting trusted device cookie with token: {device_token[:10]}...")
                
                
                resp.set_cookie(
                    'user_device_token',
                    device_token,
                    max_age=30 * 24 * 60 * 60,  
                    path='/',  
                    httponly=True,
                    secure=request.is_secure,
                    samesite='Lax'
                )
                flash(f"Welcome back, {pending_data['name']}! This device will be remembered for 30 days.", "success")
            except Exception as e:
                log_suspicious_activity('trusted_device_add_error', {
                    'user_id': pending_data['user_id'],
                    'error': str(e)
                })
                print(f"Error adding trusted device: {str(e)}")
                flash(f"Welcome back, {pending_data['name']}! (Could not remember device.)", "warning")
        else:
            flash(f"Welcome back, {pending_data['name']}!", "success")
        return resp
    else:
        log_suspicious_activity('invalid_2fa_code', {
            'user_id': user_id,
            'ip': get_client_ip()
        })
        flash("Invalid or expired verification code. Please try again.", "danger")
        return redirect(url_for('user.verify_2fa_page'))

@user_bp.route('/resend-code', methods=['POST'])
def resend_code():
    """Resend user 2FA verification code"""
    if 'pending_user_id' not in session:
        return jsonify({"status": "error", "message": "Session expired"}), 400

    from flask_wtf.csrf import validate_csrf
    from werkzeug.exceptions import BadRequest
    try:
        csrf_token = request.headers.get('X-CSRFToken')
        if not csrf_token:
            return jsonify({"status": "error", "message": "CSRF token missing"}), 403
        validate_csrf(csrf_token)
    except (BadRequest, Exception) as e:
        return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403

    user_id = session['pending_user_id']
    name = session.get('pending_name')
    email = session.get('pending_user_email')
    code = create_verification_code('user', user_id, email, 'login')
    try:
        if send_login_verification_email(email, name, code):
            return jsonify({"status": "success", "message": "Code resent to your email"})
        else:
            log_suspicious_activity('2fa_resend_error', {'user_id': user_id})
            return jsonify({"status": "error", "message": "Failed to send code"}), 500
    except Exception as e:
        log_suspicious_activity('2fa_resend_exception', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to send code"}), 500

@user_bp.route('/signup')
def signup_page():
    """User signup page"""
    smtp_configured = is_smtp_configured()
    response = make_response(
        render_template('user_signup.html', smtp_configured=smtp_configured)
    )
    response = add_no_cache_headers(response)
    return response

@user_bp.route('/signup', methods=['POST'])
@csrf_protect
def signup():
    """User signup endpoint with comprehensive validation"""
    username = sanitize_input(request.form.get('username', ''), MAX_USERNAME_LENGTH)
    email = sanitize_input(request.form.get('email', ''), MAX_EMAIL_LENGTH)
    name = sanitize_input(request.form.get('name', ''), MAX_NAME_LENGTH)
    role = sanitize_input(request.form.get('role', 'Student'), 50)
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    valid, error = validate_user_registration(
        username=username,
        email=email,
        name=name,
        password=password,
        role=role
    )
    
    if not valid:
        log_suspicious_activity('invalid_signup_data', {
            'error': error,
            'username': username,
            'email': email,
            'ip': get_client_ip()
        })
        flash(error, "danger")
        return redirect(url_for('user.signup_page'))
    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('user.signup_page'))
    try:
        user_id, qr_token, qr_filename, generated_pin = add_user_account_with_email(username, email, name, role, password)
        try:
            send_welcome_email(email, name, username)
        except Exception as e:
            log_suspicious_activity('welcome_email_error', {
                'user_id': user_id,
                'error': str(e)
            })
        notify_new_user_registered(name, role)
        regenerate_session()
        session['user_id'] = user_id
        session['username'] = username
        session['user_email'] = email
        session['name'] = name
        session.permanent = True
        notify_successful_login('user', user_id, name)
        flash(f"Account created successfully! Welcome, {name}! Your QR PIN is: {generated_pin}", "success")
        return redirect(url_for('user.dashboard'))
    except ValueError as ve:
        log_suspicious_activity('signup_duplicate_entry', {
            'error': str(ve),
            'username': username,
            'email': email
        })
        flash(str(ve), "danger")
        return redirect(url_for('user.signup_page'))
    except Exception as e:
        log_suspicious_activity('signup_error', {
            'error': str(e),
            'username': username,
            'email': email
        })
        flash("Error creating account. Please try again.", "danger")
        return redirect(url_for('user.signup_page'))

@user_bp.route('/dashboard')
@user_login_required
def dashboard():
    """User dashboard - SECURED with @user_login_required"""
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        flash("User not found. Please login again.", "danger")
        return redirect(url_for('user.login_page'))
    user = list(user)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT pin FROM users WHERE user_id = ?", (user_id,))
        pin_row = cur.fetchone()
        pin = pin_row[0] if pin_row else 'N/A'
    finally:
        conn.close()
    user.append(pin)
    show_password_warning = check_force_password_change(user_id)
    try:
        devices = get_user_trusted_devices('user', user_id)
    except Exception as e:
        log_suspicious_activity('get_trusted_devices_error', {
            'user_id': user_id,
            'error': str(e)
        })
        devices = []
    notifications = get_user_notifications('user', user_id, limit=5)
    unread_count = get_unread_count('user', user_id)
    attendance = get_user_attendance(user_id, limit=50)
    return render_template(
        'user.html',
        user=user,
        attendance=attendance,
        notifications=notifications,
        unread_count=unread_count,
        devices=devices,
        show_password_warning=show_password_warning
    )

@user_bp.route('/notifications')
@user_login_required
def get_notifications():
    """Get user notifications (AJAX endpoint)"""
    user_id = session['user_id']
    try:
        notifications = get_user_notifications('user', user_id, limit=20)
        unread_count = get_unread_count('user', user_id)

        return jsonify({
            "status": "success",
            "notifications": [
                {
                    "id": n[0],
                    "title": n[1],
                    "message": n[2],
                    "type": n[3],
                    "read": n[4],
                    "created_at": n[5]
                } for n in notifications
            ],
            "unread_count": unread_count
        })
    except Exception as e:
        log_suspicious_activity('get_notifications_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve notifications"}), 500

@user_bp.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
@csrf_protect
@user_login_required
def mark_notification_read_route(notification_id):
    """Mark notification as read"""
    if notification_id <= 0:
        return jsonify({"status": "error", "message": "Invalid notification ID"}), 400

    try:
        mark_notification_read(notification_id)
        return jsonify({"status": "success"})
    except Exception as e:
        log_suspicious_activity('mark_notification_error', {
            'user_id': session['user_id'],
            'notification_id': notification_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to mark notification"}), 500

@user_bp.route('/notifications/mark-all-read', methods=['POST'])
@csrf_protect
@user_login_required
def mark_all_notifications_read():
    """Mark all notifications as read"""
    user_id = session['user_id']
    try:
        mark_all_read('user', user_id)
        return jsonify({"status": "success"})
    except Exception as e:
        log_suspicious_activity('mark_all_notifications_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to mark all notifications"}), 500

@user_bp.route('/attendance', methods=['GET'])
@user_login_required
def get_attendance():
    """Get user attendance with pagination and filters"""
    try:
        user_id = session['user_id']

        try:
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(200, max(10, int(request.args.get('per_page', 10))))
        except (ValueError, TypeError):
            page = 1
            per_page = 10

        date_from = sanitize_input(request.args.get('date_from', ''), 10)
        date_to = sanitize_input(request.args.get('date_to', ''), 10)
        action_filter = sanitize_input(request.args.get('action', ''), 10)
        if date_from and not re.match(r'^\d{4}-\d{2}-\d{2}$', date_from):
            return jsonify({"status": "error", "message": "Invalid date_from format"}), 400
        
        if date_to and not re.match(r'^\d{4}-\d{2}-\d{2}$', date_to):
            return jsonify({"status": "error", "message": "Invalid date_to format"}), 400

        if action_filter and action_filter not in ['IN', 'OUT']:
            return jsonify({"status": "error", "message": "Invalid action filter"}), 400

        conn = get_conn()
        cur = conn.cursor()

        query = """
            SELECT log_id, action, timestamp, location
            FROM access_logs
            WHERE user_id = ?
        """
        params = [user_id]

        if date_from:
            query += " AND DATE(timestamp) >= ?"
            params.append(date_from)

        if date_to:
            query += " AND DATE(timestamp) <= ?"
            params.append(date_to)

        if action_filter:
            query += " AND action = ?"
            params.append(action_filter)

        count_query = f"SELECT COUNT(*) FROM ({query})"
        cur.execute(count_query, params)
        total_records = cur.fetchone()[0]
        total_pages = (total_records + per_page - 1) // per_page

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])

        cur.execute(query, params)
        records = cur.fetchall()
        conn.close()

        records_list = [
            {
                'log_id': r[0],
                'action': r[1],
                'timestamp': utc_to_ph_time(r[2]),
                'location': r[3] or 'Gate'
            }
            for r in records
        ]

        return jsonify({
            "status": "success",
            "records": records_list,
            "total_records": total_records,
            "total_pages": total_pages,
            "current_page": page
        })

    except Exception as e:
        log_suspicious_activity('get_attendance_error', {
            'user_id': session.get('user_id'),
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve attendance"}), 500

@user_bp.route('/profile', methods=['GET', 'POST'])
@user_login_required
def profile():
    """User profile page - allows username, name, and PASSWORD changes"""
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        session.clear()
        flash("User not found. Please login again.", "danger")
        return redirect(url_for('user.login_page'))
    if request.method == 'POST':
        try:
            
            username = sanitize_input(request.form.get('username', ''), MAX_USERNAME_LENGTH)
            name = sanitize_input(request.form.get('name', ''), MAX_NAME_LENGTH)
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            print(f"[DEBUG] Profile update - user_id: {user_id}, username: {username}")

            valid, error = validate_username(username)
            if not valid:
                flash(error, "danger")
                return redirect(url_for('user.profile'))
            valid, error = validate_name(name)
            if not valid:
                flash(error, "danger")
                return redirect(url_for('user.profile'))

            if new_password or confirm_password:
                if not new_password or not confirm_password:
                    flash("Please fill both password fields to change password.", "danger")
                    return redirect(url_for('user.profile'))
                
                if new_password != confirm_password:
                    flash("Passwords do not match.", "danger")
                    return redirect(url_for('user.profile'))

                valid, error = validate_password(new_password)
                if not valid:
                    flash(error, "danger")
                    return redirect(url_for('user.profile'))

            if new_password:
                print(f"[DEBUG] Updating profile WITH password change")
                update_user_profile(user_id, username, name, new_password)
                
                notify_password_changed('user', user_id)
                
                user_email = get_user_email(user_id)
                if user_email:
                    try:
                        send_password_changed_notification_email(user_email, name)
                    except Exception as e:
                        log_suspicious_activity('password_change_email_error', {
                            'user_id': user_id,
                            'error': str(e)
                        })  
                flash("Profile and password updated successfully!", "success")
            else:
                print(f"[DEBUG] Updating profile WITHOUT password change")
                update_user_profile(user_id, username, name, None)
                flash("Profile updated successfully!", "success")
            session['username'] = username
            session['name'] = name 
            if 'force_password_change' in session:
                session.pop('force_password_change', None)
            return redirect(url_for('user.dashboard'))
        except ValueError as ve:
            print(f"[ERROR] Profile update validation error: {str(ve)}")
            log_suspicious_activity('profile_update_validation_error', {
                'user_id': user_id,
                'error': str(ve)
            })
            flash(str(ve), "danger")
            return redirect(url_for('user.profile'))
        except Exception as e:
            print(f"[ERROR] Profile update exception: {str(e)}")
            import traceback
            traceback.print_exc()
            log_suspicious_activity('profile_update_error', {
                'user_id': user_id,
                'error': str(e)
            })
            flash("Error updating profile. Please try again.", "danger")
            return redirect(url_for('user.profile'))

    return render_template('user.html', user=user)

@user_bp.route('/remove-device/<int:device_id>', methods=['POST'])
@csrf_protect
@user_login_required
def remove_device(device_id):
    """Remove a trusted device"""
    if device_id <= 0:
        return jsonify({"status": "error", "message": "Invalid device ID"}), 400

    try:
        remove_trusted_device(device_id)
        flash("Device removed successfully.", "success")
    except Exception as e:
        log_suspicious_activity('remove_trusted_device_error', {
            'user_id': session['user_id'],
            'device_id': device_id,
            'error': str(e)
        })
        flash("Failed to remove device. Please try again.", "danger")
    
    return redirect(url_for('user.dashboard'))

@user_bp.route('/logout', methods=['GET', 'POST'])  # Allow both GET and POST
def logout():
    """
    User logout - POST preferred with CSRF, GET as fallback
    """
    # If GET request, show confirmation or redirect
    if request.method == 'GET':
        # Check if user is logged in
        if 'user_id' not in session:
            flash("You are not logged in.", "info")
            return redirect(url_for('user.login_page'))
        
        # For GET requests, just do the logout without CSRF check
        # (less secure but prevents the 400 error)
        user_id, username = logout_session('user')
        response = create_logout_response(url_for('user.login_page'), 'user')
        flash("Logged out successfully. Your session has been terminated.", "info")
        return response
    
    # POST request - validate CSRF
    try:
        from flask_wtf.csrf import validate_csrf
        csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        if csrf_token:
            validate_csrf(csrf_token)
    except Exception as e:
        # If CSRF validation fails, still log out but show warning
        print(f"CSRF validation failed during logout: {e}")
        user_id, username = logout_session('user')
        response = create_logout_response(url_for('user.login_page'), 'user')
        flash("Logged out successfully.", "info")
        return response
    
    # Normal POST logout with valid CSRF
    user_id, username = logout_session('user')
    response = create_logout_response(url_for('user.login_page'), 'user')
    flash("Logged out successfully. Your session has been terminated.", "info")
    return response

@user_bp.route('/daily-stats', methods=['GET'])
@user_login_required
def get_daily_stats():
    """Get user's daily scan statistics"""
    user_id = session['user_id']
    try:
        stats = get_user_daily_scan_count(user_id)
        return jsonify({
            "status": "success",
            "stats": stats
        })
    except Exception as e:
        log_suspicious_activity('get_daily_stats_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve statistics"}), 500

@user_bp.route('/current-status', methods=['GET'])
@user_login_required
def get_current_status():
    """Get user's current location status"""
    user_id = session['user_id']
    try:
        status = get_user_current_status(user_id)
        return jsonify({
            "status": "success",
            "user_status": status
        })
    except Exception as e:
        log_suspicious_activity('get_current_status_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve status"}), 500
    
@user_bp.route('/activity-heatmap', methods=['GET'])
@user_login_required
def get_activity_heatmap():
    """Get user's activity heatmap data for the last 365 days (1 year)"""
    user_id = session['user_id']
    try:
        from core.database import get_user_activity_heatmap
        
        activity_data = get_user_activity_heatmap(user_id, days=365)  
        
        return jsonify({
            "status": "success",
            "activity": activity_data
        })
    except Exception as e:
        log_suspicious_activity('get_activity_heatmap_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve activity data"}), 500
    
@user_bp.route('/recent-activity', methods=['GET'])
@user_login_required
def get_recent_activity():
    """Get user's most recent IN and OUT activity"""
    user_id = session['user_id']
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # Get most recent IN
        cur.execute("""
            SELECT action, timestamp, location
            FROM access_logs
            WHERE user_id = ? AND action = 'IN'
            ORDER BY timestamp DESC
            LIMIT 1
        """, (user_id,))
        recent_in = cur.fetchone()
        
        # Get most recent OUT
        cur.execute("""
            SELECT action, timestamp, location
            FROM access_logs
            WHERE user_id = ? AND action = 'OUT'
            ORDER BY timestamp DESC
            LIMIT 1
        """, (user_id,))
        recent_out = cur.fetchone()
        
        conn.close()
        
        result = {
            'in': {
                'timestamp': utc_to_ph_time(recent_in[1]) if recent_in else None,
                'location': recent_in[2] if recent_in else None
            } if recent_in else None,
            'out': {
                'timestamp': utc_to_ph_time(recent_out[1]) if recent_out else None,
                'location': recent_out[2] if recent_out else None
            } if recent_out else None
        }
        
        return jsonify({
            "status": "success",
            "activity": result
        })
    except Exception as e:
        log_suspicious_activity('get_recent_activity_error', {
            'user_id': user_id,
            'error': str(e)
        })
        return jsonify({"status": "error", "message": "Failed to retrieve recent activity"}), 500