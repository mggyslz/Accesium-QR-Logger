import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional
from core.database import get_conn
import os

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '').strip()
SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', SMTP_USER)
SMTP_FROM_NAME = os.getenv('SMTP_FROM_NAME', 'QR Access Logger')


def is_smtp_configured() -> bool:
    """Check if SMTP is properly configured"""
    return bool(SMTP_USER and SMTP_PASSWORD and SMTP_HOST)


def generate_verification_code(length: int = 6) -> str:
    """Generate a random verification code"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def send_email(to_email: str, subject: str, body: str, html: bool = True) -> bool:
    """Send an email using configured SMTP settings"""
    if not is_smtp_configured():
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        if html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        return True
        
    except Exception:
        return False


def create_verification_code(user_type: str, user_id: int, email: str, purpose: str = 'login') -> str:
    """Create and store a verification code in database"""
    code = generate_verification_code()
    expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO verification_codes (user_type, user_id, email, code, purpose, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_type, user_id, email, code, purpose, expires_at))
        conn.commit()
    finally:
        conn.close()
    
    return code


def verify_code(user_type: str, user_id: int, code: str, purpose: str = 'login') -> bool:
    """Verify a code and mark it as used if valid"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT code_id, expires_at FROM verification_codes
            WHERE user_type = ? AND user_id = ? AND code = ? AND purpose = ? AND used = 0
            ORDER BY created_at DESC LIMIT 1
        """, (user_type, user_id, code, purpose))
        row = cur.fetchone()
        
        if not row:
            return False
        
        code_id, expires_at = row
        
        if datetime.now() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
            return False
        
        cur.execute("UPDATE verification_codes SET used = 1 WHERE code_id = ?", (code_id,))
        conn.commit()
        return True
    finally:
        conn.close()


def send_login_verification_email(email: str, name: str, code: str) -> bool:
    """Send 2FA login verification email"""
    subject = "Your Login Verification Code"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #2c2c2c; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 8px; margin: 20px 0; }}
            .code-box {{ background: white; padding: 20px; text-align: center; font-size: 32px; 
                        font-weight: bold; letter-spacing: 8px; border: 2px dashed #2c2c2c; 
                        border-radius: 8px; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; padding: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>QR Access Logger</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>You're attempting to log in to your account. Use the verification code below:</p>
                <div class="code-box">{code}</div>
                <p><strong>This code will expire in 10 minutes.</strong></p>
                <p>If you didn't request this code, please ignore this email.</p>
            </div>
            <div class="footer">
                <p>QR Access Logger System - Automated Message</p>
                <p>Do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body, html=True)


def send_welcome_email(email: str, name: str, username: str) -> bool:
    """Send welcome email after successful registration"""
    subject = "Welcome to QR Access Logger"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #2c2c2c; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 8px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome!</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>Your account has been successfully created!</p>
                <p><strong>Username:</strong> {username}</p>
                <p>You can now log in and access your QR code for attendance tracking.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body, html=True)


def send_account_locked_email(email: str, name: str) -> bool:
    """Send email notification when account is locked"""
    subject = "Account Security Alert - QR Access Logger"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #e74c3c; color: white; padding: 20px; text-align: center; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 8px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Alert</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>Your account has been temporarily locked due to multiple failed login attempts.</p>
                <p><strong>What to do:</strong></p>
                <ul>
                    <li>Wait 15 minutes before trying again</li>
                    <li>Or contact your system administrator</li>
                </ul>
                <p>If this wasn't you, please contact support immediately.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body, html=True)


def generate_temporary_password(length: int = 12) -> str:
    """Generate a secure temporary password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()")
    ]
    password.extend(secrets.choice(characters) for _ in range(length - 4))
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def send_new_user_credentials_email(email: str, name: str, username: str, password: str, pin: str, login_url: str) -> bool:
    """Send email with credentials to newly created user"""
    subject = "Your Account Has Been Created"
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #2c2c2c; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
            .credentials {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #2c2c2c; }}
            .credential-item {{ margin: 12px 0; }}
            .credential-label {{ font-weight: 600; color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
            .credential-value {{ font-size: 16px; font-family: 'Courier New', monospace; background: #f5f5f5; padding: 8px 12px; border-radius: 4px; display: inline-block; margin-top: 4px; }}
            .pin-highlight {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 16px; margin: 20px 0; border-radius: 4px; }}
            .button {{ display: inline-block; background: #2c2c2c; color: white; padding: 14px 28px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }}
            .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
            .info-box {{ background: #e7f3ff; border-left: 4px solid #2196F3; padding: 16px; margin: 20px 0; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="margin: 0; font-size: 24px;">Welcome to QR Access Logger</h1>
            </div>
            <div class="content">
                <p style="font-size: 16px;">Hello <strong>{name}</strong>,</p>
                <p>Your account has been created by an administrator. Below are your login credentials:</p>
                
                <div class="credentials">
                    <div class="credential-item">
                        <div class="credential-label">Username</div>
                        <div class="credential-value">{username}</div>
                    </div>
                    <div class="credential-item">
                        <div class="credential-label">Web Password</div>
                        <div class="credential-value">{password}</div>
                    </div>
                </div>
                
                <div class="pin-highlight">
                    <strong>QR Scanner PIN</strong><br>
                    <p style="margin: 10px 0;">When scanning your QR code, use this 6-digit PIN:</p>
                    <div style="text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; font-family: 'Courier New', monospace; color: #2c2c2c;">
                        {pin}
                    </div>
                </div>
                
                <div class="info-box">
                    <strong>Security Recommendation:</strong><br>
                    You can change your web password after logging in for better security. Your QR PIN cannot be changed.
                </div>
                
                <div style="text-align: center;">
                    <a href="{login_url}" class="button">Login to Your Account</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from QR Access Logger System</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, html_body, html=True)


def send_password_changed_notification_email(email: str, name: str) -> bool:
    """Send notification after user changes password"""
    subject = "Password Successfully Changed - QR Access Logger"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #27ae60; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
            .success-icon {{ font-size: 48px; text-align: center; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; padding: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✓ Password Changed Successfully</h1>
            </div>
            <div class="content">
                <div class="success-icon"></div>
                <h2>Hello {name},</h2>
                <p>Your password has been successfully changed.</p>
                <p style="margin-top: 30px; padding: 15px; background: #e7f0fa; border-left: 4px solid #2c5d8f; border-radius: 4px;">
                    <strong> Note:</strong> If you did not make this change, please contact your system administrator immediately.
                </p>
            </div>
            <div class="footer">
                <p>QR Access Logger System - Automated Message</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body, html=True)

def send_password_changed_notification_email(email: str, name: str) -> bool:
    """Send notification after user changes password"""
    subject = "Password Successfully Changed - QR Access Logger"
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #27ae60; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
            .success-icon {{ font-size: 48px; text-align: center; margin: 20px 0; }}
            .footer {{ text-align: center; color: #666; font-size: 12px; padding: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✓ Password Changed Successfully</h1>
            </div>
            <div class="content">
                <div class="success-icon"></div>
                <h2>Hello {name},</h2>
                <p>Your password has been successfully changed.</p>
                <p style="margin-top: 30px; padding: 15px; background: #e7f0fa; border-left: 4px solid #2c5d8f; border-radius: 4px;">
                    <strong>⚠ Note:</strong> If you did not make this change, please contact your system administrator immediately.
                </p>
            </div>
            <div class="footer">
                <p>QR Access Logger System - Automated Message</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body, html=True)


def send_password_reset_by_admin_email(email: str, name: str, temporary_password: str, login_url: str) -> bool:
    """Send email with new temporary password after admin reset"""
    subject = "Your Password Has Been Reset - QR Access Logger"
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #dc3545; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
            .password-box {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #dc3545; }}
            .password-value {{ font-size: 20px; font-family: 'Courier New', monospace; background: #f5f5f5; padding: 12px; border-radius: 4px; display: inline-block; margin-top: 8px; letter-spacing: 2px; font-weight: bold; color: #dc3545; }}
            .warning-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 16px; margin: 20px 0; border-radius: 4px; }}
            .button {{ display: inline-block; background: #dc3545; color: white; padding: 14px 28px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }}
            .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
            .info-list {{ background: #e7f3ff; border-left: 4px solid #2196F3; padding: 16px; margin: 20px 0; border-radius: 4px; }}
            .info-list ul {{ margin: 10px 0; padding-left: 20px; }}
            .info-list li {{ margin: 8px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="margin: 0; font-size: 24px;">Password Reset</h1>
            </div>
            <div class="content">
                <p style="font-size: 16px;">Hello <strong>{name}</strong>,</p>
                <p>Your password has been reset by a system administrator.</p>
                
                <div class="warning-box">
                    <strong>Security Notice</strong><br>
                    <p style="margin: 8px 0 0 0;">If you did not request this password reset, please contact your administrator immediately.</p>
                </div>
                
                <div class="password-box">
                    <strong style="font-size: 14px; color: #666;">Your New Temporary Password</strong><br>
                    <div class="password-value">{temporary_password}</div>
                </div>
                
                <div class="info-list">
                    <strong>What You Need to Do:</strong>
                    <ul>
                        <li>Log in using the temporary password above</li>
                        <li>You will be <strong>required to change your password</strong> immediately upon login</li>
                        <li>Choose a strong, unique password that you haven't used before</li>
                        <li>Keep your new password secure and do not share it with anyone</li>
                    </ul>
                </div>
                
                <div style="text-align: center;">
                    <a href="{login_url}" class="button">Login Now</a>
                </div>
                
                <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 4px; font-size: 13px; color: #666;">
                    <strong>Need Help?</strong><br>
                    If you're having trouble logging in or changing your password, please contact your system administrator for assistance.
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from QR Access Logger System</p>
                <p style="margin-top: 8px;">For security reasons, do not reply to this email</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, html_body, html=True)

def send_new_admin_credentials_email(email: str, name: str, username: str, password: str, login_url: str) -> bool:
    """Send email with credentials to newly created admin"""
    subject = "Admin Account Created - QR Access Logger"
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #2c2c2c; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
            .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
            .credentials {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #2c2c2c; }}
            .credential-item {{ margin: 12px 0; }}
            .credential-label {{ font-weight: 600; color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
            .credential-value {{ font-size: 16px; font-family: 'Courier New', monospace; background: #f5f5f5; padding: 8px 12px; border-radius: 4px; display: inline-block; margin-top: 4px; }}
            .warning-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 16px; margin: 20px 0; border-radius: 4px; }}
            .button {{ display: inline-block; background: #2c2c2c; color: white; padding: 14px 28px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }}
            .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }}
            .info-box {{ background: #e7f3ff; border-left: 4px solid #2196F3; padding: 16px; margin: 20px 0; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="margin: 0; font-size: 24px;">🔐 Administrator Access Granted</h1>
            </div>
            <div class="content">
                <p style="font-size: 16px;">Hello <strong>{name}</strong>,</p>
                <p>You have been granted administrator access to the QR Access Logger system. Below are your login credentials:</p>
                
                <div class="credentials">
                    <div class="credential-item">
                        <div class="credential-label">Username</div>
                        <div class="credential-value">{username}</div>
                    </div>
                    <div class="credential-item">
                        <div class="credential-label">Temporary Password</div>
                        <div class="credential-value">{password}</div>
                    </div>
                </div>
                
                <div class="warning-box">
                    <strong> Important Security Notice</strong><br>
                    <p style="margin: 8px 0 0 0;">Please change your password immediately after your first login. As an administrator, you have full access to the system.</p>
                </div>
                
                <div class="info-box">
                    <strong>Administrator Privileges Include:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>View and manage all users</li>
                        <li>Access attendance records and analytics</li>
                        <li>Configure system settings</li>
                        <li>Manage access control rules</li>
                        <li>Export system data</li>
                    </ul>
                </div>
                
                <div style="text-align: center;">
                    <a href="{login_url}" class="button">Login to Admin Dashboard</a>
                </div>
                
                <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 4px; font-size: 13px; color: #666;">
                    <strong>Need Help?</strong><br>
                    If you have any questions about your administrator account or need assistance, please contact the system administrator.
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from QR Access Logger System</p>
                <p style="margin-top: 8px; color: #e53e3e;"><strong>Do not share your admin credentials with anyone</strong></p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, html_body, html=True)


def clean_expired_codes():
    """Remove expired verification codes"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM verification_codes WHERE expires_at < datetime('now')")
        conn.commit()
    finally:
        conn.close()