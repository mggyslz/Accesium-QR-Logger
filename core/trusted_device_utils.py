# core/trusted_device_utils.py
import secrets
from datetime import datetime, timedelta
from typing import Optional
from core.database import get_conn


def generate_device_token() -> str:
    """Generate a secure random token for device identification"""
    return secrets.token_urlsafe(32)

def get_device_name(user_agent: str) -> str:
    """Extract a friendly device name from user agent"""
    ua_lower = user_agent.lower()
    
    # Browser detection
    if 'chrome' in ua_lower and 'edg' not in ua_lower:
        browser = 'Chrome'
    elif 'firefox' in ua_lower:
        browser = 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        browser = 'Safari'
    elif 'edg' in ua_lower:
        browser = 'Edge'
    else:
        browser = 'Browser'
    # OS detection
    if 'windows' in ua_lower:
        os = 'Windows'
    elif 'mac' in ua_lower:
        os = 'macOS'
    elif 'linux' in ua_lower:
        os = 'Linux'
    elif 'android' in ua_lower:
        os = 'Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        os = 'iOS'
    else:
        os = 'Device'
    
    return f"{browser} on {os}"

def add_trusted_device(
    user_type: str,
    user_id: int,
    ip_address: str,
    user_agent: str,
    days: int = 30
) -> str:
    """Add a trusted device and return the device token"""
    device_token = generate_device_token()
    device_name = get_device_name(user_agent)
    expires_at = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trusted_devices 
            (user_type, user_id, device_token, device_name, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_type, user_id, device_token, device_name, ip_address, user_agent, expires_at))
        conn.commit()
        print(f"✅ Trusted device added: {device_name} for user {user_id}")
    finally:
        conn.close()
    
    return device_token

def is_trusted_device(
    user_type: str,
    user_id: int,
    device_token: Optional[str],
    ip_address: str = None,
    user_agent: str = None
) -> bool:
    """Check if a device token is valid and trusted"""
    if not device_token:
        return False
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT device_id, expires_at FROM trusted_devices
            WHERE user_type = ? AND user_id = ? AND device_token = ?
        """, (user_type, user_id, device_token))
        row = cur.fetchone()
        
        if not row:
            return False
        
        device_id, expires_at = row 
        # Check if expired
        if datetime.now() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
            print(f"Trusted device expired: {device_id}")
            # Delete expired device
            cur.execute("DELETE FROM trusted_devices WHERE device_id = ?", (device_id,))
            conn.commit()
            return False
        
        # Update last used timestamp and optionally IP/user_agent
        update_fields = ["last_used = CURRENT_TIMESTAMP"]
        params = []
        
        if ip_address:
            update_fields.append("ip_address = ?")
            params.append(ip_address)
        
        if user_agent:
            update_fields.append("user_agent = ?") 
            params.append(user_agent)
        
        params.append(device_id)
        
        update_query = f"""
            UPDATE trusted_devices 
            SET {', '.join(update_fields)} 
            WHERE device_id = ?
        """
        
        cur.execute(update_query, params)
        conn.commit()
        
        print(f"Trusted device verified: {device_id}")
        return True
    finally:
        conn.close()

def get_user_trusted_devices(user_type: str, user_id: int):
    """Get all trusted devices for a user"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT device_id, device_name, ip_address, created_at, last_used, expires_at
            FROM trusted_devices
            WHERE user_type = ? AND user_id = ?
            ORDER BY last_used DESC
        """, (user_type, user_id))
        return cur.fetchall()
    finally:
        conn.close()


def remove_trusted_device(device_id: int):
    """Remove a trusted device"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM trusted_devices WHERE device_id = ?", (device_id,))
        conn.commit()
    finally:
        conn.close()


def remove_all_trusted_devices(user_type: str, user_id: int):
    """Remove all trusted devices for a user"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM trusted_devices 
            WHERE user_type = ? AND user_id = ?
        """, (user_type, user_id))
        conn.commit()
    finally:
        conn.close()


def clean_expired_devices():
    """Remove all expired trusted devices"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM trusted_devices WHERE expires_at < datetime('now')")
        deleted_count = cur.rowcount
        conn.commit()
        if deleted_count > 0:
            print(f"🗑️ Cleaned up {deleted_count} expired trusted devices")
    finally:
        conn.close()