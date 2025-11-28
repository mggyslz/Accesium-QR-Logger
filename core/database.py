
import sqlite3
from pathlib import Path
from typing import Optional, Tuple, List
from config.settings import DB_PATH
from core.security import generate_salt, hash_pin, verify_pin
from core.qr_utils import make_qr_token, generate_qr_image
from datetime import datetime
import pytz

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

PH_TZ = pytz.timezone('Asia/Manila')
UTC_TZ = pytz.utc

def generate_random_pin(length: int = 6) -> str:
    """Generate a random 6-digit PIN for QR scanner"""
    import secrets
    import string
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def get_conn():
    """
    Return a sqlite3 Connection. Caller must close it.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except Exception as e:
        from core.error_utils import log_error
        log_error(e, "Opening database connection")
        raise

def get_utc_now():
    """Get current time in UTC as string."""
    return datetime.now(UTC_TZ).strftime('%Y-%m-%d %H:%M:%S')

def get_ph_now():
    """Get current time in Philippine timezone as string."""
    return datetime.now(PH_TZ).strftime('%Y-%m-%d %H:%M:%S')

def utc_to_ph_time(timestamp_str):
    """Convert UTC timestamp string to Philippine time string in 12-hour format."""
    if not timestamp_str:
        return timestamp_str
    try:
        # Parse the UTC timestamp
        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        dt_utc = UTC_TZ.localize(dt)
        
        # Convert to Philippine time
        dt_ph = dt_utc.astimezone(PH_TZ)
        
        # Format with 12-hour time (e.g., "2025-01-15 02:30:45 PM")
        return dt_ph.strftime('%Y-%m-%d %I:%M:%S %p')
    except Exception as e:
        print(f"Error converting timestamp {timestamp_str}: {e}")
        return timestamp_str

def ph_to_utc_time(timestamp_str):
    """Convert Philippine time string to UTC timestamp string."""
    if not timestamp_str:
        return timestamp_str
    try:
        # Handle both 12-hour and 24-hour input formats
        for fmt in ['%Y-%m-%d %I:%M:%S %p', '%Y-%m-%d %H:%M:%S']:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Could not parse timestamp: {timestamp_str}")
        
        dt_ph = PH_TZ.localize(dt)
        
        # Convert to UTC
        dt_utc = dt_ph.astimezone(UTC_TZ)
        return dt_utc.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Error converting timestamp {timestamp_str}: {e}")
        return timestamp_str
    
PREDEFINED_LOCATIONS = [
    'Main Gate',
    'Reception',
    'Office Area',
    'Classroom',
    'Library',
    'Supply Area',
    'Back Gate'
]

def get_active_location() -> str:
    """Get the currently active location."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = 'active_location'")
        row = cur.fetchone()
    finally:
        conn.close()
    return row[0] if row else 'Main Gate'

def set_active_location(location: str):
    """Set the active location. Must be one of PREDEFINED_LOCATIONS."""
    if location not in PREDEFINED_LOCATIONS:
        raise ValueError(f"Invalid location. Must be one of: {', '.join(PREDEFINED_LOCATIONS)}")
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('active_location', ?)",
            (location,)
        )
        conn.commit()
    finally:
        conn.close()

def add_admin(username: str, password: str):
    """Create or replace an admin account (username unique)."""
    salt = generate_salt()
    phash = hash_pin(password, salt)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO admins (username, pass_hash, pass_salt) VALUES (?, ?, ?)",
            (username, phash, salt)
        )
        conn.commit()
    finally:
        conn.close()

def check_admin_credentials(username: str, password: str) -> bool:
    """Return True if username/password is valid."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT pass_hash, pass_salt FROM admins WHERE username=?", (username,))
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return False
    stored_hash, salt = row
    return verify_pin(password, salt, stored_hash)

def add_user(name: str, role: str, pin: str) -> Tuple[str, str]:
    base_username = name.lower().replace(' ', '_').replace('.', '_').replace('-', '_')
    username = base_username
    counter = 1
    conn = get_conn()
    try:
        cur = conn.cursor()
        while True:
            cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cur.fetchone()[0] == 0:
                break
            username = f"{base_username}{counter}"
            counter += 1
    finally:
        conn.close()
    user_id, qr_token, qr_filename = add_user_account(username, name, role, pin)
    return qr_token, qr_filename

def list_users(limit: int = 100) -> List[Tuple]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, name, role, status, created_at FROM users "
            "ORDER BY user_id DESC LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    return rows

def get_all_users() -> List[Tuple]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, username, name, role, email, status, qr_code, qr_token "
            "FROM users ORDER BY user_id DESC"
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    return rows

def get_user_by_qr(qr_token: str) -> Optional[Tuple]:

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, name, role, pin, status FROM users WHERE qr_token = ?",
            (qr_token,)
        )
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def get_user_by_id(user_id: int) -> Optional[Tuple]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, username, name, role, qr_code, qr_token, status "
            "FROM users WHERE user_id = ?", 
            (user_id,)
        )
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def set_user_pin(user_id: int, pin_hash: str, pin_salt: str):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET pin_hash = ?, pin_salt = ? WHERE user_id = ?", (pin_hash, pin_salt, user_id))
        conn.commit()
    finally:
        conn.close()

def get_hourly_counts():
    conn = get_conn()
    try:
        cur = conn.cursor()
        
        today_ph = datetime.now(PH_TZ).date()
        
        cur.execute("""
            SELECT timestamp, action
            FROM access_logs
            ORDER BY timestamp DESC
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    
    hourly_data = {}
    for ts_str, action in rows:
        ts_ph = utc_to_ph_time(ts_str)
        
        # Parse 12-hour format with AM/PM
        try:
            dt_ph = datetime.strptime(ts_ph, '%Y-%m-%d %I:%M:%S %p')
        except ValueError:
            # Fallback to 24-hour format (for old data)
            dt_ph = datetime.strptime(ts_ph, '%Y-%m-%d %H:%M:%S')
        
        # Check if this log is from today
        if dt_ph.date() == today_ph:
            hour = dt_ph.strftime('%H')
            if hour not in hourly_data:
                hourly_data[hour] = {'IN': 0, 'OUT': 0}
            hourly_data[hour][action] = hourly_data[hour].get(action, 0) + 1
    
    result = []
    for hour in sorted(hourly_data.keys()):
        result.append((hour, hourly_data[hour].get('IN', 0), hourly_data[hour].get('OUT', 0)))
    
    return result


def log_access(user_id: int, action: str, location: str = "Gate"):
    utc_time = get_utc_now()
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO access_logs (user_id, action, location, timestamp) VALUES (?, ?, ?, ?)",
            (user_id, action, location, utc_time)
        )
        conn.commit()
    finally:
        conn.close()

def last_action_for_user(user_id: int) -> Optional[str]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT action FROM access_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1", (user_id,))
        row = cur.fetchone()
    finally:
        conn.close()
    return row[0] if row else None

def export_logs_csv(path: str):
    import pandas as pd
    conn = get_conn()
    try:
        df = pd.read_sql_query("SELECT * FROM access_logs ORDER BY timestamp DESC", conn)
        
        if 'timestamp' in df.columns:
            df['timestamp'] = df['timestamp'].apply(utc_to_ph_time)
        df.to_csv(path, index=False)
    finally:
        conn.close()

def get_current_inside():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT u.user_id, u.name, u.role, MAX(l.timestamp)
            FROM users u
            JOIN access_logs l ON u.user_id = l.user_id
            WHERE l.action = 'IN'
            AND u.user_id NOT IN (
                SELECT user_id FROM access_logs WHERE action='OUT'
                AND timestamp > l.timestamp
            )
            GROUP BY u.user_id
            ORDER BY MAX(l.timestamp) DESC;
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    rows = [(r[0], r[1], r[2], utc_to_ph_time(r[3])) for r in rows]
    return rows

def get_recent_logs(limit=100):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT l.log_id, u.name, l.action, l.timestamp, l.location
            FROM access_logs l
            JOIN users u ON l.user_id = u.user_id
            ORDER BY l.timestamp DESC
            LIMIT ?;
        """, (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()
    rows = [(r[0], r[1], r[2], utc_to_ph_time(r[3]), r[4]) for r in rows]
    return rows

def get_daily_counts(days=7):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT timestamp, action
            FROM access_logs
            ORDER BY timestamp DESC
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    daily_data = {}
    for ts_str, action in rows:
        ts_ph = utc_to_ph_time(ts_str)
        date_ph = ts_ph.split(' ')[0]  
        
        if date_ph not in daily_data:
            daily_data[date_ph] = {'IN': 0, 'OUT': 0}
        daily_data[date_ph][action] = daily_data[date_ph].get(action, 0) + 1
    result = []
    for date in sorted(daily_data.keys(), reverse=True)[:days]:
        result.append((date, daily_data[date].get('IN', 0), daily_data[date].get('OUT', 0)))
    
    return result[::-1]  


def get_total_inside():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM (
                SELECT u.user_id
                FROM users u
                JOIN access_logs l ON u.user_id = l.user_id
                WHERE l.action='IN'
                AND u.user_id NOT IN (
                    SELECT user_id FROM access_logs WHERE action='OUT' AND timestamp>l.timestamp
                )
                GROUP BY u.user_id
            );
        """)
        total = cur.fetchone()[0]
    finally:
        conn.close()
    return total

def update_user(user_id: int, name: str, role: str, new_pin: Optional[str] = None):
    from core.security import generate_salt, hash_pin
    conn = get_conn()
    try:
        cur = conn.cursor()
        if new_pin:
            salt = generate_salt()
            pin_hash = hash_pin(new_pin, salt)
            cur.execute("UPDATE users SET name=?, role=?, pin_hash=?, pin_salt=? WHERE user_id=?",
                        (name, role, pin_hash, salt, user_id))
        else:
            cur.execute("UPDATE users SET name=?, role=? WHERE user_id=?", (name, role, user_id))
        conn.commit()
    finally:
        conn.close()

def set_user_status(user_id: int, status: str):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET status=? WHERE user_id=?", (status, user_id))
        conn.commit()
    finally:
        conn.close()

def delete_user(user_id: int):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()

def get_admin_by_username(username: str):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT admin_id, username, pass_hash, pass_salt FROM admins WHERE username=?", (username,))
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def add_user_account(username: str, name: str, role: str, pin: str) -> Tuple[int, str, str]:
    salt = generate_salt()
    pin_hash = hash_pin(pin, salt)
    qr_token = make_qr_token(name, pin_hash)
    qr_filename = f"{qr_token[:12]}.png"
    generate_qr_image(qr_token, filename=qr_filename)

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, name, role, pin_hash, pin_salt, qr_token, qr_code, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'Active')",
            (username, name, role, pin_hash, salt, qr_token, qr_filename)
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: users.username" in str(e) or "users.username" in str(e):
            raise ValueError(f"Username '{username}' already exists")
        elif "UNIQUE constraint failed: users.name" in str(e) or "users.name" in str(e):
            raise ValueError(f"Name '{name}' already exists")
        else:
            raise
    finally:
        conn.close()

    return user_id, qr_token, qr_filename

def get_user_by_username(username: str) -> Optional[Tuple]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id, username, name, role, pin_hash, pin_salt, status, qr_code, qr_token "
            "FROM users WHERE username = ?",
            (username,)
        )
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def get_user_attendance(user_id: int, limit: int = 100) -> List[Tuple]:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT log_id, action, timestamp, location
            FROM access_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (user_id, limit))
        rows = cur.fetchall()
    finally:
        conn.close()
    
    
    rows = [(r[0], r[1], utc_to_ph_time(r[2]), r[3]) for r in rows]
    return rows

def update_user_profile(user_id: int, username: str, name: str, new_pin: Optional[str] = None):
    from core.validation import (
        validate_username,
        validate_name,
        validate_password,
        sanitize_input,
        MAX_USERNAME_LENGTH,
        MAX_NAME_LENGTH
    )
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    name = sanitize_input(name, MAX_NAME_LENGTH)
    valid, error = validate_username(username)
    if not valid:
        raise ValueError(error)
    valid, error = validate_name(name)
    if not valid:
        raise ValueError(error)
    if new_pin:
        valid, error = validate_password(new_pin)
        if not valid:
            raise ValueError(error)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id FROM users WHERE username = ? AND user_id != ?",
            (username, user_id)
        )
        if cur.fetchone():
            raise ValueError(f"Username '{username}' is already taken")
        if new_pin:
            salt = generate_salt()
            password_hash = hash_pin(new_pin, salt)
            cur.execute(
                "UPDATE users SET username=?, name=?, password_hash=?, password_salt=?, force_password_change=0 WHERE user_id=?",
                (username, name, password_hash, salt, user_id)
            )
        else:
            cur.execute(
                "UPDATE users SET username=?, name=? WHERE user_id=?",
                (username, name, user_id)
            )
        conn.commit()
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise ValueError(f"Username '{username}' is already taken")
        elif "name" in str(e).lower():
            raise ValueError(f"Name '{name}' is already taken")
        else:
            raise ValueError("Duplicate entry detected")
    finally:
        conn.close()

def add_admin_with_email(username: str, email: str, name: str, password: str):
    """Create admin account with email and name - WITH VALIDATION"""
    from core.security import generate_salt, hash_pin
    from core.validation import (
        validate_username,
        validate_email,
        validate_name,
        validate_password,
        sanitize_input,
        MAX_USERNAME_LENGTH,
        MAX_EMAIL_LENGTH,
        MAX_NAME_LENGTH
    )  
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    email = sanitize_input(email, MAX_EMAIL_LENGTH).lower()
    name = sanitize_input(name, MAX_NAME_LENGTH)
    
    valid, error = validate_username(username)
    if not valid:
        raise ValueError(error)
    
    valid, error = validate_email(email)
    if not valid:
        raise ValueError(error)
    valid, error = validate_name(name)
    if not valid:
        raise ValueError(error)
    valid, error = validate_password(password)
    if not valid:
        raise ValueError(error)
    salt = generate_salt()
    phash = hash_pin(password, salt)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO admins (username, email, name, pass_hash, pass_salt, email_verified) VALUES (?, ?, ?, ?, ?, 0)",
            (username, email, name, phash, salt)
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise ValueError(f"Username '{username}' already exists")
        elif "email" in str(e).lower():
            raise ValueError(f"Email '{email}' already in use")
        else:
            raise ValueError("Duplicate entry detected")
    finally:
        conn.close()

def get_admin_by_username_or_email(identifier: str):
    """Get admin by username or email - NOW INCLUDES NAME"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT admin_id, username, email, name, pass_hash, pass_salt, email_verified 
            FROM admins WHERE username=? OR email=?
        """, (identifier, identifier))
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def add_user_account_with_email(username: str, email: str, name: str, role: str, pin: str) -> Tuple[int, str, str, str]:
    """
    Create user account with email - NOW WITH SEPARATE PASSWORD AND PIN
    Returns (user_id, qr_token, qr_filename, generated_pin)
    """
    from core.security import generate_salt, hash_pin
    from core.qr_utils import make_qr_token, generate_qr_image
    from core.validation import (
        validate_username,
        validate_email,
        validate_name,
        validate_role,
        validate_password,
        sanitize_input,
        MAX_USERNAME_LENGTH,
        MAX_EMAIL_LENGTH,
        MAX_NAME_LENGTH
    )
    
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    email = sanitize_input(email, MAX_EMAIL_LENGTH).lower()
    name = sanitize_input(name, MAX_NAME_LENGTH)
    role = sanitize_input(role, 50)
    
    valid, error = validate_username(username)
    if not valid:
        raise ValueError(error)
    
    valid, error = validate_email(email)
    if not valid:
        raise ValueError(error)
    
    valid, error = validate_name(name)
    if not valid:
        raise ValueError(error)
    
    valid, error = validate_role(role)
    if not valid:
        raise ValueError(error)
    
    valid, error = validate_password(pin)  
    if not valid:
        raise ValueError(error)
    password_salt = generate_salt()
    password_hash = hash_pin(pin, password_salt)
    qr_pin = generate_random_pin(6)
    qr_token = make_qr_token(name, qr_pin)
    qr_filename = f"{qr_token[:12]}.png"
    generate_qr_image(qr_token, filename=qr_filename)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, name, role, password_hash, password_salt, pin, qr_token, qr_code, status, email_verified) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', 0)",
            (username, email, name, role, password_hash, password_salt, qr_pin, qr_token, qr_filename)
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise ValueError(f"Username '{username}' already exists")
        elif "email" in str(e).lower():
            raise ValueError(f"Email '{email}' already in use")
        elif "name" in str(e).lower():
            raise ValueError(f"Name '{name}' already exists")
        else:
            raise ValueError("Duplicate entry detected")
    finally:
        conn.close()

    return user_id, qr_token, qr_filename, qr_pin

def get_user_by_username_or_email(identifier: str) -> Optional[Tuple]:
    """Get user by username or email"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT user_id, username, email, name, role, password_hash, password_salt, status, qr_code, qr_token, email_verified
            FROM users WHERE username = ? OR email = ?
        """, (identifier, identifier))
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def record_login_attempt(user_type: str, identifier: str, success: bool, ip_address: str = None):
    from core.validation import sanitize_input
    user_type = sanitize_input(user_type, 20)
    identifier = sanitize_input(identifier, 255)
    ip_address = sanitize_input(ip_address, 45) if ip_address else None  
    if user_type not in ['admin', 'user']:
        user_type = 'unknown'
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO login_attempts (user_type, identifier, success, ip_address)
            VALUES (?, ?, ?, ?)
        """, (user_type, identifier, 1 if success else 0, ip_address))
        conn.commit()
    finally:
        conn.close()
        
def get_failed_login_count(user_type: str, identifier: str, minutes: int = 15) -> int:
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE user_type = ? AND identifier = ? AND success = 0
            AND timestamp > datetime('now', '-' || ? || ' minutes')
        """, (user_type, identifier, minutes))
        return cur.fetchone()[0]
    finally:
        conn.close()


def is_account_locked(user_type: str, identifier: str) -> bool:
    from core.validation import sanitize_input
    user_type = sanitize_input(user_type, 20)
    identifier = sanitize_input(identifier, 255)
    failed_count = get_failed_login_count(user_type, identifier, minutes=15)
    LOCK_THRESHOLD = 5
    return failed_count >= LOCK_THRESHOLD


def clear_login_attempts(user_type: str, identifier: str):
    """Clear login attempts after successful login"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM login_attempts
            WHERE user_type = ? AND identifier = ?
        """, (user_type, identifier))
        conn.commit()
    finally:
        conn.close()

def mark_email_verified(user_type: str, user_id: int):
    """Mark email as verified"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        if user_type == 'admin':
            cur.execute("UPDATE admins SET email_verified = 1 WHERE admin_id = ?", (user_id,))
        else:
            cur.execute("UPDATE users SET email_verified = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
        
def add_user_by_admin(username: str, email: str, name: str, role: str, password: str) -> Tuple[int, str, str, str]:
    from core.security import generate_salt, hash_pin
    from core.qr_utils import make_qr_token, generate_qr_image
    from core.validation import (
        validate_username,
        validate_email,
        validate_name,
        validate_role,
        sanitize_input,
        MAX_USERNAME_LENGTH,
        MAX_EMAIL_LENGTH,
        MAX_NAME_LENGTH
    )
    username = sanitize_input(username, MAX_USERNAME_LENGTH)
    email = sanitize_input(email, MAX_EMAIL_LENGTH).lower()
    name = sanitize_input(name, MAX_NAME_LENGTH)
    role = sanitize_input(role, 50)
    valid, error = validate_username(username)
    if not valid:
        raise ValueError(error)
    valid, error = validate_email(email)
    if not valid:
        raise ValueError(error)
    valid, error = validate_name(name)
    if not valid:
        raise ValueError(error)
    valid, error = validate_role(role)
    if not valid:
        raise ValueError(error)
    pin = generate_random_pin(6)
    password_salt = generate_salt()
    password_hash = hash_pin(password, password_salt)
    qr_token = make_qr_token(name, pin)
    qr_filename = f"{qr_token[:12]}.png"
    generate_qr_image(qr_token, filename=qr_filename)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, name, role, password_hash, password_salt, pin, qr_token, qr_code, status, email_verified, force_password_change) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', 0, 1)",
            (username, email, name, role, password_hash, password_salt, pin, qr_token, qr_filename)
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError as e:
        if "username" in str(e).lower():
            raise ValueError(f"Username '{username}' already exists")
        elif "email" in str(e).lower():
            raise ValueError(f"Email '{email}' already in use")
        elif "name" in str(e).lower():
            raise ValueError(f"Name '{name}' already exists")
        else:
            raise ValueError("Duplicate entry detected")
    finally:
        conn.close()

    return user_id, qr_token, qr_filename, pin

def check_force_password_change(user_id: int) -> bool:
    """Check if user needs to change password"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT force_password_change FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return bool(row[0]) if row else False
    finally:
        conn.close()

def update_user_password_and_clear_flag(user_id: int, new_password: str):
    """Update user password (not PIN) and clear force_password_change flag"""
    from core.security import generate_salt, hash_pin
    salt = generate_salt()
    password_hash = hash_pin(new_password, salt)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash=?, password_salt=?, force_password_change=0 WHERE user_id=?",
            (password_hash, salt, user_id)
        )
        conn.commit()
    finally:
        conn.close()

def get_user_email(user_id: int) -> Optional[str]:
    """Get user email by ID"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()
        
def get_user_daily_scan_count(user_id: int) -> dict:
    """
    Get user's scan counts for today (IN and OUT).
    Returns {'date': 'YYYY-MM-DD', 'in_count': X, 'out_count': Y, 'total': Z}
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        
        # Get today's date in Philippine timezone
        today_ph = datetime.now(PH_TZ).date()
        
        # Get all logs for this user
        cur.execute("""
            SELECT action, timestamp
            FROM access_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
        """, (user_id,))
        
        rows = cur.fetchall()
    finally:
        conn.close()
    
    in_count = 0
    out_count = 0
    
    # Convert each timestamp to PH time and check if it's today
    for action, timestamp_str in rows:
        # Convert UTC timestamp to PH time
        ts_ph = utc_to_ph_time(timestamp_str)
        
        # Parse 12-hour format with AM/PM
        try:
            dt_ph = datetime.strptime(ts_ph, '%Y-%m-%d %I:%M:%S %p')
        except ValueError:
            # Fallback to 24-hour format (for old data)
            dt_ph = datetime.strptime(ts_ph, '%Y-%m-%d %H:%M:%S')
        
        # Check if this log is from today
        if dt_ph.date() == today_ph:
            if action == 'IN':
                in_count += 1
            elif action == 'OUT':
                out_count += 1
    
    return {
        'date': today_ph.strftime('%Y-%m-%d'),
        'in_count': in_count,
        'out_count': out_count,
        'total': in_count + out_count
    }


def get_user_current_status(user_id: int) -> dict:
    """
    Get user's current location status (IN or OUT).
    Returns {'status': 'IN'|'OUT'|'UNKNOWN', 'location': str, 'timestamp': str}
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT action, location, timestamp
            FROM access_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (user_id,))
        
        row = cur.fetchone()
    finally:
        conn.close()
    
    if not row:
        return {
            'status': 'UNKNOWN',
            'location': 'No records',
            'timestamp': None
        }
    
    action, location, timestamp = row
    
    return {
        'status': action,
        'location': location or 'Gate',
        'timestamp': utc_to_ph_time(timestamp)
    }

    
def get_failed_login_count(user_type: str, identifier: str, minutes: int = None) -> int:
    """
    Get count of failed login attempts.
    If minutes is None, uses system settings.
    """
    from core.validation import sanitize_input
    
    user_type = sanitize_input(user_type, 20)
    identifier = sanitize_input(identifier, 255)
    
    # Use provided minutes or get from settings
    if minutes is None:
        from core.settings_manager import SystemSettings
        minutes = SystemSettings.get_lockout_duration()
    
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM login_attempts
            WHERE user_type = ? AND identifier = ? AND success = 0
            AND timestamp > datetime('now', '-' || ? || ' minutes')
        """, (user_type, identifier, minutes))
        return cur.fetchone()[0]
    finally:
        conn.close()


def is_account_locked(user_type: str, identifier: str) -> bool:
    """
    Check if account is locked using system settings.
    Returns True if account is locked, False otherwise.
    """
    from core.settings_manager import SystemSettings
    from core.validation import sanitize_input
    
    # Check if lockout is enabled
    if not SystemSettings.is_lockout_enabled():
        return False
    
    user_type = sanitize_input(user_type, 20)
    identifier = sanitize_input(identifier, 255)
    
    # Get failed login count using system settings
    failed_count = get_failed_login_count(user_type, identifier)
    threshold = SystemSettings.get_lockout_threshold()
    
    return failed_count >= threshold

def get_user_activity_heatmap(user_id: int, days: int = 60) -> List[dict]:
    """
    Get user's daily scan activity for the last N days (for heatmap chart).
    Returns list of {'date': 'YYYY-MM-DD', 'count': X} for each day.
    """
    from datetime import timedelta

    conn = get_conn()
    try:
        cur = conn.cursor()
        
        
        end_date = datetime.now(PH_TZ).date()
        start_date = end_date - timedelta(days=days - 1)
        
        
        cur.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM access_logs
            WHERE user_id = ?
            AND DATE(timestamp) BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (user_id, start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
        
        rows = cur.fetchall()
    finally:
        conn.close()
    activity_dict = {row[0]: row[1] for row in rows}
    result = []
    current_date = start_date
    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        result.append({
            'date': date_str,
            'count': activity_dict.get(date_str, 0)
        })
        current_date += timedelta(days=1)
    return result

def update_user_password_with_force_change(user_id: int, password_hash: str, password_salt: str):
    """Update user password and set force_password_change flag"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE users 
            SET password_hash = ?, password_salt = ?, force_password_change = 1
            WHERE user_id = ?
        """, (password_hash, password_salt, user_id))
        conn.commit()
    finally:
        conn.close()

def get_all_admins() -> List[Tuple]:
    """
    Get all admin accounts.
    Returns list of (admin_id, username, email, name, created_at, email_verified)
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT admin_id, username, email, name, created_at, email_verified 
            FROM admins 
            ORDER BY created_at ASC
        """)
        rows = cur.fetchall()
    finally:
        conn.close()
    return rows

def get_first_admin() -> Optional[Tuple]:
    """
    Get the first admin account (the one with the smallest admin_id)
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT admin_id, username, email, name 
            FROM admins 
            ORDER BY admin_id ASC 
            LIMIT 1
        """)
        row = cur.fetchone()
    finally:
        conn.close()
    return row

def is_first_admin(admin_id: int) -> bool:
    """
    Check if the given admin is the first admin
    """
    first_admin = get_first_admin()
    return first_admin and first_admin[0] == admin_id

def admin_count() -> int:
    """
    Get total number of admin accounts
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        count = cur.fetchone()[0]
    finally:
        conn.close()
    return count

def delete_admin(admin_id: int):
    """
    Delete an admin account
    Only callable by first admin, cannot delete first admin (admin_id = 1)
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        
        cur.execute("SELECT admin_id, username FROM admins WHERE admin_id = ?", (admin_id,))
        admin = cur.fetchone()
        
        if not admin:
            raise ValueError(f"Admin with ID {admin_id} not found")

        if admin_id == 1:
            raise ValueError("Cannot delete the first administrator account")

        cur.execute("DELETE FROM trusted_devices WHERE user_type = 'admin' AND user_id = ?", (admin_id,))

        cur.execute("DELETE FROM admins WHERE admin_id = ?", (admin_id,))
        
        conn.commit()
        
    finally:
        conn.close()