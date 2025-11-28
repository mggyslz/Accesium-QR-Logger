
from core.database import get_conn
from datetime import datetime, time as dt_time
import pytz

PH_TZ = pytz.timezone('Asia/Manila')

def get_user_access_rules(user_id: int):
    """Get all enabled access rules for a user"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT rule_id, rule_type, location, time_from, time_to, 
                   date_from, date_to, specific_dates
            FROM access_rules
            WHERE user_id = ? AND enabled = 1
            ORDER BY rule_type DESC
        """, (user_id,))
        return cur.fetchall()
    finally:
        conn.close()

def check_access_allowed(user_id: int, location: str) -> tuple[bool, str]:
    """
    Check if user is allowed to access given location at current time.
    Returns (allowed: bool, reason: str)
    
    Priority: Whitelist rules override blacklist rules.
    """
    rules = get_user_access_rules(user_id)
    
    if not rules:
        return True, "No restrictions"
    
    now_ph = datetime.now(PH_TZ)
    current_date = now_ph.date()
    current_time = now_ph.time()
    whitelist_rules = [r for r in rules if r[1] == 'whitelist']
    blacklist_rules = [r for r in rules if r[1] == 'blacklist']
    if whitelist_rules:
        whitelist_matched = False
        for rule in whitelist_rules:
            if _rule_matches(rule, location, current_date, current_time):
                whitelist_matched = True
                break
        if not whitelist_matched:
            return False, "Access denied: Outside allowed locations/times"
    for rule in blacklist_rules:
        if _rule_matches(rule, location, current_date, current_time):
            return False, f"Access denied: Restricted from {location}"
    return True, "Access granted"

def _rule_matches(rule: tuple, location: str, current_date, current_time) -> bool:
    """
    Check if a rule matches current conditions.
    rule format: (rule_id, rule_type, location, time_from, time_to, 
                  date_from, date_to, specific_dates)
    """
    rule_location = rule[2]
    time_from = rule[3]
    time_to = rule[4]
    date_from = rule[5]
    date_to = rule[6]
    specific_dates = rule[7]

    if rule_location and rule_location != location:
        return False
    if specific_dates:
        specific_date_list = [d.strip() for d in specific_dates.split(',')]
        if current_date.strftime('%Y-%m-%d') not in specific_date_list:
            return False
    if date_from:
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
        if current_date < date_from_obj:
            return False  
    if date_to:
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
        if current_date > date_to_obj:
            return False

    if time_from and time_to:
        time_from_obj = datetime.strptime(time_from, '%H:%M').time()
        time_to_obj = datetime.strptime(time_to, '%H:%M').time()
        if time_from_obj <= time_to_obj:
            if not (time_from_obj <= current_time <= time_to_obj):
                return False
        else:
            
            if not (current_time >= time_from_obj or current_time <= time_to_obj):
                return False
    return True

def add_access_rule(user_id: int, rule_type: str, location: str = None, 
                   time_from: str = None, time_to: str = None,
                   date_from: str = None, date_to: str = None,
                   specific_dates: str = None):
    """Add a new access rule"""
    if rule_type not in ['whitelist', 'blacklist']:
        raise ValueError("rule_type must be 'whitelist' or 'blacklist'")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO access_rules 
            (user_id, rule_type, location, time_from, time_to, date_from, date_to, specific_dates)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, rule_type, location, time_from, time_to, date_from, date_to, specific_dates))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def delete_access_rule(rule_id: int):
    """Delete an access rule"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM access_rules WHERE rule_id = ?", (rule_id,))
        conn.commit()
    finally:
        conn.close()

def toggle_rule_enabled(rule_id: int, enabled: bool):
    """Enable or disable a rule"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE access_rules SET enabled = ? WHERE rule_id = ?", 
                   (1 if enabled else 0, rule_id))
        conn.commit()
    finally:
        conn.close()

def get_all_access_rules_for_admin():
    """Get all access rules with user information (for admin dashboard)"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT ar.rule_id, u.name, ar.rule_type, ar.location, 
                   ar.time_from, ar.time_to, ar.date_from, ar.date_to, 
                   ar.specific_dates, ar.enabled, ar.created_at
            FROM access_rules ar
            JOIN users u ON ar.user_id = u.user_id
            ORDER BY ar.created_at DESC
        """)
        return cur.fetchall()
    finally:
        conn.close()