
"""
System Settings Manager
Handles admin-controlled settings that apply to both admin and user sessions
"""
from typing import Optional, Dict
from core.database import get_conn
from core.validation import sanitize_input

class SystemSettings:
    """Manage system-wide settings"""
    
    _cache = {}
    _cache_timestamp = None
    
    @staticmethod
    def _refresh_cache():
        """Refresh settings cache from database"""
        from datetime import datetime, timedelta
        
        if (SystemSettings._cache_timestamp and 
            datetime.now() - SystemSettings._cache_timestamp < timedelta(minutes=5)):
            return
        
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT setting_key, setting_value FROM system_settings")
            rows = cur.fetchall()
            
            SystemSettings._cache = {key: value for key, value in rows}
            SystemSettings._cache_timestamp = datetime.now()
        finally:
            conn.close()
    
    @staticmethod
    def get(key: str, default: str = None) -> Optional[str]:
        """Get a system setting value"""
        SystemSettings._refresh_cache()
        return SystemSettings._cache.get(key, default)
    
    @staticmethod
    def get_int(key: str, default: int = 0) -> int:
        """Get a system setting as integer"""
        value = SystemSettings.get(key)
        try:
            return int(value) if value else default
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def get_bool(key: str, default: bool = False) -> bool:
        """Get a system setting as boolean"""
        value = SystemSettings.get(key)
        return value == '1' or value == 'true' or value == 'True' if value else default
    
    @staticmethod
    def set(key: str, value: str, admin_id: int = None) -> bool:
        """Set a system setting value"""
        key = sanitize_input(key, 100)
        value = sanitize_input(str(value), 500)
        
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO system_settings 
                (setting_key, setting_value, updated_at, updated_by)
                VALUES (?, ?, datetime('now'), ?)
            """, (key, value, admin_id))
            conn.commit()
            
            
            SystemSettings._cache_timestamp = None
            
            return True
        except Exception as e:
            print(f"Error setting system setting: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def get_all() -> Dict[str, str]:
        """Get all system settings"""
        SystemSettings._refresh_cache()
        return SystemSettings._cache.copy()
    
    @staticmethod
    def get_session_timeout() -> int:
        """Get session timeout in minutes"""
        return SystemSettings.get_int('session_timeout_minutes', 30)
    
    @staticmethod
    def is_2fa_required() -> bool:
        """Check if 2FA is required"""
        return SystemSettings.get_bool('require_2fa', True)
    
    @staticmethod
    def is_lockout_enabled() -> bool:
        """Check if account lockout is enabled"""
        return SystemSettings.get_bool('account_lockout_enabled', True)
    
    @staticmethod
    def get_lockout_threshold() -> int:
        """Get number of failed attempts before lockout"""
        return SystemSettings.get_int('lockout_attempts_threshold', 5)
    
    @staticmethod
    def get_lockout_duration() -> int:
        """Get lockout duration in minutes"""
        return SystemSettings.get_int('lockout_duration_minutes', 15)

def update_session_timeout(minutes: int, admin_id: int = None) -> bool:
    """Update session timeout setting"""
    if not 5 <= minutes <= 480:  
        return False
    return SystemSettings.set('session_timeout_minutes', str(minutes), admin_id)

def update_2fa_requirement(enabled: bool, admin_id: int = None) -> bool:
    """Update 2FA requirement setting"""
    return SystemSettings.set('require_2fa', '1' if enabled else '0', admin_id)

def update_lockout_policy(enabled: bool, admin_id: int = None) -> bool:
    """Update account lockout policy"""
    return SystemSettings.set('account_lockout_enabled', '1' if enabled else '0', admin_id)

def update_lockout_threshold(attempts: int, admin_id: int = None) -> bool:
    """Update lockout threshold"""
    if not 3 <= attempts <= 10:
        return False
    return SystemSettings.set('lockout_attempts_threshold', str(attempts), admin_id)

def update_lockout_duration(minutes: int, admin_id: int = None) -> bool:
    """Update lockout duration"""
    if not 5 <= minutes <= 120:
        return False
    return SystemSettings.set('lockout_duration_minutes', str(minutes), admin_id)