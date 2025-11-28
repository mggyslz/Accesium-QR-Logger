from core.database import get_conn

def init_db():
    """Initialize database with proper foreign key constraints and triggers"""
    conn = get_conn()
    cur = conn.cursor()
    
    #bEnable foreign keys BEFORE creating tables
    cur.execute("PRAGMA foreign_keys = ON")

    # ============================================
    # CORE TABLES: admins and users
    # ============================================
    
    # Create admins table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            pass_hash TEXT NOT NULL,
            pass_salt TEXT NOT NULL,
            email_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT UNIQUE NOT NULL,
            role TEXT,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            pin TEXT NOT NULL,
            qr_token TEXT UNIQUE NOT NULL,
            qr_code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'Active',
            email_verified INTEGER DEFAULT 0,
            force_password_change INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ============================================
    # RELATED TABLES WITH FOREIGN KEYS
    # ============================================

    # access_logs with proper CASCADE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('IN', 'OUT')),
            location TEXT DEFAULT 'Gate',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) 
                ON DELETE CASCADE 
                ON UPDATE CASCADE
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_logs_user_id 
        ON access_logs(user_id)
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp 
        ON access_logs(timestamp DESC)
    """)

    # verification_codes - NO CHECK constraint (will use triggers instead)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verification_codes (
            code_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user')),
            user_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK(purpose IN ('login', 'email_verify', 'password_reset')),
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_verification_codes_lookup 
        ON verification_codes(user_type, user_id, purpose, used)
    """)

    # trusted_devices - NO CHECK constraint
    cur.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user')),
            user_id INTEGER NOT NULL,
            device_token TEXT UNIQUE NOT NULL,
            device_name TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_trusted_devices_token 
        ON trusted_devices(device_token)
    """)

    # notifications - NO CHECK constraint
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user', 'system')),
            user_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info' CHECK(type IN ('info', 'success', 'warning', 'error')),
            read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_user 
        ON notifications(user_type, user_id, read)
    """)

    # login_attempts - NO FOREIGN KEY (intentional for audit trail)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_type TEXT NOT NULL CHECK(user_type IN ('admin', 'user')),
            identifier TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup 
        ON login_attempts(user_type, identifier, timestamp DESC)
    """)

    # access_rules with proper CASCADE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_rules (
            rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            rule_type TEXT NOT NULL CHECK(rule_type IN ('whitelist', 'blacklist')),
            location TEXT,
            time_from TEXT,
            time_to TEXT,
            date_from TEXT,
            date_to TEXT,
            specific_dates TEXT,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) 
                ON DELETE CASCADE 
                ON UPDATE CASCADE
        )
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_access_rules_user 
        ON access_rules(user_id, enabled)
    """)

    # system_settings with FK to admins
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (updated_by) REFERENCES admins(admin_id) 
                ON DELETE SET NULL 
                ON UPDATE CASCADE
        )
    """)

    # Settings table (simple key-value, no FK needed)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # ============================================
    # CASCADE TRIGGERS FOR DELETION
    # ============================================

    # Trigger: Delete verification codes when admin is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_admin_verification_codes
        AFTER DELETE ON admins
        FOR EACH ROW
        BEGIN
            DELETE FROM verification_codes 
            WHERE user_type = 'admin' AND user_id = OLD.admin_id;
        END;
    """)

    # Trigger: Delete verification codes when user is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_user_verification_codes
        AFTER DELETE ON users
        FOR EACH ROW
        BEGIN
            DELETE FROM verification_codes 
            WHERE user_type = 'user' AND user_id = OLD.user_id;
        END;
    """)

    # Trigger: Delete trusted devices when admin is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_admin_trusted_devices
        AFTER DELETE ON admins
        FOR EACH ROW
        BEGIN
            DELETE FROM trusted_devices 
            WHERE user_type = 'admin' AND user_id = OLD.admin_id;
        END;
    """)

    # Trigger: Delete trusted devices when user is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_user_trusted_devices
        AFTER DELETE ON users
        FOR EACH ROW
        BEGIN
            DELETE FROM trusted_devices 
            WHERE user_type = 'user' AND user_id = OLD.user_id;
        END;
    """)

    # Trigger: Delete notifications when admin is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_admin_notifications
        AFTER DELETE ON admins
        FOR EACH ROW
        BEGIN
            DELETE FROM notifications 
            WHERE user_type = 'admin' AND user_id = OLD.admin_id;
        END;
    """)

    # Trigger: Delete notifications when user is deleted
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS delete_user_notifications
        AFTER DELETE ON users
        FOR EACH ROW
        BEGIN
            DELETE FROM notifications 
            WHERE user_type = 'user' AND user_id = OLD.user_id;
        END;
    """)

    # ============================================
    # VALIDATION TRIGGERS (INSERT/UPDATE)
    # ============================================
    # These enforce referential integrity for polymorphic relationships
    
    # Prevent invalid verification codes
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS validate_verification_code_insert
        BEFORE INSERT ON verification_codes
        FOR EACH ROW
        WHEN (
            (NEW.user_type = 'admin' AND NOT EXISTS (SELECT 1 FROM admins WHERE admin_id = NEW.user_id))
            OR
            (NEW.user_type = 'user' AND NOT EXISTS (SELECT 1 FROM users WHERE user_id = NEW.user_id))
        )
        BEGIN
            SELECT RAISE(ABORT, 'Invalid user_id for user_type in verification_codes');
        END;
    """)

    # Prevent invalid trusted devices
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS validate_trusted_device_insert
        BEFORE INSERT ON trusted_devices
        FOR EACH ROW
        WHEN (
            (NEW.user_type = 'admin' AND NOT EXISTS (SELECT 1 FROM admins WHERE admin_id = NEW.user_id))
            OR
            (NEW.user_type = 'user' AND NOT EXISTS (SELECT 1 FROM users WHERE user_id = NEW.user_id))
        )
        BEGIN
            SELECT RAISE(ABORT, 'Invalid user_id for user_type in trusted_devices');
        END;
    """)

    # Prevent invalid notifications
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS validate_notification_insert
        BEFORE INSERT ON notifications
        FOR EACH ROW
        WHEN (
            NEW.user_type != 'system'
            AND (
                (NEW.user_type = 'admin' AND NOT EXISTS (SELECT 1 FROM admins WHERE admin_id = NEW.user_id))
                OR
                (NEW.user_type = 'user' AND NOT EXISTS (SELECT 1 FROM users WHERE user_id = NEW.user_id))
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'Invalid user_id for user_type in notifications');
        END;
    """)

    # ============================================
    # DEFAULT DATA
    # ============================================
    
    # Insert default settings
    cur.execute("""
        INSERT OR IGNORE INTO settings (key, value) 
        VALUES ('active_location', 'Main Gate')
    """)

    cur.execute("""
        INSERT OR IGNORE INTO settings (key, value) 
        VALUES ('smtp_configured', '0')
    """)

    # Insert default system settings
    default_settings = [
        ('session_timeout_minutes', '30', 'Session timeout in minutes (applies to both admin and users)'),
        ('require_2fa', '1', 'Require 2FA for all accounts (1=enabled, 0=disabled)'),
        ('account_lockout_enabled', '1', 'Enable account lockout after failed attempts (1=enabled, 0=disabled)'),
        ('lockout_attempts_threshold', '5', 'Number of failed attempts before lockout'),
        ('lockout_duration_minutes', '15', 'Duration of account lockout in minutes')
    ]
    
    for key, value, desc in default_settings:
        cur.execute("""
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description)
            VALUES (?, ?, ?)
        """, (key, value, desc))

    conn.commit()
    conn.close()
    print("Database initialized successfully")


if __name__ == "__main__":
    init_db()