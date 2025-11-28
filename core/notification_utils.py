
from core.database import get_conn
from typing import List, Tuple, Optional
from datetime import datetime


def create_notification(
    user_type: str,
    title: str,
    message: str,
    notif_type: str = 'info',
    user_id: Optional[int] = None
):
    """Create a notification"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO notifications (user_type, user_id, title, message, type)
            VALUES (?, ?, ?, ?, ?)
        """, (user_type, user_id, title, message, notif_type))
        conn.commit()
    finally:
        conn.close()
def get_user_notifications(user_type: str, user_id: int, limit: int = 10) -> List[Tuple]:
    """Get notifications for a specific user"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT notification_id, title, message, type, read, created_at
            FROM notifications
            WHERE (user_type = ? AND user_id = ?) OR (user_type = 'system' AND user_id IS NULL)
            ORDER BY created_at DESC
            LIMIT ?
        """, (user_type, user_id, limit))
        return cur.fetchall()
    finally:
        conn.close()

def get_unread_count(user_type: str, user_id: int) -> int:
    """Get count of unread notifications"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM notifications
            WHERE ((user_type = ? AND user_id = ?) OR (user_type = 'system' AND user_id IS NULL))
            AND read = 0
        """, (user_type, user_id))
        return cur.fetchone()[0]
    finally:
        conn.close()
def mark_notification_read(notification_id: int):
    """Mark a notification as read"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE notifications SET read = 1 WHERE notification_id = ?", (notification_id,))
        conn.commit()
    finally:
        conn.close()

def mark_all_read(user_type: str, user_id: int):
    """Mark all notifications as read for a user"""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE notifications SET read = 1
            WHERE (user_type = ? AND user_id = ?) OR (user_type = 'system' AND user_id IS NULL)
        """, (user_type, user_id))
        conn.commit()
    finally:
        conn.close()

def notify_successful_login(user_type: str, user_id: int, name: str):
    """Send notification for successful login"""
    create_notification(
        user_type=user_type,
        user_id=user_id,
        title="Successful Login",
        message=f"Welcome back, {name}!",
        notif_type='success'
    )

def notify_failed_login_attempt(user_type: str, user_id: int, name: str):
    """Send notification for failed login attempt"""
    create_notification(
        user_type=user_type,
        user_id=user_id,
        title="Failed Login Attempt",
        message=f"Failed login attempt detected. If this wasn't you, secure your account.",
        notif_type='warning'
    )

def notify_account_locked(user_type: str, user_id: int, name: str):
    """Send notification when account is locked"""
    create_notification(
        user_type=user_type,
        user_id=user_id,
        title="Account Locked",
        message=f"Account locked due to multiple failed attempts. Wait 15 minutes.",
        notif_type='error'
    )

def notify_password_changed(user_type: str, user_id: int):
    """Send notification when password is changed"""
    create_notification(
        user_type=user_type,
        user_id=user_id,
        title="Password Changed",
        message="Your password was changed successfully.",
        notif_type='info'
    )

def notify_new_user_registered(name: str, role: str):
    """Send system-wide notification for new user"""
    create_notification(
        user_type='system',
        user_id=None,
        title="New User Registered",
        message=f"New {role} '{name}' registered.",
        notif_type='info'
    )
