from flask import Blueprint, Response, session, request
import json
import time
import queue
from typing import Dict
from core.auth_decorators import user_login_required, admin_login_required

sse_bp = Blueprint('sse', __name__)

# Global dictionaries to store queues
user_queues: Dict[int, queue.Queue] = {}
admin_queues: Dict[int, queue.Queue] = {}

def get_user_queue(user_id: int) -> queue.Queue:
    """Get or create a queue for a specific user"""
    if user_id not in user_queues:
        user_queues[user_id] = queue.Queue(maxsize=50)
    return user_queues[user_id]

def get_admin_queue(admin_id: int) -> queue.Queue:
    """Get or create a queue for a specific admin"""
    if admin_id not in admin_queues:
        admin_queues[admin_id] = queue.Queue(maxsize=50)
    return admin_queues[admin_id]

def broadcast_to_user(user_id: int, event_type: str, data: dict):
    """Send an event to a specific user's queue"""
    try:
        user_queue = get_user_queue(user_id)
        event = {
            'type': event_type,
            'data': data,
            'timestamp': time.time()
        }
        try:
            user_queue.put_nowait(event)
        except queue.Full:
            try:
                user_queue.get_nowait()
                user_queue.put_nowait(event)
            except queue.Empty:
                pass
    except Exception as e:
        print(f"Error broadcasting to user {user_id}: {e}")

def broadcast_to_admin(admin_id: int, event_type: str, data: dict):
    """Send an event to a specific admin's queue"""
    try:
        admin_queue = get_admin_queue(admin_id)
        event = {
            'type': event_type,
            'data': data,
            'timestamp': time.time()
        }
        try:
            admin_queue.put_nowait(event)
        except queue.Full:
            try:
                admin_queue.get_nowait()
                admin_queue.put_nowait(event)
            except queue.Empty:
                pass
    except Exception as e:
        print(f"Error broadcasting to admin {admin_id}: {e}")

def broadcast_to_all_admins(event_type: str, data: dict):
    """Broadcast an event to ALL connected admin streams"""
    admin_ids = list(admin_queues.keys())
    print(f"[SSE] Broadcasting to {len(admin_ids)} connected admins")
    
    for admin_id in admin_ids:
        try:
            broadcast_to_admin(admin_id, event_type, data)
        except Exception as e:
            print(f"Error broadcasting to admin {admin_id}: {e}")

@sse_bp.route('/stream')
@user_login_required
def stream():
    """SSE endpoint for real-time user updates"""
    user_id = session.get('user_id')
    
    def event_stream():
        user_queue = get_user_queue(user_id)
        
        yield f"data: {json.dumps({'type': 'connected', 'message': 'Stream connected'})}\n\n"
        
        while True:
            try:
                event = user_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
            except GeneratorExit:
                break
            except Exception as e:
                print(f"Stream error for user {user_id}: {e}")
                break
        
        if user_id in user_queues:
            del user_queues[user_id]
    
    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@sse_bp.route('/admin-stream')
@admin_login_required
def admin_stream():
    """SSE endpoint for real-time admin updates"""
    admin_id = session.get('admin_id')
    
    def event_stream():
        admin_queue = get_admin_queue(admin_id)
        
        yield f"data: {json.dumps({'type': 'connected', 'message': 'Admin stream connected'})}\n\n"
        
        while True:
            try:
                event = admin_queue.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
            except GeneratorExit:
                break
            except Exception as e:
                print(f"Stream error for admin {admin_id}: {e}")
                break
        
        if admin_id in admin_queues:
            del admin_queues[admin_id]
    
    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

def cleanup_inactive_queues():
    """Cleanup queues that haven't been used (call periodically if needed)"""
    pass

def notify_user_profile_changed(user_id: int, changes: dict):
    """Notify user that their profile was updated by admin"""
    try:
        broadcast_to_user(user_id, 'profile_updated', {
            'name': changes.get('name'),
            'role': changes.get('role'),
            'email': changes.get('email')
        })
        print(f"[SSE] Sent profile update notification to user {user_id}")
    except Exception as e:
        print(f"[SSE] Failed to notify user {user_id}: {e}")