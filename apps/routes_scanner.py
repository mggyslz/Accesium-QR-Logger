from flask import Blueprint, render_template, request, jsonify
from core.database import get_user_by_qr, log_access, last_action_for_user, get_total_inside, get_active_location
from core.security import verify_pin
from core.access_control import check_access_allowed
import sqlite3
from config.settings import DB_PATH
from datetime import datetime

scanner_bp = Blueprint('scanner', __name__, template_folder='../templates')

@scanner_bp.route('/')
def scanner_page():
    """Scanner page - CSRF exempt via app.py configuration"""
    return render_template('scanner.html')

@scanner_bp.route('/process', methods=['POST'])
def process_qr():
    """Process QR code - CSRF exempt via app.py configuration"""
    data = request.json
    qr_data = data.get("qr_data")
    pin = data.get("pin") 
    user = get_user_by_qr(qr_data)
    if not user:
        return jsonify({"status": "error", "message": "Unknown QR code."})
    user_id, name, role, stored_pin, status = user
    if status != "Active":
        return jsonify({"status": "error", "message": f"{name} is inactive."})
    last_action = last_action_for_user(user_id)
    active_location = get_active_location()

    if last_action != "IN":
        allowed, reason = check_access_allowed(user_id, active_location)
        if not allowed:
            return jsonify({
                "status": "error",
                "message": f"{name}: {reason}"
            })
             
        if not pin:
            return jsonify({"status": "require_pin", "message": f"Enter PIN for {name}."})   
        if pin != stored_pin:
            return jsonify({"status": "error", "message": "Invalid PIN."})

        log_access(user_id, "IN", active_location)
        
        # Broadcast to user's SSE stream
        _broadcast_scan_event(user_id, "IN", active_location)
        
        # Broadcast to all admin streams
        _broadcast_admin_update("IN", user_id, name, role, active_location)
        
        return jsonify({
            "status": "success", 
            "action": "IN", 
            "name": name,
            "location": active_location
        })

    log_access(user_id, "OUT", active_location)
    
    # Broadcast to user's SSE stream
    _broadcast_scan_event(user_id, "OUT", active_location)
    
    # Broadcast to all admin streams
    _broadcast_admin_update("OUT", user_id, name, role, active_location)
    
    return jsonify({
        "status": "success", 
        "action": "OUT", 
        "name": name,
        "location": active_location
    })

def _broadcast_scan_event(user_id: int, action: str, location: str):
    """Broadcast scan event to user's SSE stream"""
    try:
        try:
            from apps.routes_sse import broadcast_to_user
        except ImportError:
            try:
                from routes_sse import broadcast_to_user
            except ImportError:
                print("WARNING: routes_sse not found. Real-time updates disabled.")
                return
        
        from core.database import get_user_daily_scan_count, get_user_current_status
        from datetime import datetime
        
        stats = get_user_daily_scan_count(user_id)
        status = get_user_current_status(user_id)
        
        broadcast_to_user(user_id, 'scan_event', {
            'action': action,
            'location': location,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'stats': stats,
            'status': status
        })
        print(f"[SSE] Broadcasted {action} event to user {user_id}")
    except Exception as e:
        print(f"Error broadcasting scan event: {e}")
        import traceback
        traceback.print_exc()

def _broadcast_admin_update(action: str, user_id: int, name: str, role: str, location: str):
    """Broadcast scan event to all admin SSE streams"""
    try:
        try:
            from apps.routes_sse import broadcast_to_all_admins
        except ImportError:
            try:
                from routes_sse import broadcast_to_all_admins
            except ImportError:
                print("WARNING: Admin SSE broadcast not available")
                return
        
        from core.database import get_total_inside, utc_to_ph_time
        from datetime import datetime
        
        total_inside = get_total_inside()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        broadcast_to_all_admins('admin_scan_event', {
            'action': action,
            'user_id': user_id,
            'name': name,
            'role': role,
            'location': location,
            'timestamp': timestamp,
            'total_inside': total_inside
        })
        print(f"[SSE] Broadcasted {action} event to all admins: {name}")
    except Exception as e:
        print(f"Error broadcasting admin update: {e}")
        import traceback
        traceback.print_exc()

@scanner_bp.route('/stats', methods=['GET'])
def scanner_stats():
    """Return live statistics for scanner display"""
    try:
        from datetime import datetime, timedelta
        import pytz
        
        total_inside = get_total_inside()
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Get Philippine timezone
        try:
            ph_tz = pytz.timezone('Asia/Manila')
            now_ph = datetime.now(ph_tz)
            today = now_ph.strftime('%Y-%m-%d')
        except:
            # Fallback to UTC if pytz not available
            today = datetime.now().strftime('%Y-%m-%d')
        
        # ✅ FIX: Convert UTC timestamp to Philippine time BEFORE extracting date
        cur.execute(
            """SELECT COUNT(*) FROM access_logs 
               WHERE DATE(datetime(timestamp, '+8 hours')) = ?""",
            (today,)
        )
        today_scans = cur.fetchone()[0]
        conn.close()
        
        print(f"[Scanner Stats] Date: {today}, Total Inside: {total_inside}, Today Scans: {today_scans}")
        
        return jsonify({
            "status": "success",
            "total_inside": total_inside,
            "today_scans": today_scans
        })
    except Exception as e:
        import traceback
        print(f"[Scanner Stats Error] {e}")
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": str(e),
            "total_inside": 0,
            "today_scans": 0
        }), 500