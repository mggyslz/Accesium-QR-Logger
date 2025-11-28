
import traceback
from datetime import datetime
from tkinter import messagebox

LOG_FILE = "error_log.txt"

def log_error(err: Exception, context: str = ""):
    """Save error details to a log file."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n[{datetime.now().isoformat()}] {context}\n")
        f.write("".join(traceback.format_exception(type(err), err, err.__traceback__)))
        f.write("\n" + "-"*60 + "\n")

def safe_exec(func):
    """Decorator to auto-handle and log exceptions inside UI actions."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_error(e, f"In function {func.__name__}")
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")
    return wrapper
