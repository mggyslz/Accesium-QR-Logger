# config/settings.py
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DB_PATH = PROJECT_ROOT / "data" / "security_app.db"
QRCODE_DIR = PROJECT_ROOT / "static" / "qrcodes"
EXPORT_DIR = PROJECT_ROOT / "data" / "exports"

# Camera index (0 is default built-in webcam)
CAMERA_INDEX = 0

# Security parameters for PBKDF2
PBKDF2_ITERATIONS = 150_000
PBKDF2_ALGO = "sha256"
SALT_BYTES = 16
