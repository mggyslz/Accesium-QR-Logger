from pathlib import Path
import qrcode
from config.settings import QRCODE_DIR
import hashlib
import time

QRCODE_DIR.mkdir(parents=True, exist_ok=True)

def make_qr_token(name: str, pin_hash: str) -> str:

    base = f"{name}|{pin_hash[:12]}|{time.time_ns()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def generate_qr_image(token: str, filename: str = None) -> str:
    if filename is None:
        filename = f"{token[:12]}.png"
    path = Path(QRCODE_DIR) / filename
    img = qrcode.make(token)
    img.save(path.as_posix())
    return path.as_posix()
