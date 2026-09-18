"""Logins for the demo: one SOC admin plus staff accounts for the employee portal.

Tokens are HMAC-signed (stateless), valid for 12 hours. Set SECRET_KEY to keep
people logged in across restarts; otherwise a new key is generated at start-up.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "TOBY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "5429")
TOKEN_HOURS = 12
_SECRET = (os.getenv("SECRET_KEY") or secrets.token_hex(32)).encode()

# Demo staff accounts -> employee IDs. These are sample credentials for live demos only.
STAFF_ACCOUNTS = {
    "pradish": ("4821", "EMP001"),
    "ananya": ("7306", "EMP002"),
    "rahul": ("1957", "EMP003"),
    "karthik": ("6643", "EMP004"),
    "divya": ("3198", "EMP005"),
    "arjun": ("8570", "EMP006"),
    "meera": ("2764", "EMP007"),
    "vikram": ("9415", "EMP008"),
    "sneha": ("5082", "EMP009"),
    "aditya": ("6239", "EMP010"),
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sign(body: str) -> str:
    return hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()


def issue(role: str, sub: str, name: str, **extra) -> str:
    body = _b64(json.dumps({"role": role, "sub": sub, "name": name,
                            "exp": int(time.time()) + TOKEN_HOURS * 3600, **extra}).encode())
    return f"{body}.{_sign(body)}"


def verify(token: str) -> dict | None:
    try:
        body, sig = token.split(".")
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return claims if claims["exp"] > time.time() else None
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def check_admin(username: str, password: str) -> bool:
    return (hmac.compare_digest(username.strip().upper(), ADMIN_USERNAME.upper())
            and hmac.compare_digest(password, ADMIN_PASSWORD))


def staff_account(username: str) -> tuple[str, str] | None:
    """(password, employee_id) for a staff username, or None."""
    return STAFF_ACCOUNTS.get(username.strip().lower())


def device_from_user_agent(ua: str) -> tuple[str, str]:
    """Rough (OS, browser) from the User-Agent header, named like the employee profiles."""
    ua = ua or ""
    if "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "Windows" in ua:
        os_name = "Windows 11"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Ubuntu" in ua:
        os_name = "Ubuntu"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"
    mobile = os_name in ("iOS", "Android")
    if re.search(r"python|curl|httpx|Go-http", ua, re.I):
        browser = ua.split("/")[0]
    elif "HeadlessChrome" in ua:
        browser = "Headless Chrome"
    elif "Edg/" in ua or "EdgA/" in ua:
        browser = "Edge"
    elif "Firefox/" in ua or "FxiOS" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua or "CriOS" in ua:
        browser = "Chrome Mobile" if mobile else "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "Unknown browser"
    return os_name, browser
