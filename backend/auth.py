"""Logins for the demo: one SOC admin plus staff accounts for the employee portal.

Staff passwords are stored as salted PBKDF2 hashes; the admin also needs a code from an
authenticator app (TOTP). Tokens are HMAC-signed (stateless): 4 hours for the admin, 12 for staff. Set SECRET_KEY to keep
people logged in across restarts; otherwise a new key is generated at start-up.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from urllib.parse import quote

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "TOBY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "5429")
TOKEN_HOURS = 12
ADMIN_TOKEN_HOURS = 4  # admin sessions expire sooner
ADMIN_2FA = os.getenv("ADMIN_2FA", "true").lower() == "true"
_SECRET = (os.getenv("SECRET_KEY") or secrets.token_hex(32)).encode()

# Demo staff accounts -> (salted PBKDF2-SHA256 password hash, employee ID).
# The plain demo passwords are listed in the README; only hashes are stored here.
STAFF_ACCOUNTS = {
    "pradish": ("pbkdf2_sha256$200000$1dc11d3890fee4f1db199e93424079ad$816fee2fa0400e5116dd66093e3591f3ad60dfff6cc4db5050d245cb13aa9ea9", "EMP001"),
    "ananya": ("pbkdf2_sha256$200000$85e0565892ac022de1ebfc4122ffad01$539b378ad51573342cd976e2dfc2133fe9eab5e6433f8c6ff38cc5c815cb0107", "EMP002"),
    "rahul": ("pbkdf2_sha256$200000$49ef6f042ccc2a4fadc68fd49cba122c$579022d5250ce733fad2f718d58cac1fd49133a86bf3bbcf69d67a7ab9a04ac5", "EMP003"),
    "karthik": ("pbkdf2_sha256$200000$386f51b360fa2effc4005c1b0317f011$bbc71146783918874ba8599158ab63b6af6599f93bde31491c94798da0ddf612", "EMP004"),
    "divya": ("pbkdf2_sha256$200000$09eab60858063103102a21fb46f29a53$56f781ff146f30cf709763fcb994f8b7b647a3e8f239cd35a7dca5092e99afdb", "EMP005"),
    "arjun": ("pbkdf2_sha256$200000$aecf04e4f506c05b91921fdc828511e2$42e8b9c241c034f66503e324b9986492eec9cddf893546167cd4c720b8033128", "EMP006"),
    "meera": ("pbkdf2_sha256$200000$eb8759178f1f3648248ea37ad4e619a6$fcf272af894e652d9885e0a526e23907eece131a97c4e495b2c0d04d15a36514", "EMP007"),
    "vikram": ("pbkdf2_sha256$200000$d615f2f5747243c268f52e7ad688d222$e5413602eb97ea4d0b381e91de45de45506f53451fd4bc706c9ead22c61910b9", "EMP008"),
    "sneha": ("pbkdf2_sha256$200000$4b513340309e7a231e4eab250a486011$42c9a20be109e6d3af9e3222cac9276769033012f15d4cfbb2c74eb580cd9bf2", "EMP009"),
    "aditya": ("pbkdf2_sha256$200000$b8e9381468d80c32e0691711647008e3$c356ca239e5bf48a153a422e85a11ec7967c25762470e4853763b06ee3e7c8fb", "EMP010"),
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sign(body: str) -> str:
    return hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()


def issue(role: str, sub: str, name: str, **extra) -> str:
    hours = ADMIN_TOKEN_HOURS if role == "admin" else TOKEN_HOURS
    body = _b64(json.dumps({"role": role, "sub": sub, "name": name,
                            "exp": int(time.time()) + hours * 3600, **extra}).encode())
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
    """(password hash, employee_id) for a staff username, or None."""
    return STAFF_ACCOUNTS.get(username.strip().lower())


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a 'pbkdf2_sha256$iterations$salt$hash' record in constant time."""
    try:
        _, iterations, salt, expected = stored.split("$")
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
        return hmac.compare_digest(got, expected)
    except ValueError:
        return False


# ---------------------------------------------------------------- authenticator app (TOTP, RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, at: float | None = None, step: int = 30) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str) -> bool:
    """Accept the current 30-second code and one step either side (clock drift)."""
    code = code.strip().replace(" ", "")
    now = time.time()
    return any(hmac.compare_digest(totp_code(secret, now + drift * 30), code) for drift in (-1, 0, 1))


def totp_uri(secret: str, account: str) -> str:
    """otpauth:// link that Google Authenticator / Microsoft Authenticator read from a QR code."""
    return f"otpauth://totp/SentinelAI:{quote(account)}?secret={secret}&issuer=SentinelAI&digits=6&period=30"


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
