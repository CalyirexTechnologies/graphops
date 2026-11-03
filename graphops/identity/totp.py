"""Time-based one-time passwords, RFC 6238 over RFC 4226.

Both RFCs define the construction as HMAC plus a truncation rule, and the
HMAC is `hmac`/`hashlib` from the standard library. What is worth reading
closely is `verify`, where the two mistakes that matter live:

  * A window of one step either side is accepted, because a user who starts
    typing at second 29 submits at second 31. Accepting a wider window buys
    nothing and widens the guessing surface.
  * A code is accepted once. `last_used_counter` is stored per user, and a
    code whose counter is not strictly newer is refused. Without that, a code
    captured from a phishing page stays valid for the rest of its step.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
#: One step either side. See the module docstring.
DEFAULT_WINDOW = 1


def generate_secret(length: int = 20) -> str:
    """A base32 secret, 160 bits, which is the RFC 4226 recommendation."""
    return base64.b32encode(secrets.token_bytes(length)).decode('ascii').rstrip('=')


def _decode_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(' ', '').upper()
    padding = '=' * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:
        raise ValueError('not a base32 TOTP secret') from exc


def code_at(secret: str, counter: int, digits: int = DIGITS) -> str:
    """The HOTP value for an explicit counter."""
    key = _decode_secret(secret)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    # RFC 4226 section 5.3 dynamic truncation.
    offset = digest[-1] & 0x0F
    chunk = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(chunk % (10 ** digits)).zfill(digits)


def counter_for(moment: float | None = None, step: int = STEP_SECONDS) -> int:
    return int((time.time() if moment is None else moment) // step)


def now_code(secret: str, moment: float | None = None) -> str:
    return code_at(secret, counter_for(moment))


def verify(secret: str, code: str, *,
           window: int = DEFAULT_WINDOW,
           moment: float | None = None,
           last_used_counter: int | None = None) -> tuple[bool, int | None]:
    """Check a submitted code.

    Returns `(accepted, counter)`. Store the returned counter as the user's
    `last_used_counter`; passing it back on the next call is what makes a
    code single-use.
    """
    if not code or not code.strip().isdigit():
        return False, None
    submitted = code.strip()
    current = counter_for(moment)
    for drift in range(-window, window + 1):
        candidate = current + drift
        if candidate < 0:
            continue
        if last_used_counter is not None and candidate <= last_used_counter:
            # Already spent. Keep looping rather than returning, so a replay
            # costs the same time as any other wrong code.
            continue
        if hmac.compare_digest(code_at(secret, candidate), submitted):
            return True, candidate
    return False, None


def provisioning_uri(secret: str, *, account: str, issuer: str = 'GraphOps') -> str:
    """The otpauth:// URI an authenticator app scans.

    Returned as text for the caller to render. Nothing here draws a QR code,
    because that would pull in an image dependency to encode a string the
    client can encode itself.
    """
    label = quote('%s:%s' % (issuer, account), safe='')
    return ('otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1'
            '&digits=%d&period=%d'
            % (label, secret, quote(issuer, safe=''), DIGITS, STEP_SECONDS))
