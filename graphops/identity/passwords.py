"""Password hashing on `hashlib.scrypt`.

scrypt is in the standard library, is memory-hard, and is named in RFC 7914.
Choosing it over bcrypt or argon2 costs one property (argon2id is the current
first choice) and buys another: the whole platform installs and runs with no
native build step, which is what lets a reviewer run the test suite on a
machine with no compiler.

Parameters follow the RFC 7914 interactive-login recommendation, N=2**15,
r=8, p=1, which is about 32 MB per hash. They are stored inside the encoded
hash, so raising them later does not invalidate existing passwords: the
verifier reads each stored hash's own parameters and `needs_rehash` tells the
caller when to upgrade one on the next successful login.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

#: Encoded form: scrypt$N$r$p$<salt b64>$<hash b64>
_SCHEME = 'scrypt'
_DEFAULT_N = 2 ** 15
_DEFAULT_R = 8
_DEFAULT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32

#: hashlib.scrypt needs maxmem raised above its 32 MB default for these
#: parameters: 128 * N * r * p is exactly 32 MiB, and OpenSSL rejects a
#: request equal to the limit, so give it headroom rather than lowering N.
_MAXMEM = 128 * _DEFAULT_N * _DEFAULT_R * _DEFAULT_P * 2


class InvalidHash(ValueError):
    """The stored string is not a hash this module produced."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def _unb64(raw: str) -> bytes:
    return base64.b64decode(raw.encode('ascii'))


def hash_password(password: str, *,
                  n: int = _DEFAULT_N,
                  r: int = _DEFAULT_R,
                  p: int = _DEFAULT_P) -> str:
    """Return an encoded hash carrying its own salt and parameters."""
    if not isinstance(password, str) or not password:
        raise ValueError('password must be a non-empty string')
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(password.encode('utf-8'), salt=salt,
                             n=n, r=r, p=p, dklen=_KEY_BYTES,
                             maxmem=128 * n * r * p * 2)
    return '%s$%d$%d$%d$%s$%s' % (_SCHEME, n, r, p, _b64(salt), _b64(derived))


def _parse(encoded: str) -> tuple[int, int, int, bytes, bytes]:
    try:
        scheme, n, r, p, salt, digest = encoded.split('$')
    except (ValueError, AttributeError) as exc:
        raise InvalidHash('not a scrypt hash: %r' % (encoded,)) from exc
    if scheme != _SCHEME:
        raise InvalidHash('unsupported scheme %r' % scheme)
    try:
        return int(n), int(r), int(p), _unb64(salt), _unb64(digest)
    except Exception as exc:
        raise InvalidHash('corrupt scrypt hash') from exc


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of `password` against an encoded hash.

    Returns False rather than raising on a malformed stored value, so one
    corrupt row cannot turn a login endpoint into a 500 that tells an
    attacker the account exists.
    """
    try:
        n, r, p, salt, expected = _parse(encoded)
    except InvalidHash:
        return False
    try:
        derived = hashlib.scrypt(password.encode('utf-8'), salt=salt,
                                 n=n, r=r, p=p, dklen=len(expected),
                                 maxmem=128 * n * r * p * 2)
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(derived, expected)


def needs_rehash(encoded: str, *,
                 n: int = _DEFAULT_N,
                 r: int = _DEFAULT_R,
                 p: int = _DEFAULT_P) -> bool:
    """True when a stored hash is weaker than the current parameters."""
    try:
        have_n, have_r, have_p, _, _ = _parse(encoded)
    except InvalidHash:
        return True
    return (have_n, have_r, have_p) != (n, r, p)


def dummy_verify() -> None:
    """Burn one hash's worth of time on a known value.

    Called on the no-such-user branch of login. Without it, a missing account
    returns far faster than a wrong password and the response time enumerates
    valid usernames.
    """
    verify_password('x', hash_password('x', n=1024, r=8, p=1))
