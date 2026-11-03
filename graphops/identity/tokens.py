"""Signed access and refresh tokens, in the JWS compact form.

On not taking a dependency here: the signature is `hmac.new(key, msg,
hashlib.sha256)` from the standard library, so the cryptography is vetted
code. What this module adds is the JOSE envelope, which is base64url of two
JSON objects and a dot. Writing those forty lines keeps the auth path
installable with no wheels, and the parts that are easy to get wrong are
handled explicitly and tested:

  * `alg` is read from the header, checked against an allowlist of exactly
    one value, and `none` is rejected before any other work. The alg-confusion
    family of JWT bugs starts with trusting the header.
  * The signature is compared with `hmac.compare_digest`.
  * `exp`, `nbf` and `iss` are all verified, with `exp` required. A token
    with no expiry is refused rather than treated as eternal.
  * Every token carries `jti` and `typ`, so a refresh token cannot be
    replayed at an endpoint expecting an access token.

A revocation list lives in the database, not here; `jti` is what it stores.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

ALGORITHM = 'HS256'
_ALLOWED_ALGORITHMS = frozenset({ALGORITHM})

TYPE_ACCESS = 'access'
TYPE_REFRESH = 'refresh'

#: Tolerated clock skew between the signer and the verifier.
LEEWAY_SECONDS = 30


class TokenError(Exception):
    """Base class for every rejection, so callers can answer 401 once."""


class TokenExpired(TokenError):
    pass


class TokenInvalid(TokenError):
    pass


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _b64url_decode(segment: str) -> bytes:
    padding = '=' * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except Exception as exc:
        raise TokenInvalid('token segment is not base64url') from exc


@dataclass(frozen=True)
class Claims:
    subject: str
    organization: str
    roles: tuple[str, ...]
    token_type: str
    token_id: str
    issued_at: int
    expires_at: int
    issuer: str
    session_id: str | None = None
    #: True when this token was minted by an administrator acting as another
    #: user. Carried so the audit log can record both identities.
    impersonated_by: str | None = None

    def as_dict(self) -> dict:
        payload = {
            'sub': self.subject,
            'org': self.organization,
            'roles': list(self.roles),
            'typ': self.token_type,
            'jti': self.token_id,
            'iat': self.issued_at,
            'exp': self.expires_at,
            'iss': self.issuer,
        }
        if self.session_id:
            payload['sid'] = self.session_id
        if self.impersonated_by:
            payload['act'] = self.impersonated_by
        return payload


def _sign(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def issue(*, key: bytes, subject: str, organization: str,
          roles,
          token_type: str = TYPE_ACCESS,
          ttl_seconds: int = 900,
          issuer: str = 'graphops',
          session_id: str | None = None,
          impersonated_by: str | None = None,
          now: int | None = None) -> tuple[str, Claims]:
    """Mint a token. Returns the compact form and the claims that went in."""
    if token_type not in {TYPE_ACCESS, TYPE_REFRESH}:
        raise ValueError('unknown token type %r' % token_type)
    if ttl_seconds <= 0:
        raise ValueError('ttl_seconds must be positive')
    issued = int(time.time()) if now is None else int(now)
    claims = Claims(
        subject=subject,
        organization=organization,
        roles=tuple(roles),
        token_type=token_type,
        token_id=secrets.token_urlsafe(16),
        issued_at=issued,
        expires_at=issued + int(ttl_seconds),
        issuer=issuer,
        session_id=session_id,
        impersonated_by=impersonated_by,
    )
    header = {'alg': ALGORITHM, 'typ': 'JWT'}
    signing_input = '%s.%s' % (
        _b64url_encode(json.dumps(header, separators=(',', ':'),
                                  sort_keys=True).encode('utf-8')),
        _b64url_encode(json.dumps(claims.as_dict(), separators=(',', ':'),
                                  sort_keys=True).encode('utf-8')),
    )
    signature = _sign(key, signing_input.encode('ascii'))
    return '%s.%s' % (signing_input, _b64url_encode(signature)), claims


def verify(token: str, *, key: bytes,
           expected_type: str | None = None,
           issuer: str | None = None,
           now: int | None = None) -> Claims:
    """Check a token and return its claims, or raise a `TokenError`."""
    if not isinstance(token, str) or token.count('.') != 2:
        raise TokenInvalid('malformed token')
    header_segment, payload_segment, signature_segment = token.split('.')

    try:
        header = json.loads(_b64url_decode(header_segment))
    except (ValueError, TypeError) as exc:
        raise TokenInvalid('unreadable header') from exc
    if not isinstance(header, dict):
        raise TokenInvalid('header is not an object')

    # Before anything else. A token asking to be verified with 'none', or
    # with RS256 so the public key is treated as an HMAC secret, is refused
    # here rather than further down where the key material is in scope.
    algorithm = header.get('alg')
    if algorithm not in _ALLOWED_ALGORITHMS:
        raise TokenInvalid('unsupported alg %r' % (algorithm,))

    expected_signature = _sign(key, ('%s.%s' % (header_segment,
                                                payload_segment)).encode('ascii'))
    if not hmac.compare_digest(_b64url_decode(signature_segment),
                               expected_signature):
        raise TokenInvalid('signature mismatch')

    try:
        payload = json.loads(_b64url_decode(payload_segment))
    except (ValueError, TypeError) as exc:
        raise TokenInvalid('unreadable payload') from exc
    if not isinstance(payload, dict):
        raise TokenInvalid('payload is not an object')

    moment = int(time.time()) if now is None else int(now)

    expires_at = payload.get('exp')
    if not isinstance(expires_at, int):
        # A token with no expiry is not a long-lived token, it is a bug.
        raise TokenInvalid('token has no exp claim')
    if moment > expires_at + LEEWAY_SECONDS:
        raise TokenExpired('token expired')

    not_before = payload.get('nbf')
    if isinstance(not_before, int) and moment + LEEWAY_SECONDS < not_before:
        raise TokenInvalid('token is not valid yet')

    if issuer is not None and payload.get('iss') != issuer:
        raise TokenInvalid('issuer mismatch')

    token_type = payload.get('typ')
    if expected_type is not None and token_type != expected_type:
        raise TokenInvalid('expected a %s token, got %r'
                           % (expected_type, token_type))

    for required in ('sub', 'org', 'jti', 'iat'):
        if required not in payload:
            raise TokenInvalid('token is missing %r' % required)

    roles = payload.get('roles') or []
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise TokenInvalid('roles claim is malformed')

    return Claims(
        subject=str(payload['sub']),
        organization=str(payload['org']),
        roles=tuple(roles),
        token_type=str(token_type),
        token_id=str(payload['jti']),
        issued_at=int(payload['iat']),
        expires_at=expires_at,
        issuer=str(payload.get('iss', '')),
        session_id=payload.get('sid'),
        impersonated_by=payload.get('act'),
    )
