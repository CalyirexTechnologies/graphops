"""Accounts, sign-in, API keys and sessions.

The behaviour worth reviewing, since this is where a security product is
judged hardest:

**Sign-in does not say which half was wrong.** A missing account and a wrong
password return the same error and take comparable time, because
`passwords.dummy_verify()` runs on the no-such-user branch. Otherwise the
response time is a user enumeration oracle.

**Lockout is per account and time-boxed.** Five failures locks for fifteen
minutes. A permanent lock would let anyone disable a colleague's account by
typing the wrong password, which turns a login form into a denial of service.

**MFA is a second step, not a second field.** Password verification returns a
short-lived challenge token; the code is submitted against that. Accepting
both at once means the password is verified only when the code is also
correct, and a correct-password-wrong-code attempt becomes indistinguishable
from wrong-password, which sounds safer and is in fact how people end up
unable to tell credential stuffing from a fat-fingered colleague.

**Refresh tokens rotate and detect reuse.** Refreshing revokes the presented
token and issues a new pair. A token presented twice means it was captured,
so the whole session is revoked rather than the request merely refused.

**API keys are stored as hashes.** The full key is returned once, at
creation, and never again. The `prefix` column is what a UI shows and what a
lookup matches on, so finding the right row does not require a table scan of
hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid

from ..audit.chain import AuditLog, Outcome
from ..rbac.permissions import ASSIGNABLE_ROLES, Role, parse_role
from ..rbac.principal import Principal
from . import passwords, tokens, totp

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
MFA_CHALLENGE_TTL = 300
API_KEY_PREFIX = 'gops'


class AuthError(Exception):
    """Base for every authentication failure."""


class InvalidCredentials(AuthError):
    """Deliberately vague. Never says which half was wrong."""

    def __init__(self, message: str = 'invalid email or password'):
        super().__init__(message)


class AccountLocked(AuthError):
    def __init__(self, until: int):
        self.until = until
        super().__init__('account is locked until %d' % until)


class MfaRequired(AuthError):
    """Password accepted; a code is still needed."""

    def __init__(self, challenge: str):
        self.challenge = challenge
        super().__init__('multi-factor authentication required')


class SessionReplayDetected(AuthError):
    """A refresh token was presented twice. The session is now revoked."""


def _now() -> int:
    return int(time.time())


def _hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


class IdentityService:
    def __init__(self, db, settings, audit: AuditLog | None = None):
        self.db = db
        self.settings = settings
        self.audit = audit or AuditLog(db)

    # ------------------------------------------------------- organizations
    def create_organization(self, *, slug: str, name: str,
                            data_residency: str = 'global',
                            retention_days: int = 365) -> dict:
        slug = slug.strip().lower()
        if not slug or not slug.replace('-', '').replace('_', '').isalnum():
            raise ValueError('slug must be alphanumeric with - or _')
        org_id = str(uuid.uuid4())
        with self.db.write() as cur:
            cur.execute("""INSERT INTO organizations
                           (id, slug, name, created_at, data_residency, retention_days)
                           VALUES (?,?,?,?,?,?)""",
                        (org_id, slug, name, _now(), data_residency, retention_days))
        self.audit.record(action='org.create', outcome=Outcome.SUCCESS,
                          organization_id=org_id, actor_kind='system',
                          resource=slug, detail={'name': name})
        return {'id': org_id, 'slug': slug, 'name': name}

    def organization_by_slug(self, slug: str):
        return self.db.query_one('SELECT * FROM organizations WHERE slug = ?',
                                 (slug.strip().lower(),))

    # ---------------------------------------------------------------- users
    def create_user(self, *, organization_id: str, email: str, password: str,
                    roles=(Role.VIEWER,), display_name: str = '',
                    created_by: str | None = None) -> dict:
        email = email.strip().lower()
        if '@' not in email:
            raise ValueError('email is not an address')
        if len(password) < 12:
            # Length over composition rules, per NIST SP 800-63B. Composition
            # rules push people toward Password1! and no further.
            raise ValueError('password must be at least 12 characters')

        wanted = []
        for role in roles:
            parsed = role if isinstance(role, Role) else parse_role(role)
            if parsed not in ASSIGNABLE_ROLES:
                raise ValueError('role %s cannot be assigned to a person'
                                 % parsed.value)
            wanted.append(parsed)

        user_id = str(uuid.uuid4())
        with self.db.write() as cur:
            cur.execute("""INSERT INTO users
                           (id, organization_id, email, password_hash,
                            display_name, created_at)
                           VALUES (?,?,?,?,?,?)""",
                        (user_id, organization_id, email,
                         passwords.hash_password(password),
                         display_name or email.split('@')[0], _now()))
            for role in wanted:
                cur.execute("""INSERT INTO user_roles (user_id, role, granted_at, granted_by)
                               VALUES (?,?,?,?)""",
                            (user_id, role.value, _now(), created_by))
        self.audit.record(action='user.create', outcome=Outcome.SUCCESS,
                          organization_id=organization_id, actor_id=created_by,
                          resource=email,
                          detail={'roles': [r.value for r in wanted]})
        return {'id': user_id, 'email': email,
                'roles': [r.value for r in wanted]}

    def roles_for(self, user_id: str) -> tuple[str, ...]:
        rows = self.db.query('SELECT role FROM user_roles WHERE user_id = ?',
                             (user_id,))
        return tuple(row['role'] for row in rows)

    def _find_user(self, organization_id: str, email: str):
        return self.db.query_one(
            'SELECT * FROM users WHERE organization_id = ? AND email = ?',
            (organization_id, email.strip().lower()))

    # ------------------------------------------------------------ sign-in
    def authenticate(self, *, organization_id: str, email: str, password: str,
                     client_ip: str | None = None) -> dict:
        """Verify a password. Raises `MfaRequired` when a code is still needed."""
        user = self._find_user(organization_id, email)

        if user is None:
            # Spend a comparable amount of time before failing, so a missing
            # account does not answer faster than a wrong password.
            passwords.dummy_verify()
            self.audit.record(action='auth.login', outcome=Outcome.FAILURE,
                              organization_id=organization_id, resource=email,
                              client_ip=client_ip, detail={'reason': 'no such user'})
            raise InvalidCredentials()

        if user['locked_until'] and user['locked_until'] > _now():
            self.audit.record(action='auth.login', outcome=Outcome.DENIED,
                              organization_id=organization_id,
                              actor_id=user['id'], resource=email,
                              client_ip=client_ip, detail={'reason': 'locked'})
            raise AccountLocked(int(user['locked_until']))

        if not user['is_active']:
            self.audit.record(action='auth.login', outcome=Outcome.DENIED,
                              organization_id=organization_id,
                              actor_id=user['id'], resource=email,
                              client_ip=client_ip, detail={'reason': 'inactive'})
            raise InvalidCredentials()

        if not passwords.verify_password(password, user['password_hash']):
            self._register_failure(user, client_ip)
            raise InvalidCredentials()

        # Upgrade the stored hash opportunistically, while the plaintext is
        # in hand and already verified.
        if passwords.needs_rehash(user['password_hash']):
            with self.db.write() as cur:
                cur.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                            (passwords.hash_password(password), user['id']))

        self._clear_failures(user['id'])

        if user['mfa_enabled']:
            challenge, _ = tokens.issue(
                key=self.settings.signing_key, subject=user['id'],
                organization=organization_id, roles=('mfa-pending',),
                token_type=tokens.TYPE_ACCESS, ttl_seconds=MFA_CHALLENGE_TTL,
                issuer=self.settings.issuer)
            self.audit.record(action='auth.password', outcome=Outcome.SUCCESS,
                              organization_id=organization_id,
                              actor_id=user['id'], resource=email,
                              client_ip=client_ip, detail={'mfa': 'required'})
            raise MfaRequired(challenge)

        return self._start_session(user, client_ip=client_ip)

    def complete_mfa(self, *, challenge: str, code: str,
                     client_ip: str | None = None) -> dict:
        try:
            claims = tokens.verify(challenge, key=self.settings.signing_key,
                                   issuer=self.settings.issuer)
        except tokens.TokenError as exc:
            raise InvalidCredentials('challenge expired or invalid') from exc
        if 'mfa-pending' not in claims.roles:
            raise InvalidCredentials('not an MFA challenge')

        user = self.db.query_one('SELECT * FROM users WHERE id = ?',
                                 (claims.subject,))
        if user is None or not user['mfa_secret']:
            raise InvalidCredentials()

        accepted, counter = totp.verify(
            user['mfa_secret'], code,
            last_used_counter=user['mfa_last_counter'])
        if not accepted:
            self._register_failure(user, client_ip)
            self.audit.record(action='auth.mfa', outcome=Outcome.FAILURE,
                              organization_id=user['organization_id'],
                              actor_id=user['id'], client_ip=client_ip)
            raise InvalidCredentials('invalid code')

        with self.db.write() as cur:
            cur.execute('UPDATE users SET mfa_last_counter = ? WHERE id = ?',
                        (counter, user['id']))
        self.audit.record(action='auth.mfa', outcome=Outcome.SUCCESS,
                          organization_id=user['organization_id'],
                          actor_id=user['id'], client_ip=client_ip)
        return self._start_session(user, client_ip=client_ip)

    def _register_failure(self, user, client_ip: str | None) -> None:
        attempts = int(user['failed_attempts']) + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = _now() + LOCKOUT_SECONDS
        with self.db.write() as cur:
            cur.execute('UPDATE users SET failed_attempts = ?, locked_until = ?'
                        ' WHERE id = ?', (attempts, locked_until, user['id']))
        self.audit.record(
            action='auth.login', outcome=Outcome.FAILURE,
            organization_id=user['organization_id'], actor_id=user['id'],
            resource=user['email'], client_ip=client_ip,
            detail={'attempts': attempts, 'locked': bool(locked_until)})

    def _clear_failures(self, user_id: str) -> None:
        with self.db.write() as cur:
            cur.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL,'
                        ' last_login_at = ? WHERE id = ?', (_now(), user_id))

    def _start_session(self, user, *, client_ip: str | None = None,
                       impersonated_by: str | None = None) -> dict:
        session_id = str(uuid.uuid4())
        roles = self.roles_for(user['id'])
        expires = _now() + self.settings.refresh_token_ttl_seconds
        with self.db.write() as cur:
            cur.execute("""INSERT INTO sessions
                           (id, user_id, organization_id, created_at, expires_at, client_ip)
                           VALUES (?,?,?,?,?,?)""",
                        (session_id, user['id'], user['organization_id'],
                         _now(), expires, client_ip))
        return self._issue_pair(user, session_id, roles,
                                impersonated_by=impersonated_by,
                                client_ip=client_ip)

    def _issue_pair(self, user, session_id: str, roles,
                    *, impersonated_by: str | None = None,
                    client_ip: str | None = None) -> dict:
        access, access_claims = tokens.issue(
            key=self.settings.signing_key, subject=user['id'],
            organization=user['organization_id'], roles=roles,
            token_type=tokens.TYPE_ACCESS,
            ttl_seconds=self.settings.access_token_ttl_seconds,
            issuer=self.settings.issuer, session_id=session_id,
            impersonated_by=impersonated_by)
        refresh, _ = tokens.issue(
            key=self.settings.signing_key, subject=user['id'],
            organization=user['organization_id'], roles=roles,
            token_type=tokens.TYPE_REFRESH,
            ttl_seconds=self.settings.refresh_token_ttl_seconds,
            issuer=self.settings.issuer, session_id=session_id,
            impersonated_by=impersonated_by)
        self.audit.record(action='auth.session', outcome=Outcome.SUCCESS,
                          organization_id=user['organization_id'],
                          actor_id=user['id'], on_behalf_of=impersonated_by,
                          resource=session_id, client_ip=client_ip)
        return {
            'access_token': access,
            'refresh_token': refresh,
            'token_type': 'Bearer',
            'expires_in': self.settings.access_token_ttl_seconds,
            'session_id': session_id,
            'roles': list(roles),
            'user_id': user['id'],
            'organization_id': user['organization_id'],
            'issued_at': access_claims.issued_at,
        }

    # ----------------------------------------------------------- refreshing
    def refresh(self, refresh_token: str, *, client_ip: str | None = None) -> dict:
        claims = tokens.verify(refresh_token, key=self.settings.signing_key,
                               expected_type=tokens.TYPE_REFRESH,
                               issuer=self.settings.issuer)

        if self.is_revoked(claims.token_id):
            # Presented twice. The first use already rotated it away, so
            # either the client replayed or someone else captured it. Revoke
            # the session rather than guessing which.
            self.revoke_session(claims.session_id, reason='refresh token reuse')
            self.audit.record(action='auth.refresh', outcome=Outcome.DENIED,
                              organization_id=claims.organization,
                              actor_id=claims.subject, client_ip=client_ip,
                              detail={'reason': 'token reuse, session revoked'})
            raise SessionReplayDetected(
                'this refresh token was already used; the session is revoked')

        session = self.db.query_one('SELECT * FROM sessions WHERE id = ?',
                                    (claims.session_id,))
        if session is None or session['revoked_at'] or session['expires_at'] < _now():
            raise AuthError('session is no longer valid')

        user = self.db.query_one('SELECT * FROM users WHERE id = ?',
                                 (claims.subject,))
        if user is None or not user['is_active']:
            raise AuthError('account is not active')

        self.revoke_token(claims.token_id, claims.expires_at, reason='rotated')
        # Roles are re-read rather than carried over from the old token, so a
        # role removed by an admin takes effect at the next refresh instead
        # of lasting as long as the client keeps refreshing.
        return self._issue_pair(user, claims.session_id,
                                self.roles_for(user['id']),
                                impersonated_by=claims.impersonated_by,
                                client_ip=client_ip)

    # ----------------------------------------------------------- revocation
    def revoke_token(self, jti: str, expires_at: int, *, reason: str = '') -> None:
        with self.db.write() as cur:
            cur.execute("""INSERT OR IGNORE INTO revoked_tokens
                           (jti, expires_at, revoked_at, reason) VALUES (?,?,?,?)""",
                        (jti, int(expires_at), _now(), reason))

    def is_revoked(self, jti: str) -> bool:
        return self.db.query_one('SELECT 1 FROM revoked_tokens WHERE jti = ?',
                                 (jti,)) is not None

    def revoke_session(self, session_id: str | None, *, reason: str = '') -> None:
        if not session_id:
            return
        with self.db.write() as cur:
            cur.execute('UPDATE sessions SET revoked_at = ? WHERE id = ?',
                        (_now(), session_id))
        self.audit.record(action='auth.logout', outcome=Outcome.SUCCESS,
                          resource=session_id, detail={'reason': reason})

    def session_is_live(self, session_id: str | None) -> bool:
        if not session_id:
            return True   # an API key has no session
        row = self.db.query_one('SELECT revoked_at, expires_at FROM sessions'
                                ' WHERE id = ?', (session_id,))
        return bool(row) and not row['revoked_at'] and row['expires_at'] >= _now()

    def purge_expired_revocations(self) -> int:
        """Drop denylist rows whose tokens have expired anyway."""
        with self.db.write() as cur:
            cur.execute('DELETE FROM revoked_tokens WHERE expires_at < ?', (_now(),))
            return cur.rowcount

    # -------------------------------------------------------------- MFA setup
    def begin_mfa_enrolment(self, user_id: str) -> dict:
        user = self.db.query_one('SELECT * FROM users WHERE id = ?', (user_id,))
        if user is None:
            raise AuthError('no such user')
        secret = totp.generate_secret()
        with self.db.write() as cur:
            # Stored but not yet enabled. Enabling before a code is confirmed
            # locks the user out of their own account if the QR never scanned.
            cur.execute('UPDATE users SET mfa_secret = ?, mfa_enabled = 0'
                        ' WHERE id = ?', (secret, user_id))
        return {'secret': secret,
                'otpauth_uri': totp.provisioning_uri(
                    secret, account=user['email'],
                    issuer=self.settings.issuer)}

    def confirm_mfa_enrolment(self, user_id: str, code: str) -> bool:
        user = self.db.query_one('SELECT * FROM users WHERE id = ?', (user_id,))
        if user is None or not user['mfa_secret']:
            raise AuthError('enrolment was not started')
        accepted, counter = totp.verify(user['mfa_secret'], code)
        if not accepted:
            return False
        with self.db.write() as cur:
            cur.execute('UPDATE users SET mfa_enabled = 1, mfa_last_counter = ?'
                        ' WHERE id = ?', (counter, user_id))
        self.audit.record(action='user.mfa_enabled', outcome=Outcome.SUCCESS,
                          organization_id=user['organization_id'], actor_id=user_id)
        return True

    # ------------------------------------------------------------- API keys
    def create_api_key(self, *, organization_id: str, name: str,
                       roles=(Role.SERVICE,), created_by: str | None = None,
                       expires_at: int | None = None) -> dict:
        prefix = '%s_%s' % (API_KEY_PREFIX, secrets.token_hex(4))
        secret = secrets.token_urlsafe(32)
        full = '%s.%s' % (prefix, secret)
        key_id = str(uuid.uuid4())
        role_values = [getattr(r, 'value', str(r)) for r in roles]
        with self.db.write() as cur:
            cur.execute("""INSERT INTO api_keys
                           (id, organization_id, name, prefix, key_hash, roles,
                            created_by, created_at, expires_at)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (key_id, organization_id, name, prefix,
                         _hash_api_key(full), ','.join(role_values),
                         created_by, _now(), expires_at))
        self.audit.record(action='apikey.create', outcome=Outcome.SUCCESS,
                          organization_id=organization_id, actor_id=created_by,
                          resource=prefix, detail={'name': name, 'roles': role_values})
        # The only time the full key exists outside the caller's hand.
        return {'id': key_id, 'name': name, 'prefix': prefix,
                'api_key': full, 'roles': role_values,
                'warning': 'store this now; it is not recoverable'}

    def principal_for_api_key(self, raw_key: str,
                              client_ip: str | None = None) -> Principal:
        if not raw_key or '.' not in raw_key:
            raise InvalidCredentials('malformed API key')
        prefix = raw_key.split('.', 1)[0]
        row = self.db.query_one('SELECT * FROM api_keys WHERE prefix = ?', (prefix,))
        if row is None:
            raise InvalidCredentials('unknown API key')
        if not hmac.compare_digest(row['key_hash'], _hash_api_key(raw_key)):
            raise InvalidCredentials('unknown API key')
        if row['revoked_at']:
            raise InvalidCredentials('API key revoked')
        if row['expires_at'] and row['expires_at'] < _now():
            raise InvalidCredentials('API key expired')
        with self.db.write() as cur:
            cur.execute('UPDATE api_keys SET last_used_at = ? WHERE id = ?',
                        (_now(), row['id']))
        return Principal(subject=row['id'], organization=row['organization_id'],
                         roles=tuple(r for r in row['roles'].split(',') if r),
                         kind='service', client_ip=client_ip,
                         attributes={'api_key_prefix': prefix, 'name': row['name']})

    def revoke_api_key(self, key_id: str, *, actor_id: str | None = None) -> bool:
        with self.db.write() as cur:
            cur.execute('UPDATE api_keys SET revoked_at = ? WHERE id = ?'
                        ' AND revoked_at IS NULL', (_now(), key_id))
            changed = cur.rowcount
        if changed:
            self.audit.record(action='apikey.revoke', outcome=Outcome.SUCCESS,
                              actor_id=actor_id, resource=key_id)
        return bool(changed)

    # --------------------------------------------------------- impersonation
    def impersonate(self, *, admin: Principal, target_user_id: str,
                    client_ip: str | None = None) -> dict:
        """Start a session as another user, recording both identities."""
        from ..rbac.permissions import Permission
        admin.require(Permission.IMPERSONATE)
        target = self.db.query_one('SELECT * FROM users WHERE id = ?',
                                   (target_user_id,))
        if target is None:
            raise AuthError('no such user')
        if target['organization_id'] != admin.organization:
            # An impersonation that crosses tenants is the single most
            # valuable action in the product. It is refused outright.
            raise AuthError('cannot impersonate across organizations')
        self.audit.record(action='user.impersonate', outcome=Outcome.SUCCESS,
                          organization_id=admin.organization,
                          actor_id=admin.subject, on_behalf_of=target_user_id,
                          resource=target['email'], client_ip=client_ip)
        return self._start_session(target, client_ip=client_ip,
                                   impersonated_by=admin.subject)

    # ------------------------------------------------- bearer token -> principal
    def principal_for_token(self, token: str,
                            client_ip: str | None = None) -> Principal:
        claims = tokens.verify(token, key=self.settings.signing_key,
                               expected_type=tokens.TYPE_ACCESS,
                               issuer=self.settings.issuer)
        if 'mfa-pending' in claims.roles:
            raise InvalidCredentials('MFA challenge is not an access token')
        if self.is_revoked(claims.token_id):
            raise InvalidCredentials('token revoked')
        if not self.session_is_live(claims.session_id):
            raise InvalidCredentials('session revoked or expired')
        return Principal(subject=claims.subject, organization=claims.organization,
                         roles=claims.roles, kind='user',
                         session_id=claims.session_id, token_id=claims.token_id,
                         impersonated_by=claims.impersonated_by,
                         client_ip=client_ip)
