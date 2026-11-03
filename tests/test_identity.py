"""Passwords, tokens, TOTP and the sign-in flow.

These tests are written as the attacks they are meant to prevent, so a
regression reads as "forgery accepted" rather than "assertion failed".
"""
from __future__ import annotations

import base64
import json
import time

import pytest

from graphops.identity import passwords, tokens, totp
from graphops.identity.service import (
    MAX_FAILED_ATTEMPTS,
    AccountLocked,
    InvalidCredentials,
    MfaRequired,
    SessionReplayDetected,
)


# ------------------------------------------------------------------ passwords
def test_a_password_verifies_against_its_own_hash():
    encoded = passwords.hash_password('correct horse battery staple')
    assert passwords.verify_password('correct horse battery staple', encoded)
    assert not passwords.verify_password('Correct horse battery staple', encoded)


def test_two_hashes_of_one_password_differ():
    """A shared salt would let one rainbow table cover every account."""
    assert (passwords.hash_password('same passphrase')
            != passwords.hash_password('same passphrase'))


def test_a_corrupt_stored_hash_is_false_not_an_exception():
    for rubbish in ('', 'garbage', 'scrypt$x$y$z$a$b', 'bcrypt$1$2$3$4$5'):
        assert passwords.verify_password('anything', rubbish) is False


def test_weaker_parameters_are_flagged_for_rehash():
    assert passwords.needs_rehash(passwords.hash_password('x', n=1024))
    assert not passwords.needs_rehash(passwords.hash_password('x'))


# --------------------------------------------------------------------- tokens
KEY = b'k' * 32


def test_a_token_round_trips():
    token, claims = tokens.issue(key=KEY, subject='u1', organization='acme',
                                 roles=['analyst'], ttl_seconds=60)
    verified = tokens.verify(token, key=KEY, expected_type='access',
                             issuer='graphops')
    assert verified.subject == 'u1'
    assert verified.roles == ('analyst',)
    assert verified.token_id == claims.token_id


def test_a_tampered_payload_is_refused():
    token, _ = tokens.issue(key=KEY, subject='u1', organization='acme',
                            roles=['viewer'], ttl_seconds=60)
    header, payload, signature = token.split('.')
    decoded = json.loads(base64.urlsafe_b64decode(payload + '=='))
    decoded['roles'] = ['owner']
    forged = base64.urlsafe_b64encode(
        json.dumps(decoded, separators=(',', ':'),
                   sort_keys=True).encode()).rstrip(b'=').decode()
    with pytest.raises(tokens.TokenInvalid):
        tokens.verify('%s.%s.%s' % (header, forged, signature), key=KEY)


def test_alg_none_is_refused():
    """The classic JWT forgery: drop the signature, claim no algorithm."""
    def segment(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(',', ':'),
                       sort_keys=True).encode()).rstrip(b'=').decode()
    forged = '%s.%s.' % (segment({'alg': 'none', 'typ': 'JWT'}),
                         segment({'sub': 'u1', 'org': 'acme', 'roles': ['owner'],
                                  'typ': 'access', 'jti': 'x', 'iat': 1,
                                  'exp': 2 ** 31, 'iss': 'graphops'}))
    with pytest.raises(tokens.TokenInvalid):
        tokens.verify(forged, key=KEY)


def test_a_token_with_no_expiry_is_refused():
    def segment(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(',', ':'),
                       sort_keys=True).encode()).rstrip(b'=').decode()
    import hashlib
    import hmac
    head = segment({'alg': 'HS256', 'typ': 'JWT'})
    body = segment({'sub': 'u1', 'org': 'acme', 'roles': [], 'typ': 'access',
                    'jti': 'x', 'iat': 1, 'iss': 'graphops'})
    signature = base64.urlsafe_b64encode(
        hmac.new(KEY, ('%s.%s' % (head, body)).encode(),
                 hashlib.sha256).digest()).rstrip(b'=').decode()
    with pytest.raises(tokens.TokenInvalid, match='no exp'):
        tokens.verify('%s.%s.%s' % (head, body, signature), key=KEY)


def test_the_wrong_key_is_refused():
    token, _ = tokens.issue(key=KEY, subject='u1', organization='acme',
                            roles=[], ttl_seconds=60)
    with pytest.raises(tokens.TokenInvalid):
        tokens.verify(token, key=b'j' * 32)


def test_an_expired_token_is_refused():
    token, _ = tokens.issue(key=KEY, subject='u1', organization='acme',
                            roles=[], ttl_seconds=1,
                            now=int(time.time()) - 10_000)
    with pytest.raises(tokens.TokenExpired):
        tokens.verify(token, key=KEY)


def test_a_refresh_token_cannot_be_used_as_an_access_token():
    token, _ = tokens.issue(key=KEY, subject='u1', organization='acme',
                            roles=[], token_type='refresh', ttl_seconds=60)
    with pytest.raises(tokens.TokenInvalid):
        tokens.verify(token, key=KEY, expected_type='access')


def test_the_wrong_issuer_is_refused():
    token, _ = tokens.issue(key=KEY, subject='u1', organization='acme',
                            roles=[], ttl_seconds=60, issuer='somebody-else')
    with pytest.raises(tokens.TokenInvalid):
        tokens.verify(token, key=KEY, issuer='graphops')


# ----------------------------------------------------------------------- totp
def test_a_current_code_is_accepted_once():
    secret = totp.generate_secret()
    code = totp.now_code(secret)
    accepted, counter = totp.verify(secret, code)
    assert accepted and counter is not None
    replayed, _ = totp.verify(secret, code, last_used_counter=counter)
    assert not replayed, 'a spent code must not be accepted again'


def test_a_code_from_the_previous_step_is_still_accepted():
    secret = totp.generate_secret()
    previous = totp.code_at(secret, totp.counter_for() - 1)
    accepted, _ = totp.verify(secret, previous)
    assert accepted, 'a user who starts typing at second 29 must succeed'


def test_a_code_from_far_outside_the_window_is_refused():
    secret = totp.generate_secret()
    stale = totp.code_at(secret, totp.counter_for() - 10)
    assert not totp.verify(secret, stale)[0]


def test_rubbish_is_refused_without_raising():
    secret = totp.generate_secret()
    for value in ('', '     ', 'abcdef', '12345678901234'):
        assert totp.verify(secret, value)[0] is False


# ------------------------------------------------------------------- sign-in
def test_an_unknown_user_and_a_wrong_password_are_indistinguishable(identity, org):
    identity.create_user(organization_id=org['id'], email='a@acme.com',
                         password='a sufficiently long passphrase')
    errors = []
    for email, password in (('a@acme.com', 'wrong'), ('ghost@acme.com', 'wrong')):
        with pytest.raises(InvalidCredentials) as caught:
            identity.authenticate(organization_id=org['id'], email=email,
                                  password=password)
        errors.append(str(caught.value))
    assert errors[0] == errors[1]


def test_an_account_locks_after_repeated_failures(identity, org):
    identity.create_user(organization_id=org['id'], email='a@acme.com',
                         password='a sufficiently long passphrase')
    for _ in range(MAX_FAILED_ATTEMPTS):
        with pytest.raises(InvalidCredentials):
            identity.authenticate(organization_id=org['id'],
                                  email='a@acme.com', password='wrong')
    with pytest.raises(AccountLocked):
        identity.authenticate(organization_id=org['id'], email='a@acme.com',
                              password='a sufficiently long passphrase')


def test_a_refresh_token_rotates_and_reuse_revokes_the_session(identity, org):
    identity.create_user(organization_id=org['id'], email='a@acme.com',
                         password='a sufficiently long passphrase')
    first = identity.authenticate(organization_id=org['id'],
                                  email='a@acme.com',
                                  password='a sufficiently long passphrase')
    second = identity.refresh(first['refresh_token'])
    assert second['refresh_token'] != first['refresh_token']

    with pytest.raises(SessionReplayDetected):
        identity.refresh(first['refresh_token'])

    # The whole session is gone, not just the replayed token.
    with pytest.raises(InvalidCredentials):
        identity.principal_for_token(second['access_token'])


def test_roles_are_reread_on_refresh_not_carried_over(identity, org, db):
    from graphops.rbac.permissions import Permission
    user = identity.create_user(organization_id=org['id'], email='a@acme.com',
                                password='a sufficiently long passphrase',
                                roles=['owner'])
    session = identity.authenticate(organization_id=org['id'],
                                    email='a@acme.com',
                                    password='a sufficiently long passphrase')
    with db.write() as cur:
        cur.execute('DELETE FROM user_roles WHERE user_id = ? AND role = ?',
                    (user['id'], 'owner'))
        cur.execute('INSERT INTO user_roles (user_id, role, granted_at)'
                    ' VALUES (?,?,?)', (user['id'], 'viewer', 0))
    refreshed = identity.refresh(session['refresh_token'])
    principal = identity.principal_for_token(refreshed['access_token'])
    assert not principal.can(Permission.USER_WRITE), (
        'a revoked role must not survive a refresh')


def test_mfa_is_demanded_and_the_challenge_is_not_an_access_token(identity, org):
    user = identity.create_user(organization_id=org['id'], email='m@acme.com',
                                password='a sufficiently long passphrase')
    enrolment = identity.begin_mfa_enrolment(user['id'])
    assert identity.confirm_mfa_enrolment(
        user['id'], totp.now_code(enrolment['secret']))

    with pytest.raises(MfaRequired) as caught:
        identity.authenticate(organization_id=org['id'], email='m@acme.com',
                              password='a sufficiently long passphrase')
    challenge = caught.value.challenge

    with pytest.raises(InvalidCredentials):
        identity.principal_for_token(challenge)

    # The enrolment code was spent confirming enrolment.
    with pytest.raises(InvalidCredentials):
        identity.complete_mfa(challenge=challenge,
                              code=totp.now_code(enrolment['secret']))

    session = identity.complete_mfa(
        challenge=challenge,
        code=totp.code_at(enrolment['secret'], totp.counter_for() + 1))
    assert session['access_token']


def test_an_api_key_is_not_recoverable_after_creation(identity, org, db):
    created = identity.create_api_key(organization_id=org['id'], name='splunk')
    stored = db.query_one('SELECT key_hash FROM api_keys WHERE id = ?',
                          (created['id'],))
    assert created['api_key'] not in stored['key_hash']
    assert identity.principal_for_api_key(created['api_key']).is_service


def test_a_revoked_api_key_stops_working(identity, org):
    created = identity.create_api_key(organization_id=org['id'], name='splunk')
    assert identity.revoke_api_key(created['id'])
    with pytest.raises(InvalidCredentials):
        identity.principal_for_api_key(created['api_key'])


def test_impersonation_cannot_cross_tenants(identity, org, other_org,
                                            principal_factory):
    target = identity.create_user(organization_id=other_org['id'],
                                  email='x@globex.com',
                                  password='a sufficiently long passphrase')
    owner = principal_factory('owner')
    with pytest.raises(Exception, match='across organizations'):
        identity.impersonate(admin=owner, target_user_id=target['id'])


def test_impersonation_takes_the_targets_rights_and_records_both(
        identity, org, principal_factory, users, audit):
    owner = principal_factory('owner')
    session = identity.impersonate(admin=owner,
                                   target_user_id=users['analyst']['id'])
    acting = identity.principal_for_token(session['access_token'])
    assert acting.subject == users['analyst']['id']
    assert acting.roles == ('analyst',)
    assert acting.impersonated_by == owner.subject

    entries = [e for e in audit.entries() if e['action'] == 'user.impersonate']
    assert entries and entries[0]['actor_id'] == owner.subject
    assert entries[0]['on_behalf_of'] == users['analyst']['id']
