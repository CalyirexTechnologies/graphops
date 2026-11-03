"""Authorisation, crown-jewel redaction and the audit chain."""
from __future__ import annotations

import pytest

from graphops.audit.chain import GENESIS_HASH, Outcome, scrub
from graphops.rbac.permissions import (
    ASSIGNABLE_ROLES,
    ROLE_PERMISSIONS,
    Permission,
    Role,
    has,
    permissions_for,
)
from graphops.rbac.policy import ensure_same_tenant, redact
from graphops.rbac.principal import AccessDenied, Principal

SALT = b'a per-tenant salt'


# ------------------------------------------------------------- the matrix
def test_the_matrix_denies_by_default():
    """An unknown role grants nothing, rather than raising or granting all."""
    assert permissions_for(['not-a-role']) == frozenset()
    assert not has(['not-a-role'], Permission.GRAPH_READ)


def test_viewer_is_a_strict_subset_of_analyst():
    assert ROLE_PERMISSIONS[Role.VIEWER] < ROLE_PERMISSIONS[Role.ANALYST]


def test_only_four_roles_may_reveal_crown_jewels():
    revealing = {role for role, granted in ROLE_PERMISSIONS.items()
                 if Permission.CROWN_REVEAL in granted}
    assert revealing == {Role.OWNER, Role.ADMIN, Role.ANALYST, Role.RESPONDER}


def test_an_auditor_reads_the_log_but_not_the_targets():
    granted = ROLE_PERMISSIONS[Role.AUDITOR]
    assert Permission.AUDIT_READ in granted
    assert Permission.CROWN_REVEAL not in granted


def test_a_service_identity_cannot_read_anything_sensitive():
    granted = ROLE_PERMISSIONS[Role.SERVICE]
    for forbidden in (Permission.AUDIT_READ, Permission.CROWN_REVEAL,
                      Permission.GRAPH_QUERY, Permission.USER_WRITE):
        assert forbidden not in granted


def test_the_service_role_cannot_be_handed_to_a_person():
    assert Role.SERVICE not in ASSIGNABLE_ROLES


def test_only_the_owner_may_impersonate():
    holders = {role for role, granted in ROLE_PERMISSIONS.items()
               if Permission.IMPERSONATE in granted}
    assert holders == {Role.OWNER}


def test_require_raises_with_the_permission_attached():
    principal = Principal(subject='u', organization='acme',
                          roles=(Role.VIEWER.value,))
    with pytest.raises(AccessDenied) as caught:
        principal.require(Permission.GRAPH_EXPORT)
    assert caught.value.permission is Permission.GRAPH_EXPORT


def test_a_cross_tenant_reference_is_refused():
    principal = Principal(subject='u', organization='acme', roles=('owner',))
    ensure_same_tenant(principal, 'acme')
    with pytest.raises(AccessDenied):
        ensure_same_tenant(principal, 'globex')


# ---------------------------------------------------------------- redaction
def _payload():
    return {'paths': [{'steps': [{'to': {'id': 'asset:billing',
                                         'key': 'billing-database',
                                         'label': 'billing-database (PCI)',
                                         'is_crown_jewel': True}}]}],
            'count': 7}


def test_an_analyst_sees_the_real_name():
    principal = Principal(subject='u', organization='acme', roles=('analyst',))
    result = redact(_payload(), principal, salt=SALT)
    assert result['paths'][0]['steps'][0]['to']['key'] == 'billing-database'
    assert '_redaction' not in result


def test_a_viewer_gets_a_pseudonym_and_a_notice():
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    result = redact(_payload(), principal, salt=SALT)
    name = result['paths'][0]['steps'][0]['to']['key']
    assert name.startswith('crown-jewel-')
    assert 'billing' not in name
    assert result['_redaction']['nodes_redacted'] == 1
    assert result['_redaction']['unlocked_by'] == 'crown:reveal'


def test_counts_survive_redaction():
    """The number is what a viewer is there for; hiding it is pointless."""
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    assert redact(_payload(), principal, salt=SALT)['count'] == 7


def test_a_pseudonym_is_stable_for_one_tenant():
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    first = redact(_payload(), principal, salt=SALT)
    second = redact(_payload(), principal, salt=SALT)
    assert (first['paths'][0]['steps'][0]['to']['key']
            == second['paths'][0]['steps'][0]['to']['key'])


def test_a_pseudonym_does_not_correlate_across_tenants():
    one = Principal(subject='u', organization='acme', roles=('viewer',))
    two = Principal(subject='u', organization='globex', roles=('viewer',))
    assert (redact(_payload(), one, salt=SALT)['paths'][0]['steps'][0]['to']['key']
            != redact(_payload(), two, salt=SALT)['paths'][0]['steps'][0]['to']['key'])


def test_both_spellings_of_the_crown_flag_are_redacted():
    """The estate stores `crown`; the engine emits `is_crown_jewel`."""
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    for flag in ('crown', 'is_crown_jewel'):
        result = redact({'node': {'id': 'n1', 'key': 'secret-db', flag: True}},
                        principal, salt=SALT)
        assert result['node']['key'].startswith('crown-jewel-'), flag


def test_redaction_reaches_a_shape_nobody_anticipated():
    """The walker is recursive so a new endpoint cannot leak by omission."""
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    buried = {'a': {'b': [{'c': {'id': 'x', 'key': 'crown-db',
                                 'is_crown_jewel': True}}]}}
    result = redact(buried, principal, salt=SALT)
    assert result['a']['b'][0]['c']['key'].startswith('crown-jewel-')


def test_a_non_crown_node_is_untouched():
    principal = Principal(subject='u', organization='acme', roles=('viewer',))
    payload = {'node': {'id': 'n1', 'key': 'storefront-web',
                        'is_crown_jewel': False}}
    assert redact(payload, principal, salt=SALT)['node']['key'] == 'storefront-web'


# -------------------------------------------------------------- audit chain
def test_an_empty_log_has_the_genesis_head(audit):
    assert audit.head() == GENESIS_HASH
    assert audit.verify_chain()['valid']


def test_entries_chain_to_their_predecessor(audit):
    first = audit.record(action='a', outcome=Outcome.SUCCESS)
    second = audit.record(action='b', outcome=Outcome.SUCCESS)
    assert first.previous_hash == GENESIS_HASH
    assert second.previous_hash == first.entry_hash
    assert audit.verify_chain()['valid']


def test_editing_an_entry_is_detected(audit, db):
    audit.record(action='a', outcome=Outcome.SUCCESS)
    target = audit.record(action='graph.export', outcome=Outcome.DENIED)
    audit.record(action='c', outcome=Outcome.SUCCESS)

    with db.write() as cur:
        cur.execute('UPDATE audit_events SET outcome = ? WHERE id = ?',
                    (Outcome.SUCCESS, target.id))

    report = audit.verify_chain()
    assert not report['valid']
    assert report['broken_at'] == 2
    assert 'hash' in report['reason']


def test_deleting_an_entry_is_detected(audit, db):
    audit.record(action='a', outcome=Outcome.SUCCESS)
    middle = audit.record(action='b', outcome=Outcome.SUCCESS)
    audit.record(action='c', outcome=Outcome.SUCCESS)
    with db.write() as cur:
        cur.execute('DELETE FROM audit_events WHERE id = ?', (middle.id,))
    assert not audit.verify_chain()['valid']


def test_a_wholesale_rewrite_is_caught_only_by_the_anchored_head(audit, db):
    """Internally consistent but not the chain we published."""
    audit.record(action='a', outcome=Outcome.SUCCESS)
    anchored = audit.head()
    audit.record(action='b', outcome=Outcome.SUCCESS)
    assert audit.verify_chain()['valid']
    report = audit.verify_chain(expected_head=anchored)
    assert not report['valid']
    assert 'anchored' in report['reason']


def test_secrets_never_reach_the_log(audit):
    entry = audit.record(action='auth.login', outcome=Outcome.SUCCESS,
                         detail={'email': 'a@b.c', 'password': 'hunter2',
                                 'nested': {'api_key': 'live_abc',
                                            'items': [{'token': 'tok'}]}})
    assert entry.detail['password'] == '[redacted]'
    assert entry.detail['nested']['api_key'] == '[redacted]'
    assert entry.detail['nested']['items'][0]['token'] == '[redacted]'
    assert entry.detail['email'] == 'a@b.c'


def test_scrub_survives_a_deeply_nested_payload():
    deep = current = {}
    for _ in range(40):
        current['next'] = {}
        current = current['next']
    assert scrub(deep)  # must terminate rather than recurse forever
