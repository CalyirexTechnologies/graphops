"""The routes the console needs, and the state the API now keeps.

Before this, three things the console design relies on were not true:

  * Running ingest changed nothing. The route ingested, resolved and threw
    the result away, because the served estate was fixed at startup.
  * Nothing was remembered. `connector_runs` and `findings` existed as
    tables and were never written, so there was no "last ingest" and no
    "open since".
  * A locked account answered exactly like a wrong password, so the person
    locked out could not tell why. Making it say so is easy; making it say
    so without revealing which accounts exist is the part tested here.
"""
from __future__ import annotations

import pytest

from graphops.rbac.permissions import ROLE_PERMISSIONS, Permission

#: The passphrase conftest gives every test user. Not a secret.
TEST_PASSPHRASE = 'a sufficiently long passphrase'  # noqa: S105


def _login(client, role, attempt=TEST_PASSPHRASE):
    return client.post('/v1/auth/login', json={
        'organization': 'acme', 'email': '%s@acme.com' % role,
        'password': attempt})


# ---------------------------------------------------------------- overview

def test_the_overview_answers_the_headline_in_one_request(client, auth_header):
    body = client.get('/v1/overview', headers=auth_header('analyst')).json()
    assert body['estate']['entities'] == 35
    assert body['exposure']['path_count'] == 3
    assert body['exposure']['crown_jewels_total'] >= len(body['exposure']['targets'])
    assert body['exposure']['cheapest']['cost'] == 2.0
    severities = body['findings']['by_severity']
    assert sum(severities.values()) == body['findings']['total']
    assert body['access']['dormant'] == 3
    assert body['sections_withheld'] == {}


def test_a_viewer_gets_the_counts_but_not_the_routes(client, auth_header):
    """Graph read without graph query. Counts are never redacted; the steps
    of a route are a query result and are withheld, and the response says
    which permission would unlock them rather than leaving a hole."""
    body = client.get('/v1/overview', headers=auth_header('viewer')).json()
    assert body['exposure']['path_count'] == 3
    assert 'cheapest' not in body['exposure']
    assert body['sections_withheld']['exposure.cheapest'] == 'graph:query'
    assert body['sections_withheld']['last_ingest'] == 'connector:read'


# ------------------------------------------------------------- node detail

def test_node_detail_says_where_an_entity_came_from(client, auth_header):
    body = client.get('/v1/graph/nodes/asset:billing-database',
                      headers=auth_header('analyst')).json()
    node = body['node']
    assert node['regimes'] == ['PCI']
    assert node['owner'] == 'finance-ops'
    assert set(node['sources']) == {'okta', 'servicenow'}
    assert body['routes']['count'] >= 1
    assert body['grantees'], 'someone holds a grant on the card database'


def test_node_detail_for_an_identity_lists_what_it_is_granted(client, auth_header):
    body = client.get('/v1/graph/nodes/id:support-desk',
                      headers=auth_header('analyst')).json()
    statuses = {g['target']['key']: g['status'] for g in body['grants']}
    assert statuses['billing-database'] == 'never'
    assert body['choke']['routes_through'] == 2


def test_an_unknown_node_is_404(client, auth_header):
    response = client.get('/v1/graph/nodes/asset:no-such-thing',
                          headers=auth_header('analyst'))
    assert response.status_code == 404


def test_an_auditor_reaches_a_crown_jewel_by_its_pseudonym(client, auth_header):
    """The console links every node it shows. An auditor only ever sees
    pseudonyms, so the link has to work with one, and the page it opens
    must say no more than the link did."""
    exposure = client.get('/v1/graph/exposure', headers=auth_header('auditor')).json()
    alias = exposure['targets'][0]['id']
    assert alias.startswith('crown-jewel-')
    body = client.get('/v1/graph/nodes/%s' % alias,
                      headers=auth_header('auditor')).json()
    assert body['node']['id'] == alias
    assert 'billing' not in str(body) and 'nightly' not in str(body) \
        and 'hr-database' not in str(body)


def test_an_auditor_asking_for_a_crown_jewel_by_its_real_id_is_told_nothing(
        client, auth_header):
    """404, the same answer as for a node that does not exist. A 200 with a
    masked body would still confirm the guess."""
    response = client.get('/v1/graph/nodes/asset:billing-database',
                          headers=auth_header('auditor'))
    assert response.status_code == 404


# ------------------------------------------------------------- crown jewels

def test_marking_a_crown_jewel_changes_every_answer_for_that_tenant(
        client, auth_header):
    before = client.get('/v1/graph/exposure', headers=auth_header('analyst')).json()
    response = client.post('/v1/graph/crown-jewels', headers=auth_header('analyst'),
                           json={'node_id': 'asset:order-service', 'crown': True,
                                 'reason': 'reads the card database'})
    assert response.status_code == 200, response.text
    after = client.get('/v1/graph/exposure', headers=auth_header('analyst')).json()
    assert after['crown_jewels_total'] == before['crown_jewels_total'] + 1


def test_marking_is_tenant_scoped(client, auth_header, identity, other_org):
    """Another tenant's analyst sees the estate as its sources described it."""
    client.post('/v1/graph/crown-jewels', headers=auth_header('analyst'),
                json={'node_id': 'asset:order-service', 'crown': True})
    from graphops.rbac.permissions import Role
    identity.create_user(organization_id=other_org['id'], email='a@globex.com',
                         password='a sufficiently long passphrase',
                         roles=[Role.ANALYST])
    token = client.post('/v1/auth/login', json={
        'organization': 'globex', 'email': 'a@globex.com',
        'password': 'a sufficiently long passphrase'}).json()['access_token']
    theirs = client.get('/v1/graph/exposure',
                        headers={'Authorization': 'Bearer %s' % token}).json()
    ours = client.get('/v1/graph/exposure', headers=auth_header('analyst')).json()
    assert theirs['crown_jewels_total'] == ours['crown_jewels_total'] - 1


def test_marking_is_audited_with_its_reason(client, auth_header):
    client.post('/v1/graph/crown-jewels', headers=auth_header('analyst'),
                json={'node_id': 'asset:order-service', 'crown': True,
                      'reason': 'reads the card database'})
    entries = client.get('/v1/admin/audit', headers=auth_header('admin')).json()['entries']
    marks = [e for e in entries if e['action'] == 'crown_jewel.mark']
    assert marks and marks[0]['detail']['reason'] == 'reads the card database'


def test_an_address_on_the_internet_cannot_be_made_a_crown_jewel(client, auth_header):
    response = client.post('/v1/graph/crown-jewels', headers=auth_header('analyst'),
                           json={'node_id': 'addr:192.0.2.41', 'crown': True})
    assert response.status_code == 400


@pytest.mark.parametrize('role', ['viewer', 'auditor', 'responder'])
def test_only_roles_that_define_scope_can_mark(client, auth_header, role):
    response = client.post('/v1/graph/crown-jewels', headers=auth_header(role),
                           json={'node_id': 'asset:order-service', 'crown': True})
    assert response.status_code == 403


def test_every_role_that_can_mark_a_crown_jewel_can_see_its_name():
    """A role that could mark one but not see names would mark a pseudonym,
    and learn the real id from whether the mark succeeded."""
    for role, granted in ROLE_PERMISSIONS.items():
        if Permission.CROWN_WRITE in granted:
            assert Permission.CROWN_REVEAL in granted, role.value


# ------------------------------------------------------------------ ingest

def test_running_ingest_changes_what_the_api_serves(client, auth_header):
    """The bug: the route used to throw its own result away."""
    before = client.get('/v1/overview', headers=auth_header('owner')).json()
    run = client.post('/v1/connectors/run', headers=auth_header('owner'),
                      json={'mode': 'replay', 'connectors': ['okta', 'servicenow']})
    assert run.status_code == 200, run.text
    after = client.get('/v1/overview', headers=auth_header('owner')).json()
    assert after['estate']['entities'] != before['estate']['entities']
    assert after['last_ingest']['id'] == run.json()['ingest_id']


def test_an_ingest_and_its_runs_are_remembered(client, auth_header):
    run = client.post('/v1/connectors/run', headers=auth_header('owner'),
                      json={'mode': 'replay'}).json()
    listing = client.get('/v1/connectors', headers=auth_header('analyst')).json()
    assert listing['last_ingest']['id'] == run['ingest_id']
    assert listing['last_ingest']['connectors_run'] == 9
    okta = next(c for c in listing['connectors'] if c['key'] == 'okta')
    assert okta['last_run']['status'] == 'success'
    assert okta['last_run']['nodes'] > 0


def test_one_tenants_ingest_does_not_change_another_tenants_estate(
        client, auth_header, identity, other_org):
    client.post('/v1/connectors/run', headers=auth_header('owner'),
                json={'mode': 'replay', 'connectors': ['okta']})
    from graphops.rbac.permissions import Role
    identity.create_user(organization_id=other_org['id'], email='o@globex.com',
                         password='a sufficiently long passphrase', roles=[Role.ANALYST])
    token = client.post('/v1/auth/login', json={
        'organization': 'globex', 'email': 'o@globex.com',
        'password': 'a sufficiently long passphrase'}).json()['access_token']
    theirs = client.get('/v1/overview',
                        headers={'Authorization': 'Bearer %s' % token}).json()
    assert theirs['estate']['entities'] == 35


def test_a_restart_serves_the_tenant_its_own_estate_and_names_its_ingest(
        settings, db, connector_estate, client, auth_header):
    """The bug: a tenant's estate lived only in memory. After a restart the
    tenant was served the server's startup estate, and the console labelled
    it with the tenant's own last ingest, so a live run would come back as
    replay data under the live run's name."""
    from fastapi.testclient import TestClient

    from graphops.api.app import create_app
    run = client.post('/v1/connectors/run', headers=auth_header('owner'),
                      json={'mode': 'replay', 'connectors': ['okta', 'servicenow']}).json()
    before = client.get('/v1/overview', headers=auth_header('analyst')).json()
    assert before['estate']['entities'] != 35, 'the subset must differ from startup'

    restarted = TestClient(create_app(settings=settings, db=db,
                                      estate_provider=lambda: connector_estate))
    token = _login(restarted, 'analyst').json()['access_token']
    after = restarted.get('/v1/overview',
                          headers={'Authorization': 'Bearer %s' % token}).json()
    assert after['estate'] == before['estate']
    assert after['exposure']['path_count'] == before['exposure']['path_count']
    assert after['served_ingest']['id'] == run['ingest_id']


def test_a_failed_run_is_the_last_ingest_but_not_the_one_served(client, auth_header):
    good = client.post('/v1/connectors/run', headers=auth_header('owner'),
                       json={'mode': 'replay', 'connectors': ['okta']}).json()
    bad = client.post('/v1/connectors/run', headers=auth_header('owner'),
                      json={'mode': 'replay', 'connectors': ['jira']})
    assert bad.status_code == 200, bad.text
    assert bad.json()['served'] is False
    body = client.get('/v1/overview', headers=auth_header('analyst')).json()
    assert body['last_ingest']['id'] == bad.json()['ingest_id']
    assert body['last_ingest']['status'] == 'failed'
    assert body['served_ingest']['id'] == good['ingest_id']


def test_a_tenant_that_never_ran_an_ingest_is_served_the_startup_one(
        client, auth_header):
    body = client.get('/v1/overview', headers=auth_header('analyst')).json()
    # No startup ingest is recorded in the test app, so there is nothing to
    # name, and the overview must say nothing rather than borrow a label.
    assert body['served_ingest'] is None
    assert body['estate']['entities'] == 35


def test_the_schema_version_is_the_last_migration_and_a_fresh_store_reaches_it():
    """A migration added without bumping SCHEMA_VERSION fails here, not in
    production. The version's own comment said a test asserted this, and
    until this one none did."""
    from graphops.store.db import MIGRATIONS, SCHEMA_VERSION, Database
    versions = [version for version, _ in MIGRATIONS]
    assert versions == sorted(set(versions))
    assert versions[-1] == SCHEMA_VERSION
    store = Database(':memory:')
    try:
        assert store.migrate() == SCHEMA_VERSION
    finally:
        store.close()


# ---------------------------------------------------------------- findings

def test_a_finding_remembers_when_it_was_first_seen(client, auth_header):
    first = client.get('/v1/findings', headers=auth_header('analyst')).json()
    again = client.get('/v1/findings', headers=auth_header('analyst')).json()
    a = {f['fingerprint']: f['first_seen'] for f in first['findings']}
    b = {f['fingerprint']: f['first_seen'] for f in again['findings']}
    assert a == b and all(a.values())


def test_findings_filter_and_page_but_count_over_everything(client, auth_header):
    everything = client.get('/v1/findings', headers=auth_header('analyst')).json()
    page = client.get('/v1/findings?kind=over-privilege&limit=2',
                      headers=auth_header('analyst')).json()
    assert len(page['findings']) == 2
    assert page['total'] == everything['by_kind']['over-privilege']
    assert page['by_kind'] == everything['by_kind']
    searched = client.get('/v1/findings?q=support-desk',
                          headers=auth_header('analyst')).json()
    assert searched['total'] >= 1
    assert all('support-desk' in f['title'] for f in searched['findings'])


def test_a_finding_that_stops_being_true_is_marked_resolved(client, auth_header):
    """Closing the loop on a fix. Re-ingest without the identity provider and
    the dormant-grant findings it produced are no longer true."""
    client.get('/v1/findings', headers=auth_header('owner'))
    client.post('/v1/connectors/run', headers=auth_header('owner'),
                json={'mode': 'replay', 'connectors': ['servicenow', 'splunk']})
    body = client.get('/v1/findings?status=resolved', headers=auth_header('owner')).json()
    assert body['total'] >= 1
    assert all(f['status'] == 'resolved' and f['resolved_at'] for f in body['findings'])


# ---------------------------------------------------------- over-privilege

def test_access_filters_and_counts(client, auth_header):
    everything = client.get('/v1/graph/over-privilege',
                            headers=auth_header('analyst')).json()
    regulated = client.get('/v1/graph/over-privilege?regulated=true&status=dormant',
                           headers=auth_header('analyst')).json()
    assert regulated['total'] == everything['dormant_reaching_crown_jewels']
    assert all(r['reaches_crown_jewel'] and r['status'] in ('never', 'idle')
               for r in regulated['grants'])
    assert regulated['granted'] == everything['granted']


# -------------------------------------------------------------------- admin

def test_users_are_listed_without_anything_secret(client, auth_header):
    body = client.get('/v1/admin/users', headers=auth_header('admin')).json()
    assert len(body['users']) >= 6
    text = str(body)
    for secret in ('password_hash', 'mfa_secret', 'pbkdf2', 'scrypt$'):
        assert secret not in text
    one = body['users'][0]
    assert {'email', 'display_name', 'roles', 'mfa_enabled',
            'last_login_at', 'is_active'} <= set(one)


def test_users_of_another_tenant_are_never_listed(client, auth_header, identity,
                                                  other_org):
    from graphops.rbac.permissions import Role
    identity.create_user(organization_id=other_org['id'], email='x@globex.com',
                         password='a sufficiently long passphrase', roles=[Role.VIEWER])
    emails = [u['email'] for u in
              client.get('/v1/admin/users', headers=auth_header('admin')).json()['users']]
    assert 'x@globex.com' not in emails


def test_api_keys_are_listed_without_their_secret(client, auth_header):
    minted = client.post('/v1/admin/api-keys', headers=auth_header('admin'),
                         json={'name': 'siem forwarder', 'roles': ['service']}).json()
    body = client.get('/v1/admin/api-keys', headers=auth_header('admin')).json()
    assert any(k['name'] == 'siem forwarder' for k in body['api_keys'])
    assert minted['api_key'] not in str(body)
    assert 'key_hash' not in str(body)


def test_an_owner_can_view_as_another_user_and_the_session_says_so(
        client, auth_header, users):
    target = users['auditor']['id']
    response = client.post('/v1/admin/impersonation', headers=auth_header('owner'),
                           json={'user_id': target})
    assert response.status_code == 200, response.text
    token = response.json()['access_token']
    me = client.get('/v1/auth/me', headers={'Authorization': 'Bearer %s' % token}).json()
    assert me['roles'] == ['auditor']
    assert me['impersonator']['email'] == 'owner@acme.com'
    exposure = client.get('/v1/graph/exposure',
                          headers={'Authorization': 'Bearer %s' % token}).json()
    assert '_redaction' in exposure, 'viewing as an auditor must show what they see'


def test_only_an_owner_can_view_as_someone_else(client, auth_header, users):
    response = client.post('/v1/admin/impersonation', headers=auth_header('admin'),
                           json={'user_id': users['viewer']['id']})
    assert response.status_code == 403


# ---------------------------------------------------------------------- me

def test_me_names_the_person_and_their_organisation(client, auth_header):
    me = client.get('/v1/auth/me', headers=auth_header('analyst')).json()
    assert me['email'] == 'analyst@acme.com'
    assert me['organization_detail']['slug'] == 'acme'
    assert me['organization_detail']['name'] == 'Acme Ltd'
    assert 'data_residency' in me['organization_detail']
    assert me['session_started_at']
    assert me['impersonator'] is None


# ------------------------------------------------------------------- login

def test_a_wrong_password_says_how_many_attempts_are_left(client):
    response = _login(client, 'analyst', attempt='not the passphrase at all')
    assert response.status_code == 401
    assert response.json()['attempts_remaining'] == 4


def test_a_locked_account_says_so_and_when_it_unlocks(client):
    for _ in range(5):
        _login(client, 'analyst', attempt='not the passphrase at all')
    response = _login(client, 'analyst')
    assert response.status_code == 423
    assert response.json()['retry_after_seconds'] > 0


def test_an_unknown_email_locks_out_exactly_like_a_real_one(client):
    """Otherwise the lockout message is an oracle: try an address five times,
    and if it locks, the account exists."""
    def five_then_status(email):
        for _ in range(5):
            client.post('/v1/auth/login', json={
                'organization': 'acme', 'email': email,
                'password': 'not the passphrase at all'})
        response = client.post('/v1/auth/login', json={
            'organization': 'acme', 'email': email,
            'password': 'not the passphrase at all'})
        return response.status_code, sorted(response.json())

    assert five_then_status('analyst@acme.com') == five_then_status('ghost@acme.com')


def test_a_lockout_that_has_expired_starts_the_count_again(client, db):
    """The count used to stay at five after the fifteen minutes, so the next
    wrong password locked the account again at once. The person who waited
    out the lockout got one try, not five. Expiry is simulated by moving the
    stored lock into the past rather than by waiting on the real clock."""
    for _ in range(5):
        _login(client, 'analyst', attempt='not the passphrase at all')
    with db.write() as cur:
        cur.execute("UPDATE users SET locked_until = 1 WHERE email = 'analyst@acme.com'")
    response = _login(client, 'analyst', attempt='not the passphrase at all')
    assert response.status_code == 401
    assert response.json()['attempts_remaining'] == 4


def test_a_deactivated_account_answers_as_a_wrong_password_does(client, db):
    with db.write() as cur:
        cur.execute("UPDATE users SET is_active = 0 WHERE email = 'viewer@acme.com'")
    deactivated = _login(client, 'viewer')
    wrong = _login(client, 'analyst', attempt='not the passphrase at all')
    assert deactivated.status_code == wrong.status_code == 401
    assert deactivated.json() == wrong.json()


def test_attempts_remaining_count_down_identically_for_a_missing_account(client):
    real = _login(client, 'viewer', attempt='wrong wrong wrong wrong').json()
    ghost = client.post('/v1/auth/login', json={
        'organization': 'acme', 'email': 'nobody@acme.com',
        'password': 'wrong wrong wrong wrong'}).json()
    assert real == ghost
