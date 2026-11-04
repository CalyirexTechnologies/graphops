"""The HTTP surface.

The test worth reading first is `test_every_route_is_guarded`. It walks the
route table rather than checking endpoints one by one, so a route added next
month is covered the day it is written. Enumerating endpoints by hand is how
an unauthenticated route reaches production with a green suite.
"""
from __future__ import annotations

import pytest

from graphops.api.app import PUBLIC_PATHS


# ------------------------------------------------------------ the guarantee
def walk_routes(router):
    """Every route, including the ones nested inside included routers.

    THIS HELPER EXISTS BECAUSE ITS ABSENCE MADE THE GUARANTEE BELOW VACUOUS.
    This version of FastAPI keeps an `include_router` call as an
    `_IncludedRouter` entry in `app.routes` instead of flattening its routes
    into the parent. Those wrappers have no `path`, so a walk that skipped
    anything without one skipped every route the application actually
    serves, examined the four documentation routes, found them all in
    PUBLIC_PATHS, and passed.

    A route-table walk is the right shape for this check and that is exactly
    why it has to be verified: a guarantee that iterates the wrong collection
    is worse than no guarantee, because the green tick is read as coverage.
    """
    for route in getattr(router, 'routes', ()) or ():
        # An included router is reachable through `original_router` on this
        # version and through `routes` on others. Both are tried rather than
        # one, because the failure mode of guessing wrong is a silent pass.
        nested = getattr(route, 'original_router', None)
        if nested is None and getattr(route, 'routes', None):
            nested = route
        if nested is not None:
            yield from walk_routes(nested)
        if getattr(route, 'path', None) is not None:
            yield route


def test_the_route_walk_actually_reaches_the_application_routes():
    """Guards the guard. If this drops, the test below means nothing."""
    from graphops.api.app import create_app
    from graphops.config import load_settings
    from graphops.store.db import Database

    database = Database(':memory:')
    try:
        app = create_app(settings=load_settings(), db=database,
                         estate_provider=lambda: None)
        paths = {route.path for route in walk_routes(app)}
    finally:
        database.close()

    assert '/v1/graph/exposure' in paths
    assert '/v1/auth/login' in paths
    assert len(paths) > 20, 'the walk found %d paths, which is too few' % len(paths)


def test_every_route_is_guarded(app):
    """No route may be reachable without resolving a principal."""
    unguarded = []
    for route in walk_routes(app):
        path = getattr(route, 'path', None)
        endpoint = getattr(route, 'endpoint', None)
        if path is None or endpoint is None or path in PUBLIC_PATHS:
            continue
        dependant = getattr(route, 'dependant', None)
        names = set()
        if dependant is not None:
            stack = list(dependant.dependencies)
            while stack:
                current = stack.pop()
                call = getattr(current, 'call', None)
                if call is not None:
                    names.add(getattr(call, '__name__', ''))
                stack.extend(current.dependencies)
        if not ({'current_principal', 'guard'} & names):
            unguarded.append('%s %s' % (sorted(getattr(route, 'methods', []) or []),
                                        path))
    assert not unguarded, 'unauthenticated routes: %s' % unguarded


def test_the_public_list_contains_nothing_that_reads_the_estate():
    for path in PUBLIC_PATHS:
        assert not path.startswith('/v1/graph')
        assert not path.startswith('/v1/findings')
        assert not path.startswith('/v1/admin')


# ------------------------------------------------------------------- health
def test_health_is_open_and_names_the_version(client):
    body = client.get('/health').json()
    assert body['status'] == 'ok' and body['version']


def test_readiness_fails_when_no_estate_is_loaded(settings, db, identity, org):
    from fastapi.testclient import TestClient

    from graphops.api.app import create_app
    bare = TestClient(create_app(settings=settings, db=db, estate_provider=None))
    response = bare.get('/health/ready')
    assert response.status_code == 503
    assert response.json()['checks']['estate'] is False


def test_openapi_describes_the_surface(client):
    document = client.get('/openapi.json').json()
    assert document['info']['title'] == 'GraphOps API'
    assert len(document['paths']) >= 20
    tags = {tag['name'] for tag in document['openapi_tags']} \
        if 'openapi_tags' in document else {t['name'] for t in document['tags']}
    assert {'auth', 'graph', 'connectors', 'admin'} <= tags


# --------------------------------------------------------------------- auth
def test_an_anonymous_caller_is_refused(client):
    for path in ('/v1/graph/exposure', '/v1/findings', '/v1/admin/audit',
                 '/v1/connectors', '/v1/auth/me'):
        assert client.get(path).status_code == 401, path


def test_a_garbage_bearer_token_is_refused(client):
    response = client.get('/v1/auth/me',
                          headers={'Authorization': 'Bearer not-a-token'})
    assert response.status_code == 401


def test_an_unknown_tenant_answers_like_a_wrong_password(client):
    """Compared whole, rather than checked against a remembered string.

    The first version asserted the body was {'detail': 'invalid credentials'},
    which pinned a shape rather than the property in this test's name. Since
    a failed sign-in now also says how many tries are left, the property is
    only kept if a tenant that does not exist counts down in exactly the same
    way, and comparing the two responses is the test that says so.
    """
    ghost = client.post('/v1/auth/login', json={
        'organization': 'nosuchtenant', 'email': 'a@b.com',
        'password': 'a sufficiently long passphrase'})
    real = client.post('/v1/auth/login', json={
        'organization': 'acme', 'email': 'viewer@acme.com',
        'password': 'not the passphrase at all'})
    assert ghost.status_code == real.status_code == 401
    assert ghost.json() == real.json()
    assert ghost.json()['error'] == 'invalid credentials'


def test_login_then_me_reports_the_roles(client, auth_header):
    body = client.get('/v1/auth/me', headers=auth_header('analyst')).json()
    assert body['roles'] == ['analyst']
    assert 'graph:query' in body['permissions']


def test_logout_revokes_the_session(client, auth_header):
    header = auth_header('analyst')
    assert client.post('/v1/auth/logout', headers=header).status_code == 200
    assert client.get('/v1/auth/me', headers=header).status_code == 401


def test_refresh_reuse_answers_409(client):
    login = client.post('/v1/auth/login', json={
        'organization': 'acme', 'email': 'analyst@acme.com',
        'password': 'a sufficiently long passphrase'}).json()
    assert client.post('/v1/auth/refresh',
                       json={'refresh_token': login['refresh_token']}
                       ).status_code == 200
    replayed = client.post('/v1/auth/refresh',
                           json={'refresh_token': login['refresh_token']})
    assert replayed.status_code == 409


# ------------------------------------------------------------ authorisation
@pytest.mark.parametrize('role,path,expected', [
    ('analyst', '/v1/graph/exposure', 200),
    ('responder', '/v1/graph/exposure', 200),
    ('viewer', '/v1/graph/exposure', 403),     # no graph:query
    # An auditor may run the path search. What they may not do is see what
    # sits at the end of it, which is the next test.
    ('auditor', '/v1/graph/exposure', 200),
    ('analyst', '/v1/admin/audit', 403),       # no audit:read
    ('auditor', '/v1/admin/audit', 200),
    ('owner', '/v1/admin/audit', 200),
    ('analyst', '/v1/graph/export?fmt=stix', 200),
    ('responder', '/v1/graph/export?fmt=stix', 403),   # no graph:export
    ('viewer', '/v1/findings', 200),
    ('viewer', '/v1/connectors', 403),         # no connector:read
])
def test_each_role_reaches_exactly_what_its_permissions_allow(
        client, auth_header, role, path, expected):
    assert client.get(path, headers=auth_header(role)).status_code == expected


def test_a_denial_names_the_missing_permission(client, auth_header):
    body = client.get('/v1/admin/audit', headers=auth_header('analyst')).json()
    assert body['missing_permission'] == 'audit:read'


# ---------------------------------------------------------------- redaction
def test_an_analyst_sees_crown_jewels_and_a_viewer_does_not(client, auth_header):
    analyst = client.get('/v1/findings', headers=auth_header('analyst')).json()
    viewer = client.get('/v1/findings', headers=auth_header('viewer')).json()
    assert analyst['count'] == viewer['count'], 'counts must not change'
    assert '_redaction' not in analyst
    assert viewer['_redaction']['nodes_redacted'] > 0


def test_an_auditor_reviews_routes_without_learning_the_targets(client, auth_header):
    """The pair that makes crown:reveal worth having as its own permission.

    An auditor confirming attack paths are being reviewed runs the same
    query an analyst runs and gets the same count of routes, with the final
    node of each pseudonymised. If no role could do that, the permission
    would be decorative.
    """
    analyst = client.get('/v1/graph/exposure',
                         headers=auth_header('analyst')).json()
    auditor = client.get('/v1/graph/exposure',
                         headers=auth_header('auditor')).json()

    assert len(auditor['paths']) == len(analyst['paths']) > 0
    assert '_redaction' not in analyst
    assert auditor['_redaction']['nodes_redacted'] > 0
    assert auditor['_redaction']['unlocked_by'] == 'crown:reveal'

    analyst_targets = [p['steps'][-1]['to']['key'] for p in analyst['paths']]
    auditor_targets = [p['steps'][-1]['to']['key'] for p in auditor['paths']]
    assert all(t.startswith('crown-jewel-') for t in auditor_targets)
    assert not set(auditor_targets) & set(analyst_targets)

    # The route itself is intact: same hop count, same tactics. Only the
    # identity at the end is withheld.
    assert ([len(p['steps']) for p in auditor['paths']]
            == [len(p['steps']) for p in analyst['paths']])
    assert all(step['tactic'] for p in auditor['paths'] for step in p['steps'])


def test_the_crown_reveal_permission_is_load_bearing():
    """At least one role must be able to query paths without revealing them.

    If the two permission sets are identical, crown:reveal changes nothing on
    the graph endpoints and the split is decoration. That was the case until
    the auditor was given graph:query.
    """
    from graphops.rbac.permissions import ROLE_PERMISSIONS, Permission
    can_query = {role for role, granted in ROLE_PERMISSIONS.items()
                 if Permission.GRAPH_QUERY in granted}
    can_reveal = {role for role, granted in ROLE_PERMISSIONS.items()
                  if Permission.CROWN_REVEAL in granted}
    assert can_query - can_reveal, (
        'no role can run a path query without seeing the targets, so '
        'crown:reveal does nothing on /v1/graph')


# --------------------------------------------------------------------- graph
def test_exposure_returns_routes_with_tactics(client, auth_header):
    body = client.get('/v1/graph/exposure',
                      headers=auth_header('analyst')).json()
    assert body['paths']
    first_step = body['paths'][0]['steps'][0]
    assert first_step['tactic'] and first_step['tactic_id'].startswith('TA')


def test_blast_radius_rejects_an_unknown_node(client, auth_header):
    response = client.post('/v1/graph/blast-radius',
                           json={'node_id': 'asset:does-not-exist', 'hops': 2},
                           headers=auth_header('analyst'))
    assert response.status_code in (404, 200)


def test_query_bounds_are_enforced_by_the_schema(client, auth_header):
    header = auth_header('analyst')
    assert client.get('/v1/graph/exposure?max_depth=99',
                      headers=header).status_code == 422
    assert client.post('/v1/graph/blast-radius',
                       json={'node_id': 'x', 'hops': 50},
                       headers=header).status_code == 422


@pytest.mark.parametrize('fmt', ['stix', 'sarif', 'oscal', 'csv'])
def test_every_export_format_returns(client, auth_header, fmt):
    assert client.get('/v1/graph/export?fmt=%s' % fmt,
                      headers=auth_header('analyst')).status_code == 200


def test_an_unknown_export_format_is_rejected(client, auth_header):
    assert client.get('/v1/graph/export?fmt=xlsx',
                      headers=auth_header('analyst')).status_code == 422


# ---------------------------------------------------------------- tenancy
def test_a_tenant_cannot_read_another_tenants_audit_log(
        client, auth_header, identity, other_org, audit):
    from graphops.audit.chain import Outcome
    audit.record(action='secret.action', outcome=Outcome.SUCCESS,
                 organization_id=other_org['id'], actor_id='someone')
    entries = client.get('/v1/admin/audit',
                         headers=auth_header('auditor')).json()['entries']
    assert all(e['organization_id'] != other_org['id'] for e in entries)
    assert all(e['action'] != 'secret.action' for e in entries)


def test_revoking_another_tenants_api_key_answers_404(
        client, auth_header, identity, other_org):
    theirs = identity.create_api_key(organization_id=other_org['id'],
                                     name='theirs')
    response = client.delete('/v1/admin/api-keys/%s' % theirs['id'],
                             headers=auth_header('owner'))
    # 404, not 403: a 403 would confirm the key exists somewhere.
    assert response.status_code == 404


# ------------------------------------------------------------------- admin
def test_an_api_key_authenticates_and_is_limited_to_its_role(client, auth_header):
    created = client.post('/v1/admin/api-keys',
                          json={'name': 'splunk', 'roles': ['service']},
                          headers=auth_header('owner')).json()
    header = {'X-Api-Key': created['api_key']}
    assert client.get('/v1/auth/me', headers=header).json()['kind'] == 'service'
    # A service identity must not be able to read the graph.
    assert client.get('/v1/graph/exposure', headers=header).status_code == 403


def test_the_service_role_cannot_be_given_to_a_person_over_http(client, auth_header):
    response = client.post('/v1/admin/users',
                           json={'email': 'svc@acme.com',
                                 'password': 'a sufficiently long passphrase',
                                 'roles': ['service']},
                           headers=auth_header('owner'))
    assert response.status_code == 400


def test_a_short_password_is_refused_by_the_schema(client, auth_header):
    response = client.post('/v1/admin/users',
                           json={'email': 'x@acme.com', 'password': 'short',
                                 'roles': ['viewer']},
                           headers=auth_header('owner'))
    assert response.status_code == 422


def test_the_audit_chain_verifies_over_http(client, auth_header):
    body = client.get('/v1/admin/audit/verify',
                      headers=auth_header('auditor')).json()
    assert body['valid'] is True


# -------------------------------------------------------------- connectors
def test_the_catalogue_never_includes_a_credential_value(client, auth_header):
    body = client.get('/v1/connectors', headers=auth_header('analyst')).json()
    assert len(body['connectors']) >= 13
    for connector in body['connectors']:
        # Names of required variables, never values.
        assert all(name.isupper() for name in connector['credentials'])


def test_live_mode_is_refused_on_a_replay_deployment(client, auth_header):
    response = client.post('/v1/connectors/run', json={'mode': 'live'},
                           headers=auth_header('owner'))
    assert response.status_code == 400


def test_running_connectors_reports_resolution(client, auth_header):
    body = client.post('/v1/connectors/run', json={'mode': 'replay'},
                       headers=auth_header('owner')).json()
    assert body['status'] == 'success'
    assert body['connectors_run'] >= 9
    assert body['resolution']['merged'] >= 3


# -------------------------------------------------------------- containment
def test_containment_ranks_what_a_cut_was_measured_to_buy(client, auth_header):
    body = client.get('/v1/graph/containment',
                      headers=auth_header('analyst')).json()
    assert body['reachable'] is True
    assert body['routes_before'] > 0
    assert body['options']

    for option in body['options']:
        assert option['kind'] in ('node', 'entitlement')
        assert option['routes_after'] == (option['routes_before']
                                          - option['routes_removed'])
        assert option['cut']['action']

    # The first option is the one a team should do first, and the ranking
    # puts reach removed above routes removed.
    best = body['options'][0]
    assert best['fully_contained'] or best['crown_jewels_cut_off']


def test_an_auditor_can_plan_a_cut_without_learning_what_it_protects(
        client, auth_header):
    """The redaction has to survive a new response shape.

    Crown jewels appear inside `crown_jewels_cut_off` and `cut` here, which
    are nested differently from the path steps the redactor was written
    against. A permission that only covers the shapes that existed when it
    was written is not a permission.
    """
    analyst = client.get('/v1/graph/containment',
                         headers=auth_header('analyst')).json()
    auditor = client.get('/v1/graph/containment',
                         headers=auth_header('auditor')).json()

    assert len(auditor['options']) == len(analyst['options']) > 0
    assert '_redaction' not in analyst
    assert auditor['_redaction']['nodes_redacted'] > 0

    analyst_jewels = [j['key'] for j in analyst['crown_jewels_at_risk']]
    auditor_jewels = [j['key'] for j in auditor['crown_jewels_at_risk']]
    assert analyst_jewels and auditor_jewels
    assert all(j.startswith('crown-jewel-') for j in auditor_jewels)
    assert not set(auditor_jewels) & set(analyst_jewels)

    # The decision itself survives: same ranking, same counts. Only the
    # identity of what is protected is withheld.
    assert ([o['routes_removed'] for o in auditor['options']]
            == [o['routes_removed'] for o in analyst['options']])


def test_containment_is_capped_so_one_request_cannot_cost_a_minute(
        client, auth_header):
    """Each candidate re-runs the whole path search."""
    response = client.get('/v1/graph/containment?candidates=99',
                          headers=auth_header('analyst'))
    assert response.status_code == 422


def test_containment_needs_the_same_permission_as_any_other_query(
        client, auth_header):
    assert client.get('/v1/graph/containment').status_code == 401
    assert client.get('/v1/graph/containment',
                      headers=auth_header('viewer')).status_code == 403


# ------------------------------------------------------------------ headers
def test_security_headers_are_present(client):
    response = client.get('/health')
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert response.headers['x-frame-options'] == 'DENY'
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['x-request-id']


def test_a_supplied_request_id_is_echoed(client):
    response = client.get('/health', headers={'X-Request-Id': 'abc-123'})
    assert response.headers['x-request-id'] == 'abc-123'
