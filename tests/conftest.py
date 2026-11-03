"""Shared fixtures.

Every fixture is function-scoped and builds against an in-memory database,
so no test can see another's state. That costs a few milliseconds per test
and removes the whole class of failures where a suite passes in order and
fails shuffled.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Set before anything imports config. A real key is required by design, and
#: the test suite supplies its own rather than relying on a default, because
#: the absence of a default is the property being preserved.
os.environ.setdefault('GRAPHOPS_SIGNING_KEY', 'test-signing-key-' + 'x' * 32)


@pytest.fixture
def settings():
    from graphops.config import load_settings
    return load_settings()


@pytest.fixture
def db():
    from graphops.store.db import Database
    database = Database(':memory:')
    yield database
    database.close()


@pytest.fixture
def audit(db):
    from graphops.audit.chain import AuditLog
    return AuditLog(db)


@pytest.fixture
def identity(db, settings, audit):
    from graphops.identity.service import IdentityService
    return IdentityService(db, settings, audit)


@pytest.fixture
def org(identity):
    return identity.create_organization(slug='acme', name='Acme Ltd')


@pytest.fixture
def other_org(identity):
    return identity.create_organization(slug='globex', name='Globex')


@pytest.fixture
def users(identity, org):
    """One user per assignable role, with a known password."""
    from graphops.rbac.permissions import ASSIGNABLE_ROLES
    made = {}
    for role in sorted(ASSIGNABLE_ROLES, key=lambda r: r.value):
        made[role.value] = identity.create_user(
            organization_id=org['id'],
            email='%s@acme.com' % role.value,
            password='a sufficiently long passphrase',
            roles=[role])
    return made


@pytest.fixture
def principal_factory(identity, org, users):
    def make(role: str):
        session = identity.authenticate(
            organization_id=org['id'], email='%s@acme.com' % role,
            password='a sufficiently long passphrase')
        return identity.principal_for_token(session['access_token'])
    return make


@pytest.fixture(scope='session')
def connector_estate():
    """The estate assembled from every connector fixture, resolved."""
    from graphops import analysis
    from graphops.connectors import registry, resolve
    return analysis.Estate(resolve.resolve(registry.ingest().estate))


@pytest.fixture(scope='session')
def synthetic_estate():
    """The hand-authored estate the engine demo uses."""
    from graphops import analysis
    from graphops import estate as estate_module
    return analysis.Estate(estate_module.build())


@pytest.fixture
def app(settings, db, identity, org, users, connector_estate):
    from graphops.api.app import create_app
    return create_app(settings=settings, db=db,
                      estate_provider=lambda: connector_estate)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture
def auth_header(client):
    """Log in as a role and return the Authorization header."""
    def make(role: str = 'analyst'):
        response = client.post('/v1/auth/login', json={
            'organization': 'acme', 'email': '%s@acme.com' % role,
            'password': 'a sufficiently long passphrase'})
        assert response.status_code == 200, response.text
        return {'Authorization': 'Bearer %s' % response.json()['access_token']}
    return make
