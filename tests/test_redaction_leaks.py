"""No crown jewel's name reaches a caller who may not know it. Anywhere.

THIS FILE EXISTS BECAUSE THE REDACTION LEAKED. The redactor recognised a
crown jewel only as a dict carrying an id and a crown flag, and masked those.
Every place that rendered a crown jewel's name into a sentence walked past
it. Measured on 4 November against the connector estate:

  /v1/findings              auditor and viewer saw all three names, in
                            titles, `target` and remediation text
  /v1/compliance/controls   auditor saw all three, in evidence titles
  /v1/graph/containment     auditor saw two, in revocation sentences

The per-field tests passed throughout, because they checked the fields the
redactor was written against and never looked at the strings. So the
guarantee here is stated as the thing that actually matters: serialise the
whole response and search it for every name the crown jewel goes by. And it
walks the route table rather than listing endpoints, so a route added next
month is covered the day it is written.
"""
from __future__ import annotations

import json

import pytest

from graphops.connectors.resolve import normalise_key
from graphops.rbac.permissions import ROLE_PERMISSIONS, Permission
from tests.test_api import walk_routes

#: Roles that hold a graph or findings permission without crown:reveal.
#: Computed rather than listed, so a role granted reveal later drops out of
#: this test instead of failing it, and a new role without reveal joins it.
BLIND_ROLES = sorted(
    role.value for role, granted in ROLE_PERMISSIONS.items()
    if Permission.CROWN_REVEAL not in granted
    and role.value != 'service')


def crown_names(estate) -> set[str]:
    """Every string a crown jewel is known by in the estate."""
    names: set[str] = set()
    for node in estate.nodes:
        if not node.get('crown'):
            continue
        for field in ('id', 'key', 'label', 'arn'):
            if node.get(field):
                names.add(str(node[field]))
        for alias in node.get('resolved_from') or []:
            names.add(str(alias))
        normalised = normalise_key(node.get('key', ''))
        if normalised:
            names.add(normalised)
    # A name this short would match ordinary words and make the test
    # meaningless rather than strict. None of the estate's are this short.
    return {name for name in names if len(name) >= 4}


def _calls():
    """Every GET a blind role could make with no path parameter."""
    from graphops.api.app import create_app
    from graphops.config import load_settings
    from graphops.store.db import Database

    database = Database(':memory:')
    try:
        app = create_app(settings=load_settings(), db=database,
                         estate_provider=lambda: None)
        paths = sorted({route.path for route in walk_routes(app)
                        if 'GET' in (getattr(route, 'methods', None) or set())
                        and '{' not in route.path
                        and route.path.startswith('/v1/')})
    finally:
        database.close()
    return paths


@pytest.mark.parametrize('role', BLIND_ROLES)
@pytest.mark.parametrize('path', _calls())
def test_no_route_names_a_crown_jewel_to_a_role_without_reveal(
        client, auth_header, connector_estate, role, path):
    names = crown_names(connector_estate)
    assert names, 'the estate has no crown jewels, so this test proves nothing'

    response = client.get(path, headers=auth_header(role))
    if response.status_code in (401, 403, 404, 422):
        return      # nothing returned, so nothing to leak
    body = json.dumps(response.json())
    leaked = sorted(name for name in names if name in body)
    assert not leaked, '%s %s leaked %s' % (role, path, leaked)


@pytest.mark.parametrize('role', BLIND_ROLES)
def test_blast_radius_names_no_crown_jewel_it_reaches(
        client, auth_header, connector_estate, role):
    names = crown_names(connector_estate)
    response = client.post('/v1/graph/blast-radius',
                           json={'node_id': 'id:support-desk', 'hops': 3},
                           headers=auth_header(role))
    if response.status_code in (401, 403):
        return
    body = json.dumps(response.json())
    leaked = sorted(name for name in names if name in body)
    assert not leaked, '%s blast radius leaked %s' % (role, leaked)


def test_the_blind_roles_are_the_ones_the_product_says_they_are():
    """If this changes, the threat model's description of who sees what has
    to change with it."""
    assert 'auditor' in BLIND_ROLES
    assert 'viewer' in BLIND_ROLES


# --------------------------------------------------------- the scrub itself

class _Estate:
    """Just enough estate for the redactor: nodes, and room for its cache."""

    def __init__(self, nodes):
        self.nodes = nodes


def _blind_principal():
    from graphops.rbac.permissions import Role
    from graphops.rbac.principal import Principal
    return Principal(subject='u1', organization='org-a', roles=(Role.AUDITOR,),
                     kind='user')


def _redactor(nodes):
    from graphops.rbac.policy import Redactor
    return Redactor(_blind_principal(), salt=b'salt', estate=_Estate(nodes))


_CARD_DB = {'id': 'asset:billing-database', 'key': 'billing-database',
            'label': 'billing-database (PCI)', 'crown': True,
            'arn': 'arn:aws:rds:ap-south-1:000000000000:db:billing-database',
            'owner': 'finance-ops', 'environment': 'Production',
            'resolved_from': ['svc:billing-database'], 'regimes': ['PCI']}
_BACKUPS = {'id': 'svc:s3://nightly-backups', 'key': 's3://nightly-backups',
            'label': 's3://nightly-backups', 'crown': True}


def test_a_sentence_and_the_node_beside_it_carry_the_same_pseudonym():
    """Otherwise an auditor reading "revoke ... on crown-jewel-ab12" cannot
    tell which of the masked nodes on the same screen it means."""
    redactor = _redactor([_CARD_DB])
    masked = redactor.node(dict(_CARD_DB))
    sentence = redactor.scrub("revoke support-desk's grant on billing-database")
    assert masked['key'] in sentence
    assert 'billing-database' not in sentence


def test_the_longer_name_is_replaced_whole():
    """Two names starting at the same character, and the longer must win.

    A regex engine takes the leftmost match, so order among alternatives
    only matters when two of them start at the same position. The first
    version of this test used `s3://nightly-backups`, where only the long
    name can start at the `s`, and it passed with the order reversed. Two
    crown jewels called `billing` and `billing-database` are the case that
    actually depends on it: shortest first leaves `-database` behind.
    """
    billing = {'id': 'asset:billing', 'key': 'billing', 'label': 'billing',
               'crown': True}
    card_db = {'id': 'asset:billing-database', 'key': 'billing-database',
               'label': 'billing-database', 'crown': True}
    redactor = _redactor([billing, card_db])
    out = redactor.scrub('a route ends at billing-database today')
    assert 'database' not in out, out
    assert redactor.node(dict(card_db))['key'] in out

    backups = dict(_BACKUPS, resolved_from=['svc:nightly-backups'])
    out = _redactor([backups]).scrub('route ends at s3://nightly-backups')
    assert 's3://' not in out
    assert 'nightly-backups' not in out


def test_a_name_is_found_however_it_is_cased():
    redactor = _redactor([_CARD_DB])
    assert 'billing' not in redactor.scrub('Billing-Database is reachable').lower()


def test_a_name_inside_another_identifier_is_left_alone_only_when_it_is_part_of_a_word():
    """`hr` must not be found inside `three`. A hyphen is not part of a word,
    so a crown name followed by `-replica` is still replaced: over-redacting
    a neighbour is the safe direction."""
    hr = {'id': 'asset:hr', 'key': 'hr', 'label': 'hr', 'crown': True}
    redactor = _redactor([hr])
    assert redactor.scrub('three routes') == 'three routes'
    assert 'hr' not in redactor.scrub('reaches hr today').split()


def test_a_masked_crown_jewel_keeps_nothing_that_would_identify_it():
    """The ARN carries the name, the owner narrows it to one system for
    anyone who knows the business, and `resolved_from` lists the other
    names it was known by. The regime stays: an auditor checking PCI scope
    needs to know a reachable system holds card data, not which one."""
    masked = _redactor([_CARD_DB]).node(dict(_CARD_DB))
    for field in ('arn', 'owner', 'environment', 'resolved_from'):
        assert field not in masked, field
    assert masked['regimes'] == ['PCI']
    assert 'billing' not in json.dumps(masked)


def test_a_role_that_may_reveal_gets_the_text_untouched():
    from graphops.rbac.permissions import Role
    from graphops.rbac.policy import Redactor
    from graphops.rbac.principal import Principal
    analyst = Principal(subject='u2', organization='org-a',
                        roles=(Role.ANALYST,), kind='user')
    redactor = Redactor(analyst, salt=b'salt', estate=_Estate([_CARD_DB]))
    text = 'support-desk may reach billing-database'
    assert redactor.walk({'title': text}) == {'title': text}


def test_every_role_that_can_export_can_also_reveal():
    """An export is a file that leaves the product. It is not redacted on the
    way out, so only a role that may already see the names may make one."""
    for role, granted in ROLE_PERMISSIONS.items():
        if Permission.GRAPH_EXPORT in granted:
            assert Permission.CROWN_REVEAL in granted, role.value
