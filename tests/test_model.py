"""The data model carries what the vendors already send.

THE CONNECTORS WERE RECEIVING THIS AND THROWING IT AWAY. Okta's assignment
records say when each grant was last used and whether it came through a
group. CloudTrail names the action an identity took. ServiceNow says which
regulatory regime a system falls under. Entra names the role a membership
grants. All of it arrived in the fixtures, in each vendor's own response
shape, and none of it survived to an answer.

Two separate losses, both tested here:

  * Loading. `Estate.load` kept six fields per node and two per edge.
  * Merging. Two sources reporting the same relationship kept whichever
    arrived first and dropped the other entirely, so CloudTrail's record
    that svc-deploy read the backups disappeared behind Okta's record that
    it signed on, because both describe the same edge.
"""
from __future__ import annotations

import pytest

from graphops import analysis
from graphops.connectors import registry, resolve
from graphops.connectors.base import GraphDelta
from graphops.connectors.itsm import ServiceNowConnector
from graphops.vocab import EdgeKind, NodeKind, Zone


@pytest.fixture(scope='module')
def estate():
    return resolve.resolve(registry.ingest().estate)


def _node(estate, node_id):
    for node in estate['nodes']:
        if node['id'] == node_id:
            return node
    raise AssertionError('no node %r' % node_id)


def _edge(estate, src, dst, kind):
    for edge in estate['edges']:
        if (edge['src'], edge['dst'], edge['kind']) == (src, dst, kind):
            return edge
    raise AssertionError('no %s edge %r -> %r' % (kind, src, dst))


# ------------------------------------------------------------- regulation

def test_a_regulated_system_says_which_regime_it_falls_under(estate):
    """ServiceNow's data_classification, kept as data rather than as a
    suffix on the label where nothing could filter by it."""
    assert _node(estate, 'asset:billing-database')['regimes'] == ['PCI']
    assert _node(estate, 'asset:hr-database')['regimes'] == ['PII']


def test_an_unregulated_system_carries_no_regime(estate):
    order_service = _node(estate, 'asset:order-service')
    assert not order_service.get('regimes')
    assert order_service['classification'] == 'Internal'


def test_a_sensitive_classification_is_not_promoted_to_a_regime():
    """Confidential is a sensitivity level, not a regulation. It still marks
    a crown jewel, and it must not appear in the regime column as though a
    regulator had a view on it."""
    delta = ServiceNowConnector().transform({'items': [
        {'sys_id': 'c1', 'name': 'strategy-docs',
         'data_classification': 'Confidential'}]})
    node = delta.nodes[0]
    assert node['crown'] is True
    assert node['regimes'] == []
    assert node['classification'] == 'Confidential'


# ------------------------------------------------------------ entitlements

def test_an_okta_grant_says_whether_it_came_through_a_group(estate):
    via_group = _edge(estate, 'id:support-desk', 'asset:billing-database',
                      EdgeKind.ENTITLED)
    direct = _edge(estate, 'id:svc-backup', 'svc:s3://nightly-backups',
                   EdgeKind.ENTITLED)
    assert via_group['via'] == 'group'
    assert direct['via'] == 'direct'


def test_an_okta_grant_remembers_when_it_was_last_used(estate):
    """`lastSignOn` on the assignment. A grant that has never been used has
    no value here, and that absence is the over-privilege finding."""
    used = _edge(estate, 'id:svc-deploy', 'svc:s3://nightly-backups',
                 EdgeKind.ENTITLED)
    never = _edge(estate, 'id:support-desk', 'asset:billing-database',
                  EdgeKind.ENTITLED)
    assert used['last_used'] == '2026-11-03T04:00:00Z'
    assert never['last_used'] is None


def test_an_okta_grant_names_what_it_grants(estate):
    grant = _edge(estate, 'id:support-desk', 'asset:billing-database',
                  EdgeKind.ENTITLED)
    assert grant['permission'] == 'Okta app assignment'


def test_an_entra_role_membership_names_the_role_as_the_permission(estate):
    grant = _edge(estate, 'id:ci-pipeline', 'svc:entra/Application Administrator',
                  EdgeKind.ENTITLED)
    assert grant['permission'] == 'Application Administrator'
    assert grant['via'] == 'directory role'


# ---------------------------------------------------------------- actions

def test_cloudtrail_records_the_permission_an_identity_actually_used(estate):
    """`s3:GetObject`, in IAM's own action format, so it can be compared
    against a policy rather than read as prose."""
    use = _edge(estate, 'id:svc-deploy', 'svc:s3://nightly-backups',
                EdgeKind.CALLED)
    assert 's3:GetObject' in use['actions']


def test_a_second_source_for_one_relationship_adds_to_it(estate):
    """The merge bug, at the edge that matters most in the demo.

    Okta reports svc-deploy signing on to the backups and CloudTrail
    reports it reading them. They are the same relationship, so they merge,
    and the merged edge has to keep both rather than whichever came first.
    """
    use = _edge(estate, 'id:svc-deploy', 'svc:s3://nightly-backups',
                EdgeKind.CALLED)
    assert set(use['actions']) >= {'s3:GetObject', 'user.authentication.sso'}
    assert use['sources'] == ['cloudtrail', 'okta']


def test_cloudtrail_says_what_kind_of_principal_acted(estate):
    """An assumed role is a role session, which is the honest answer to
    "is this a person" for an identity only CloudTrail has seen acting."""
    assert _node(estate, 'id:svc-deploy')['principal_type'] == 'role'


def test_every_edge_names_the_connector_that_saw_it(estate):
    for edge in estate['edges']:
        assert edge.get('sources'), edge


# ----------------------------------------------------------- merge rules

def _delta(*edges):
    delta = GraphDelta()
    delta.add_node('a', NodeKind.IDENTITY, 'a', Zone.INTERNAL)
    delta.add_node('b', NodeKind.SERVICE, 'b', Zone.INTERNAL)
    for edge in edges:
        delta.add_edge('a', 'b', EdgeKind.CALLED, edge.pop('first_seen'), **edge)
    return delta


def test_merging_keeps_the_earliest_first_seen_and_the_latest_last_seen():
    early = _delta({'first_seen': '2026-09-01T00:00:00Z',
                    'last_seen': '2026-09-02T00:00:00Z', 'actions': ['x:Read']})
    late = _delta({'first_seen': '2026-10-01T00:00:00Z',
                   'last_seen': '2026-10-05T00:00:00Z', 'actions': ['x:Write']})
    merged = registry.merge([late, early])['edges']
    assert len(merged) == 1
    assert merged[0]['first_seen'] == '2026-09-01T00:00:00Z'
    assert merged[0]['last_seen'] == '2026-10-05T00:00:00Z'
    assert merged[0]['actions'] == ['x:Read', 'x:Write']


def test_merging_keeps_the_cheapest_cost_whichever_source_reported_it():
    dear = _delta({'first_seen': '2026-09-01T00:00:00Z', 'cost': 5.0})
    cheap = _delta({'first_seen': '2026-10-01T00:00:00Z', 'cost': 1.0})
    assert registry.merge([dear, cheap])['edges'][0]['cost'] == 1.0
    assert registry.merge([cheap, dear])['edges'][0]['cost'] == 1.0


def test_resolution_combines_relationships_by_the_same_rules():
    """The same rule in the second place edges are deduplicated. Resolution
    rewrites two edges onto one survivor and used to keep the first."""
    payload = {'nodes': [
        {'id': 'id:a', 'kind': NodeKind.IDENTITY, 'key': 'a',
         'zone': Zone.INTERNAL, 'crown': False},
        {'id': 'svc:s3://bucket', 'kind': NodeKind.SERVICE, 'key': 's3://bucket',
         'zone': Zone.INTERNAL, 'crown': False},
        {'id': 'svc:bucket', 'kind': NodeKind.SERVICE, 'key': 'bucket',
         'zone': Zone.INTERNAL, 'crown': False}],
        'edges': [
            {'src': 'id:a', 'dst': 'svc:s3://bucket', 'kind': EdgeKind.CALLED,
             'cost': 1.0, 'first_seen': '2026-10-01T00:00:00Z',
             'last_seen': '2026-10-01T00:00:00Z', 'actions': ['okta:sso']},
            {'src': 'id:a', 'dst': 'svc:bucket', 'kind': EdgeKind.CALLED,
             'cost': 1.0, 'first_seen': '2026-09-01T00:00:00Z',
             'last_seen': '2026-11-01T00:00:00Z', 'actions': ['s3:GetObject']}]}
    edges = resolve.resolve(payload)['edges']
    assert len(edges) == 1
    assert edges[0]['first_seen'] == '2026-09-01T00:00:00Z'
    assert edges[0]['last_seen'] == '2026-11-01T00:00:00Z'
    assert edges[0]['actions'] == ['okta:sso', 's3:GetObject']


def test_resolution_keeps_every_regime_either_record_carried():
    payload = {'nodes': [
        {'id': 'asset:vault', 'kind': NodeKind.ASSET, 'key': 'vault',
         'zone': Zone.CROWN, 'crown': True, 'regimes': ['PCI'],
         'crown_source': 'servicenow.data_classification'},
        {'id': 'svc:vault', 'kind': NodeKind.SERVICE, 'key': 'vault',
         'zone': Zone.CROWN, 'crown': True, 'regimes': ['PII']}],
        'edges': []}
    survivor = resolve.resolve(payload)['nodes'][0]
    assert survivor['regimes'] == ['PCI', 'PII']


# --------------------------------------------------------------- loading

def test_a_loaded_estate_keeps_every_field_a_source_sent(estate):
    loaded = analysis.Estate(estate).load()
    card_db = loaded.meta['asset:billing-database']
    assert card_db['regimes'] == ['PCI']
    assert card_db['sources'] == ['okta', 'servicenow']
    assert card_db['owner'] == 'finance-ops'


def test_a_loaded_estate_keeps_each_relationship_and_its_attributes(estate):
    """The adjacency map collapses two kinds of edge between one pair into
    one step, which is right for path search. The record of each is kept
    beside it, so a grant and its use stay two facts."""
    loaded = analysis.Estate(estate).load()
    pair = loaded.edges_between[('id:svc-deploy', 'svc:s3://nightly-backups')]
    kinds = {edge['kind'] for edge in pair}
    assert kinds == {EdgeKind.ENTITLED, EdgeKind.CALLED}
    grant = next(edge for edge in pair if edge['kind'] == EdgeKind.ENTITLED)
    assert grant['via'] == 'group'


# ------------------------------------------------------------------ time

def test_a_replay_answers_as_of_the_moment_it_was_recorded(estate):
    """The demo's central finding expired on its own a day after recording.

    `novel_activity` measured its 24-hour window against the real clock, and
    the fixtures' new route is stamped 3 November 04:00 UTC. By the evening
    of 4 November the route had aged out, the finding stopped firing, and
    the finding count only held at 8 because the containment finding had
    been added the same day. A judge running the replay a week later would
    have seen no new activity at all.

    A replay is a recording, so its "now" is when it was recorded. Live mode
    stamps the real time at ingest instead.
    """
    loaded = analysis.Estate(estate)
    assert loaded.as_of is not None
    novel = analysis.novel_activity(loaded)
    assert novel['new_reach_count'] > 0, 'the quiet route has expired again'


def test_a_hand_authored_estate_with_no_recording_time_still_answers():
    from graphops import estate as estate_module
    result = analysis.novel_activity(analysis.Estate(estate_module.build()),
                                     now=estate_module.GENERATED)
    assert result['new_reach_count'] > 0


def test_loading_a_hand_authored_estate_still_works_without_any_of_this():
    """The demo estate predates every field above. Nothing may require them."""
    from graphops import estate as estate_module
    loaded = analysis.Estate(estate_module.build()).load()
    assert loaded.meta and loaded.edges_between
