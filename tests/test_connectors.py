"""Connectors, entity resolution and the merged estate."""
from __future__ import annotations

import pytest

from graphops.connectors import registry, resolve
from graphops.connectors.base import (
    MODE_LIVE,
    GraphDelta,
    MissingCredentials,
    OutboundConnector,
)
from graphops.connectors.outbound import PagerDutyConnector, SlackConnector, summarise
from graphops.connectors.resolve import normalise_key
from graphops.vocab import EdgeKind


# -------------------------------------------------------------- the contract
def test_every_connector_declares_its_identity():
    for key, cls in registry.CONNECTORS.items():
        assert cls.key == key
        assert cls.vendor and cls.product and cls.category
        assert cls.direction in ('inbound', 'outbound')
        assert cls.api_reference.startswith('http'), key


def test_every_inbound_connector_ships_a_fixture():
    """Replay is the default, so a missing fixture is a broken default."""
    for key in registry.INBOUND:
        connector = registry.build(key)
        assert connector.fixture_path().exists(), key


def test_live_mode_refuses_to_start_without_credentials():
    for key, cls in registry.INBOUND.items():
        if not cls.required_credentials:
            continue
        with pytest.raises(MissingCredentials):
            registry.build(key, mode=MODE_LIVE)


def test_live_mode_never_falls_back_to_the_fixture():
    """A connector serving stale fixture data on an expired token is worse
    than one that fails loudly."""
    connector = registry.build('okta', mode=MODE_LIVE, credentials={
        'OKTA_DOMAIN': 'https://127.0.0.1:1', 'OKTA_API_TOKEN': 'x'})
    result, delta = connector.run()
    assert result.status == 'failed'
    assert len(delta) == 0


def test_a_connector_parsing_failure_does_not_raise():
    class Broken(registry.CONNECTORS['splunk']):
        key = 'splunk'

        def transform(self, payload):
            raise ValueError('vendor changed a field name')

    result, delta = Broken(mode='replay').run()
    assert result.status == 'failed'
    assert 'vendor changed a field name' in result.error
    assert len(delta) == 0


# ------------------------------------------------------------------ ingest
def test_every_inbound_connector_runs_and_produces_a_graph():
    result = registry.ingest()
    assert result.status == 'success'
    assert len(result.runs) == len(registry.INBOUND)
    assert all(run.status == 'success' for run in result.runs)
    assert result.estate['nodes'] and result.estate['edges']


def test_one_failing_connector_does_not_fail_the_ingest():
    result = registry.ingest(['splunk', 'okta', 'not-a-connector'])
    assert result.status == 'degraded'
    assert len(result.failures) == 1
    assert result.estate['nodes'], 'the other two must still have landed'


def test_a_repeated_relationship_becomes_one_edge():
    delta = GraphDelta()
    delta.add_edge('a', 'b', EdgeKind.REQUESTED, '2026-01-01', cost=3.0)
    delta.add_edge('a', 'b', EdgeKind.REQUESTED, '2026-01-02', cost=1.0)
    merged = registry.merge([delta])
    edges = [e for e in merged['edges'] if e['src'] == 'a' and e['dst'] == 'b']
    assert len(edges) == 1
    assert edges[0]['cost'] == 1.0, 'the cheapest route is the one that counts'


def test_an_edge_naming_an_undescribed_node_creates_a_placeholder():
    delta = GraphDelta()
    delta.add_edge('ghost', 'other', EdgeKind.SERVES, '2026-01-01')
    merged = registry.merge([delta])
    ghost = next(n for n in merged['nodes'] if n['id'] == 'ghost')
    assert ghost['inferred'] is True


# ------------------------------------------------------- entity resolution
@pytest.mark.parametrize('raw,expected', [
    ('s3://nightly-backups', 'nightly-backups'),
    ('arn:aws:s3:::nightly-backups', 'nightly-backups'),
    ('arn:aws:sts::000000000000:assumed-role/svc-deploy', 'svc-deploy'),
    ('storefront-web.internal.invalid', 'storefront-web'),
    ('Billing-Database', 'billing-database'),
    ('https://example.invalid/app', 'app'),
])
def test_names_for_one_thing_normalise_alike(raw, expected):
    assert normalise_key(raw) == expected


def test_resolution_joins_the_same_system_across_sources():
    merged = registry.ingest().estate
    resolved = resolve.resolve(merged)
    assert resolved['resolution']['merged'] >= 3
    keys = {n['id'] for n in resolved['nodes']}
    assert 'svc:billing-database' not in keys
    assert 'asset:billing-database' in keys


def test_an_identity_and_a_system_with_one_name_never_merge():
    """Over-merging is the worse failure; classes are never compared."""
    from graphops.vocab import NodeKind, Zone
    estate = {'nodes': [
        {'id': 'id:backup', 'kind': NodeKind.IDENTITY, 'key': 'backup',
         'zone': Zone.INTERNAL, 'crown': False},
        {'id': 'svc:backup', 'kind': NodeKind.SERVICE, 'key': 'backup',
         'zone': Zone.INTERNAL, 'crown': False},
    ], 'edges': []}
    assert resolve.resolve(estate)['resolution']['merged'] == 0


def test_a_stated_classification_beats_an_inferred_one():
    resolved = resolve.resolve(registry.ingest().estate)
    billing = next(n for n in resolved['nodes']
                   if n['id'] == 'asset:billing-database')
    assert billing['crown'] is True
    assert billing['crown_source'] == 'servicenow.data_classification'
    assert 'okta' in billing['sources'] and 'servicenow' in billing['sources']


def test_resolution_records_what_it_joined():
    resolved = resolve.resolve(registry.ingest().estate)
    billing = next(n for n in resolved['nodes']
                   if n['id'] == 'asset:billing-database')
    assert 'svc:billing-database' in billing['resolved_from']


def test_resolution_lets_an_entitlement_reach_a_crown_jewel():
    """The whole point. Before resolution this query returns nothing."""
    resolved = resolve.resolve(registry.ingest().estate)
    crowns = {n['id'] for n in resolved['nodes'] if n.get('crown')}
    reaching = [e for e in resolved['edges']
                if e['kind'] == EdgeKind.ENTITLED and e['dst'] in crowns]
    assert reaching, 'entitlements must reach the resolved crown jewels'
    assert any(e['src'] == 'id:support-desk' for e in reaching)


# ---------------------------------------------------------------- outbound
def test_an_outbound_body_withholds_the_target_by_default():
    finding = {'id': 'f1', 'title': 'x', 'severity': 'critical',
               'target': 'billing-database', 'routes': 3,
               'fingerprint': 'abc'}
    assert summarise(finding)['target'] == 'a crown jewel'
    assert summarise(finding, include_crown=True)['target'] == 'billing-database'


def test_delivering_twice_with_one_key_sends_once():
    connector = SlackConnector(mode='replay')
    finding = {'id': 'f1', 'title': 'x', 'severity': 'high', 'routes': 2,
               'fingerprint': 'abc', 'target': 'billing-database'}
    first = connector.deliver(finding, idempotency_key='k1')
    second = connector.deliver(finding, idempotency_key='k1')
    assert first['delivered'] and second.get('deduplicated')
    assert len(connector.sent) == 1


def test_pagerduty_refuses_anything_below_critical():
    connector = PagerDutyConnector(mode='replay')
    for severity in ('high', 'medium', 'low'):
        result = connector.deliver({'severity': severity, 'target': 'x'},
                                   idempotency_key='k')
        assert not result['delivered'], severity
    assert connector.deliver({'severity': 'critical', 'target': 'x',
                              'title': 't', 'fingerprint': 'f'},
                             idempotency_key='k')['delivered']


def test_outbound_connectors_contribute_nothing_to_the_graph():
    for key, cls in registry.OUTBOUND.items():
        assert issubclass(cls, OutboundConnector)
        result, delta = registry.build(key).run()
        assert len(delta) == 0, key


# ---------------------------------------------------------------- url guard
@pytest.mark.parametrize('url', [
    'file:///etc/passwd',
    'ftp://example.invalid/x',
    'gopher://example.invalid/',
    '/etc/passwd',
    '',
])
def test_a_connector_refuses_a_non_http_url(url):
    """urlopen honours file: and ftp:, so a connector URL must be checked.

    These URLs reach the HTTP helpers from environment variables and, for
    the webhook connectors, from tenant configuration.
    """
    from graphops.connectors.base import ConnectorError, require_http_url
    with pytest.raises(ConnectorError):
        require_http_url(url, 'test')


@pytest.mark.parametrize('url', [
    'https://example.invalid/api',
    'http://127.0.0.1:8000/x',
])
def test_an_http_url_is_allowed(url):
    from graphops.connectors.base import require_http_url
    assert require_http_url(url, 'test') == url


def test_an_outbound_webhook_refuses_a_file_url():
    """A tenant-supplied webhook URL must not be able to name a local file."""
    from graphops.connectors.base import ConnectorError
    connector = SlackConnector(mode=MODE_LIVE,
                               credentials={'SLACK_WEBHOOK_URL': 'file:///etc/passwd'})
    with pytest.raises(ConnectorError, match='only http and https'):
        connector.deliver({'severity': 'high', 'title': 't',
                           'fingerprint': 'f', 'routes': 1},
                          idempotency_key='k1')
