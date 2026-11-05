"""Every connector's live path, run over real HTTP.

Until 5 November 2026 no live path had ever run. Replay handed each parser a
fixture shaped to fit it, and checked against the vendors' documentation most
of the live code was wrong: a decommissioned CrowdStrike API, an Okta field
that does not exist, a Tenable endpoint without the data needed, and three
connectors that never exchanged their client credentials for a token.

So this starts a real HTTP server on 127.0.0.1 that answers each vendor's
documented responses, the same recordings replay uses, and runs every
connector in live mode against it. The server checks each request carries
that vendor's documented authentication, and refuses anything else.

What this proves: the URLs, query parameters, request bodies, auth headers,
token exchanges, multi-step joins and paging logic all work over real HTTP,
and produce exactly the graph replay produces. What it cannot prove: that a
real vendor tenant answers as documented. The recordings were checked
against each vendor's own documentation, cited on every connector as
`api_reference`, not captured from a tenant.
"""
from __future__ import annotations

import base64
import gzip
import json
import threading
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from graphops.connectors import registry, resolve
from graphops.connectors.base import Connector, _query_of

RECORDED = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
HTTP_VENDORS = [k for k in registry.INBOUND if k != 'cloudtrail']


def _basic(user, password):
    return 'Basic ' + base64.b64encode(('%s:%s' % (user, password)).encode()).decode()


#: The credentials each live connector is given, and the auth its vendor
#: documents. A token endpoint is checked separately, by its form body.
SECRETS = {
    'splunk': ({'SPLUNK_TOKEN': 't-splunk'}, {'authorization': 'Bearer t-splunk'}),
    'okta': ({'OKTA_API_TOKEN': 't-okta'}, {'authorization': 'SSWS t-okta'}),
    'crowdstrike': ({'FALCON_CLIENT_ID': 'cid', 'FALCON_CLIENT_SECRET': 'csecret'},
                    {'authorization': 'Bearer replay-token'}),
    'sentinel': ({'AZURE_TENANT_ID': 'replay', 'AZURE_CLIENT_ID': 'cid',
                  'AZURE_CLIENT_SECRET': 'csecret'}, {'authorization': 'Bearer replay-token'}),
    'entra': ({'AZURE_TENANT_ID': 'replay', 'AZURE_CLIENT_ID': 'cid',
               'AZURE_CLIENT_SECRET': 'csecret'}, {'authorization': 'Bearer replay-token'}),
    'qualys': ({'QUALYS_USERNAME': 'qu', 'QUALYS_PASSWORD': 'qp'},
               {'authorization': _basic('qu', 'qp'), 'x-requested-with': 'GraphOps'}),
    'tenable': ({'TENABLE_ACCESS_KEY': 'ak', 'TENABLE_SECRET_KEY': 'sk'},
                {'x-apikeys': 'accessKey=ak;secretKey=sk'}),
    'servicenow': ({'SERVICENOW_USERNAME': 'su', 'SERVICENOW_PASSWORD': 'sp'},
                   {'authorization': _basic('su', 'sp')}),
}


def _recording(key):
    return registry.build(key).load_fixture()


class VendorServer:
    """Answers each vendor's recorded exchanges, under /<connector key>."""

    def __init__(self, expected_auth=None):
        self.recordings = {key: _recording(key)['exchanges'] for key in HTTP_VENDORS}
        self.used = {key: set() for key in HTTP_VENDORS}
        self.violations: list[str] = []
        self.expected_auth = expected_auth or {k: v[1] for k, v in SECRETS.items()}
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, method):
                parsed = urllib.parse.urlparse(self.path)
                key, _, rest = parsed.path.lstrip('/').partition('/')
                if key not in server.recordings:
                    return self._send(404, '{}')
                path = '/' + rest
                length = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(length).decode('utf-8') if length else ''
                is_token = path.endswith('/oauth2/token') or path.endswith('/oauth2/v2.0/token')
                if is_token:
                    form = urllib.parse.parse_qs(raw)
                    if 'x-www-form-urlencoded' not in (self.headers.get('Content-Type') or '') \
                            or form.get('client_id') != ['cid'] or form.get('client_secret') != ['csecret']:
                        server.violations.append('%s token request malformed' % key)
                        return self._send(401, '{"error": "invalid_client"}')
                else:
                    for header, value in server.expected_auth[key].items():
                        if self.headers.get(header) != value:
                            server.violations.append('%s %s sent %s=%r' % (key, path, header,
                                                                           self.headers.get(header)))
                            return self._send(401, '{"error": "unauthorized"}')
                body = json.loads(raw) if raw and not is_token else None
                query = _query_of(self.path)
                for index, exchange in enumerate(server.recordings[key]):
                    request = exchange['request']
                    if request['method'] != method or request['path'] != path:
                        continue
                    if request.get('query', {}) != query:
                        continue
                    if 'body' in request and request['body'] != body:
                        continue
                    server.used[key].add(index)
                    reply = exchange['response']
                    text = reply['text'] if 'text' in reply else json.dumps(reply.get('body'))
                    return self._send(int(reply.get('status', 200)), text)
                server.violations.append('%s asked for %s %s %s, which is not documented here'
                                         % (key, method, path, query))
                return self._send(404, '{}')

            def _send(self, status, text):
                payload = text.encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self._answer('GET')

            def do_POST(self):
                self._answer('POST')

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base = 'http://127.0.0.1:%d' % self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _credentials(base, tmp_path, secrets=None):
    secrets = secrets or {k: v[0] for k, v in SECRETS.items()}
    sentinel_ws = registry.CONNECTORS['sentinel'].replay_settings['SENTINEL_WORKSPACE_ID']
    hosts = {
        'splunk': {'SPLUNK_HOST': base + '/splunk'},
        'okta': {'OKTA_DOMAIN': base + '/okta'},
        'crowdstrike': {'FALCON_BASE_URL': base + '/crowdstrike'},
        'sentinel': {'AZURE_LOGIN_URL': base + '/sentinel', 'AZURE_MANAGEMENT_URL': base + '/sentinel',
                     'SENTINEL_WORKSPACE_ID': sentinel_ws},
        'entra': {'AZURE_LOGIN_URL': base + '/entra', 'GRAPH_URL': base + '/entra'},
        'qualys': {'QUALYS_API_URL': base + '/qualys'},
        'tenable': {'TENABLE_BASE_URL': base + '/tenable'},
        'servicenow': {'SERVICENOW_INSTANCE': base + '/servicenow'},
    }
    creds = {key: dict(hosts[key], **secrets[key]) for key in HTTP_VENDORS}
    # CloudTrail is read from delivered log files, as a synced S3 bucket.
    logs = tmp_path / 'cloudtrail'
    logs.mkdir()
    for entry in _recording('cloudtrail')['files']:
        with gzip.open(logs / entry['name'], 'wt', encoding='utf-8') as handle:
            json.dump(entry['content'], handle)
    creds['cloudtrail'] = {'CLOUDTRAIL_LOG_DIR': str(logs)}
    return creds


@pytest.fixture
def frozen_clock(monkeypatch):
    """Live mode reads the clock to ask for the last 90 days of sign-ons.
    Tests never read the real clock, so it is the recording's moment."""
    monkeypatch.setattr(Connector, 'now', lambda self: RECORDED)


def _signature(estate):
    nodes = sorted((n['id'], n['kind'], bool(n.get('crown')), tuple(n.get('regimes') or ()))
                   for n in estate['nodes'])
    edges = sorted((e['src'], e['dst'], e['kind'], e.get('first_seen') or '', e.get('cost'),
                    e.get('last_used') or '', e.get('via') or '') for e in estate['edges'])
    return nodes, edges


def test_every_live_path_runs_over_http_and_builds_the_replay_graph(frozen_clock, tmp_path):
    with VendorServer() as server:
        live = registry.ingest(mode='live', credentials=_credentials(server.base, tmp_path))
    assert not server.violations, server.violations
    failed = {run.connector: run.error for run in live.runs if run.status != 'success'}
    assert not failed, failed
    replay = registry.ingest()
    assert _signature(resolve.resolve(live.estate)) == _signature(resolve.resolve(replay.estate))


def test_every_recorded_exchange_is_one_the_live_path_asks_for(frozen_clock, tmp_path):
    """A recorded response nobody requests is documentation the code has
    drifted away from."""
    with VendorServer() as server:
        registry.ingest(mode='live', credentials=_credentials(server.base, tmp_path))
    for key in HTTP_VENDORS:
        unused = [server.recordings[key][i]['request'] for i in range(len(server.recordings[key]))
                  if i not in server.used[key]]
        assert not unused, (key, unused)


def test_replay_runs_the_same_requests_and_uses_every_one():
    for key in HTTP_VENDORS:
        connector = registry.build(key)
        result, _delta = connector.run()
        assert result.status == 'success', (key, result.error)
        assert connector.transport.unused() == [], key


@pytest.mark.parametrize('key', HTTP_VENDORS)
def test_wrong_credentials_fail_loudly_and_never_fall_back(frozen_clock, tmp_path, key):
    secrets = {k: dict(v[0]) for k, v in SECRETS.items()}
    for name in secrets[key]:
        if name != 'AZURE_TENANT_ID':
            secrets[key][name] = 'wrong'
    with VendorServer() as server:
        connector = registry.build(key, mode='live',
                                   credentials=_credentials(server.base, tmp_path, secrets)[key])
        result, delta = connector.run()
    assert result.status == 'failed'
    assert 'HTTP 401' in result.error
    assert len(delta) == 0


def test_a_request_the_recording_does_not_hold_is_an_error_not_an_empty_answer():
    connector = registry.build('okta')
    with pytest.raises(Exception) as caught:
        connector.request('GET', 'https://okta.replay.invalid/api/v1/groups')
    assert 'recording does not hold' in str(caught.value)


def test_qualys_refuses_xml_that_declares_entities():
    from graphops.connectors.vulnerability import _parse_xml
    bomb = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">'
            '<!ENTITY b "&a;&a;&a;&a;">]><x>&b;</x>')
    with pytest.raises(Exception) as caught:
        _parse_xml(bomb, 'qualys')
    assert 'entities' in str(caught.value)


def test_okta_follows_a_link_header_to_the_next_page(monkeypatch):
    """Okta pages with RFC 8288 Link headers. A tenant with more users than
    one page would otherwise lose everyone after the first 200."""
    connector = registry.build('okta')
    pages = {'/api/v1/users?limit=200': ([{'id': 'u1'}], '<https://x/api/v1/users?after=u1>; rel="next"'),
             '/api/v1/users?after=u1': ([{'id': 'u2'}], '')}

    def fake(method, url, **kwargs):
        parsed = urllib.parse.urlparse(url)
        body, link = pages[parsed.path + '?' + parsed.query]
        return body, {'link': link} if link else {}
    monkeypatch.setattr(connector, 'request_full', fake)
    assert [u['id'] for u in connector.follow('https://x/api/v1/users?limit=200', headers={})] == ['u1', 'u2']


def test_a_grant_older_than_the_use_log_is_idle_for_at_least_the_log_not_never_used():
    """Okta's System Log covers 90 days. No sign-on in it, for a grant made
    before it began, is 'not used in at least 90 days', not 'never used'."""
    from graphops import analysis
    from graphops.vocab import EdgeKind, NodeKind, Zone
    estate = analysis.Estate({'as_of': '2026-11-03T09:00:00Z', 'nodes': [
        {'id': 'id:a', 'kind': NodeKind.IDENTITY, 'key': 'a', 'zone': Zone.INTERNAL, 'crown': False},
        {'id': 'svc:b', 'kind': NodeKind.SERVICE, 'key': 'b', 'zone': Zone.CROWN, 'crown': True}],
        'edges': [{'src': 'id:a', 'dst': 'svc:b', 'kind': EdgeKind.ENTITLED, 'cost': 1.0,
                   'first_seen': '2025-01-01T00:00:00Z', 'last_used': None,
                   'usage_since': '2026-08-05T09:00:00.000Z'}]})
    grant = analysis.over_privilege(estate)['grants'][0]
    assert grant['status'] == 'idle'
    assert grant['idle_at_least'] is True
    assert grant['idle_days'] == 90
    # A log shorter than the idle threshold cannot say either way. The
    # first version of this rule called that case "used".
    shorter = analysis.over_privilege(estate, idle_days=120)['grants'][0]
    assert shorter['status'] == 'unknown'


def test_crowdstrike_asks_for_alerts_not_the_decommissioned_detects_api():
    paths = [e['request']['path'] for e in _recording('crowdstrike')['exchanges']]
    assert not any(path.startswith('/detects/') for path in paths)
    assert '/alerts/entities/alerts/v2' in paths
