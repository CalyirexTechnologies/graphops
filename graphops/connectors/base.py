"""The connector contract.

A connector is the only thing in the platform that knows what a vendor's
payload looks like. Everything downstream sees nodes and edges from
`graphops.vocab`, which is why adding CrowdStrike does not touch the engine,
the API or the viewer.

Two directions, kept apart because they fail differently:

  * **inbound** pulls telemetry and returns a `GraphDelta`. A failure means
    stale data, so it retries and the run is recorded as degraded.
  * **outbound** pushes a finding to a human system (a ticket, a channel, a
    page). A failure means nobody was told, so it is loud, and it is
    idempotent on a caller-supplied key because the alternative is paging
    somebody four times for one finding.

Two modes, ONE CODE PATH:

  * **live** sends real HTTP to the vendor.
  * **replay**, the default, runs exactly the same requests against a
    recording. Every connector ships one, so the whole pipeline runs with no
    vendor account, no API key and no network.

The only difference between the two is the transport. Every replay therefore
exercises the live code: the endpoints called, their order, the query
parameters, the request bodies and the parsing. A request the recording does
not hold fails loudly rather than returning nothing, so the recording and
the code cannot drift apart unnoticed.

THIS WAS NOT TRUE BEFORE 5 NOVEMBER 2026, AND THE GAP WAS LARGE. Replay used
to hand each connector a fixture shaped to fit its parser, and the live path
was separate code that nothing ran. Checked against each vendor's own
documentation, most of those live paths were wrong: CrowdStrike called the
Detects API, decommissioned on 30 September 2025; Okta read a per-user
`appAssignments[].lastSignOn` that no Okta endpoint returns; Tenable's
workbench carries neither affected assets nor CVEs; Sentinel's entities are a
separate call per incident; Splunk read a saved search's job history as
though it were its results; Qualys asked for JSON from an API that returns
XML. And three connectors named client credentials they never exchanged for
a token. Each recording is now the documented responses to the documented
calls, and `tests/test_live_paths.py` runs every live path over real HTTP
against a local server that serves them and checks each vendor's auth scheme.

The recordings are synthetic records in each vendor's documented response
shape, not captures from anyone's tenant. Live mode refuses to start without
its credentials rather than falling back to the recording. A connector that
silently served recorded data when a token expired would be worse than one
that fails.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent / 'fixtures'

MODE_REPLAY = 'replay'
MODE_LIVE = 'live'


class ConnectorError(Exception):
    pass


class MissingCredentials(ConnectorError):
    """Live mode was asked for without the credentials it needs."""


#: The only schemes a connector may fetch over.
ALLOWED_SCHEMES = frozenset({'http', 'https'})


def require_http_url(url: str, connector_key: str = '') -> str:
    """Refuse anything but http and https before opening it.

    `urlopen` honours `file:`, `ftp:` and anything else the installed
    openers handle, so a connector base URL that reaches configuration or a
    vendor payload becomes a local file read. The URLs here come from
    environment variables and, for a couple of connectors, from a field in a
    vendor response, which is exactly the path that should not be able to
    name `file:///etc/passwd`.
    """
    parsed = urllib.parse.urlparse(str(url or ''))
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ConnectorError(
            '%s refused a %r URL; only http and https are allowed'
            % (connector_key or 'connector', parsed.scheme or 'relative'))
    if not parsed.netloc:
        raise ConnectorError('%s refused a URL with no host'
                             % (connector_key or 'connector'))
    return url


@dataclass
class GraphDelta:
    """Nodes and edges a connector wants merged into the estate."""

    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    #: Free-form counters the run record keeps, e.g. {'alerts': 12}.
    stats: dict = field(default_factory=dict)

    def add_node(self, node_id: str, kind: str, key: str, zone: str,
                 *, label: str | None = None, crown: bool = False,
                 **extra) -> str:
        self.nodes.append({'id': node_id, 'kind': kind, 'key': key,
                           'zone': zone, 'label': label or key,
                           'crown': crown, **extra})
        return node_id

    def add_edge(self, src: str, dst: str, kind: str,
                 first_seen: str, *, cost: float | None = None, **extra) -> None:
        from ..vocab import DEFAULT_COST
        self.edges.append({
            'src': src, 'dst': dst, 'kind': kind,
            'cost': float(cost if cost is not None
                          else DEFAULT_COST.get(kind, 1.0)),
            'first_seen': first_seen, **extra})

    def extend(self, other: GraphDelta) -> GraphDelta:
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)
        for key, value in other.stats.items():
            self.stats[key] = self.stats.get(key, 0) + value
        return self

    def __len__(self) -> int:
        return len(self.nodes) + len(self.edges)


def _next_link(header: str) -> str | None:
    """The rel="next" URL from an RFC 8288 Link header, as Okta pages."""
    for part in str(header or '').split(','):
        segments = part.split(';')
        if len(segments) > 1 and any(s.strip() == 'rel="next"' for s in segments[1:]):
            return segments[0].strip().strip('<>')
    return None


def _query_of(url: str) -> dict:
    """A URL's query as a dict of strings. Repeated keys are joined, which no
    vendor here uses but which keeps the comparison total."""
    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    return {key: ','.join(values) for key, values in parsed.items()}


class HttpTransport:
    """Real HTTP, for live mode. Returns (status, lowercased headers, text)."""

    def __init__(self, timeout: float):
        self.timeout = timeout

    def send(self, method, url, *, headers, json_body=None, form=None):
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode('utf-8')
            headers.setdefault('Content-Type', 'application/json')
        elif form is not None:
            data = urllib.parse.urlencode(form).encode('utf-8')
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        request = urllib.request.Request(url, data=data, headers=headers,  # noqa: S310
                                         method=method)
        try:
            # The scheme is checked by require_http_url before this is called.
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return (response.status, {k.lower(): v for k, v in response.headers.items()},
                        response.read().decode('utf-8', errors='replace'))
        except urllib.error.HTTPError as exc:
            return exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, ''
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectorError('unreachable: %s' % exc) from exc


class RecordedTransport:
    """Answers from a recording, for replay mode.

    A request matches a recorded exchange on method, path and query, and on
    the JSON body when the recording holds one. The host is ignored, since
    a recording is about what was asked, not where. A request the recording
    does not hold is an error, so a change to the code that calls a vendor
    differently fails here instead of quietly returning nothing.
    """

    def __init__(self, exchanges: list, key: str):
        self.key = key
        self.exchanges = exchanges
        self.used: set[int] = set()

    def send(self, method, url, *, headers, json_body=None, form=None):
        path = urllib.parse.urlparse(url).path
        query = _query_of(url)
        for index, exchange in enumerate(self.exchanges):
            request = exchange['request']
            if request['method'] != method or request['path'] != path:
                continue
            if request.get('query', {}) != query:
                continue
            if 'body' in request and request['body'] != json_body:
                continue
            self.used.add(index)
            response = exchange['response']
            body = response.get('body')
            text = response['text'] if 'text' in response else json.dumps(body)
            return (int(response.get('status', 200)),
                    {k.lower(): v for k, v in (response.get('headers') or {}).items()}, text)
        raise ConnectorError('%s made a request its recording does not hold: %s %s%s'
                             % (self.key, method, path,
                                ('?' + urllib.parse.urlencode(query)) if query else ''))

    def unused(self) -> list:
        return [exchange['request'] for index, exchange in enumerate(self.exchanges)
                if index not in self.used]


def _earliest(a, b):
    present = [value for value in (a, b) if value]
    return min(present) if present else (a if a is not None else b)


def _latest(a, b):
    present = [value for value in (a, b) if value]
    return max(present) if present else (a if a is not None else b)


def combine_edges(existing: dict, incoming: dict) -> dict:
    """Fold a second observation of one relationship into the first.

    Two sources reporting the same (src, dst, kind) are two pieces of
    evidence about one fact, and the merge has to keep both. The previous
    rule kept whichever arrived first and dropped the other, which is how
    CloudTrail's record of svc-deploy reading the backups vanished behind
    Okta's record of it signing on: same edge, so one of them went.

      cost        the cheapest, because two confirmations of a step do not
                  make it harder for an attacker
      first_seen  the earliest, which is what "first" means
      last_seen,  the latest, which is what "last" means
      last_used
      actions,    the union, sorted, so the result does not depend on the
      sources     order connectors happened to run in
      otherwise   the first value wins and a later one fills only a gap

    ISO-8601 timestamps in UTC compare correctly as strings, which is why
    min and max are safe here without parsing.
    """
    merged = dict(existing)
    merged['cost'] = min(float(existing.get('cost', 1.0)),
                         float(incoming.get('cost', 1.0)))
    merged['first_seen'] = _earliest(existing.get('first_seen'),
                                     incoming.get('first_seen'))
    for field_name in ('last_seen', 'last_used'):
        if field_name in existing or field_name in incoming:
            merged[field_name] = _latest(existing.get(field_name),
                                         incoming.get(field_name))
    for field_name in ('actions', 'sources'):
        values = set(existing.get(field_name) or ()) | set(incoming.get(field_name) or ())
        if values:
            merged[field_name] = sorted(values)
    for field_name, value in incoming.items():
        if field_name in merged and merged[field_name] not in (None, '', []):
            continue
        merged[field_name] = value
    return merged


@dataclass
class RunResult:
    connector: str
    status: str                 # success | degraded | failed
    mode: str
    started_at: float
    finished_at: float
    nodes: int = 0
    edges: int = 0
    error: str | None = None
    stats: dict = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def as_dict(self) -> dict:
        return {'run_id': self.run_id, 'connector': self.connector,
                'status': self.status, 'mode': self.mode,
                'nodes': self.nodes, 'edges': self.edges,
                'duration_ms': self.duration_ms, 'error': self.error,
                'stats': self.stats}


class Connector(ABC):
    """Base for every integration."""

    #: Stable identifier. Used in config, the registry and the fixture name.
    key: str = ''
    vendor: str = ''
    product: str = ''
    #: siem | edr | idp | cloud | vulnerability | itsm | chat | oncall | code
    category: str = ''
    direction: str = 'inbound'
    #: Environment variables the live path needs. Named, never defaulted.
    required_credentials: tuple[str, ...] = ()
    #: Documentation URL for the API being called, so a reviewer can check
    #: the payload shape against the vendor rather than trusting this code.
    api_reference: str = ''

    def __init__(self, *, mode: str = MODE_REPLAY, credentials: dict | None = None,
                 timeout: float = 15.0):
        if mode not in (MODE_REPLAY, MODE_LIVE):
            raise ValueError('mode must be replay or live')
        self.mode = mode
        self.credentials = dict(credentials or {})
        self.timeout = timeout
        if mode == MODE_LIVE:
            missing = [name for name in self.required_credentials
                       if not self.credentials.get(name)]
            if missing:
                raise MissingCredentials(
                    '%s needs %s' % (self.key, ', '.join(missing)))

    #: Settings with a default, used in both modes: chiefly a vendor's API
    #: host, so a customer on CrowdStrike's EU cloud or Azure Government can
    #: point the connector at theirs. Overridden by a credential of the same
    #: name.
    defaults: dict = {}
    #: Values for required settings in replay mode, where no credentials
    #: exist. Only those that shape a request path need a real value, since
    #: replay matches on method, path, query and body, never on the host.
    replay_settings: dict = {}

    # ------------------------------------------------------------- settings
    def setting(self, name: str) -> str:
        value = self.credentials.get(name)
        if value:
            return str(value)
        if name in self.defaults:
            return str(self.defaults[name])
        if self.mode == MODE_REPLAY:
            if name in self.replay_settings:
                return str(self.replay_settings[name])
            return ('https://%s.replay.invalid' % self.key
                    if name.endswith(('_HOST', '_URL', '_DOMAIN', '_INSTANCE'))
                    else 'replay')
        raise MissingCredentials('%s needs %s' % (self.key, name))

    def now(self):
        """When this run is happening. A replay happens when it was recorded,
        so a request that depends on the time, such as "the last 90 days of
        sign-ins", is the same request the recording holds."""
        from datetime import datetime, timezone
        if self.mode == MODE_REPLAY:
            stamp = self.load_fixture().get('recorded_at')
            if stamp:
                return datetime.fromisoformat(str(stamp).replace('Z', '+00:00'))
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------- fetching
    def fixture_path(self) -> Path:
        return FIXTURE_DIR / ('%s.json' % self.key)

    def load_fixture(self) -> dict:
        cached = getattr(self, '_fixture', None)
        if cached is not None:
            return cached
        path = self.fixture_path()
        if not path.exists():
            raise ConnectorError('no fixture for %s at %s' % (self.key, path))
        with path.open(encoding='utf-8') as handle:
            self._fixture = json.load(handle)
        return self._fixture

    @property
    def transport(self):
        current = getattr(self, '_transport', None)
        if current is None:
            current = (RecordedTransport(self.load_fixture().get('exchanges', []), self.key)
                       if self.mode == MODE_REPLAY else HttpTransport(self.timeout))
            self._transport = current
        return current

    @transport.setter
    def transport(self, value):
        self._transport = value

    def fetch(self) -> dict:
        """The vendor's raw payload, from the same calls in either mode."""
        return self.collect()

    def collect(self) -> dict:
        raise NotImplementedError('%s has no live implementation' % self.key)

    def request(self, method: str, url: str, *, headers: dict | None = None,
                json_body=None, form: dict | None = None, expect: str = 'json'):
        """One place for every vendor call, so errors read the same everywhere.

        `expect` is 'json' or 'text'. Returns (parsed body, response headers)
        through `request_full`; this convenience returns the body alone.
        """
        return self.request_full(method, url, headers=headers, json_body=json_body,
                                 form=form, expect=expect)[0]

    def request_full(self, method: str, url: str, *, headers: dict | None = None,
                     json_body=None, form: dict | None = None, expect: str = 'json'):
        require_http_url(url, self.key)
        status, response_headers, text = self.transport.send(
            method, url, headers=dict(headers or {}), json_body=json_body, form=form)
        if status >= 400:
            raise ConnectorError('%s returned HTTP %d for %s %s'
                                 % (self.key, status, method,
                                    urllib.parse.urlparse(url).path))
        if expect == 'text':
            return text, response_headers
        try:
            return json.loads(text), response_headers
        except json.JSONDecodeError as exc:
            raise ConnectorError('%s returned non-JSON from %s'
                                 % (self.key, urllib.parse.urlparse(url).path)) from exc

    def bearer(self, token: str) -> dict:
        return {'Authorization': 'Bearer %s' % token, 'Accept': 'application/json'}

    def azure_token(self, scope: str) -> str:
        """A client-credentials token from Microsoft identity, for one scope.

        The connectors that name AZURE_CLIENT_ID and AZURE_CLIENT_SECRET used
        to read a pre-minted AZURE_ACCESS_TOKEN they never asked for, so
        their live paths could not authenticate at all.
        """
        login = self.setting('AZURE_LOGIN_URL').rstrip('/')
        body = self.request('POST', '%s/%s/oauth2/v2.0/token'
                            % (login, self.setting('AZURE_TENANT_ID')),
                            form={'grant_type': 'client_credentials',
                                  'client_id': self.setting('AZURE_CLIENT_ID'),
                                  'client_secret': self.setting('AZURE_CLIENT_SECRET'),
                                  'scope': scope})
        token = body.get('access_token')
        if not token:
            raise ConnectorError('%s: Microsoft identity returned no token' % self.key)
        return str(token)

    def follow(self, url: str, *, headers: dict, items_key: str | None = None,
               next_key: str | None = None, max_pages: int = 50) -> list:
        """Every page of a listing, by `Link: rel="next"` or a next-link field.

        Bounded, because an endless next-link from a misbehaving server would
        otherwise be an endless loop inside an ingest.
        """
        out: list = []
        for _ in range(max_pages):
            body, response_headers = self.request_full('GET', url, headers=headers)
            page = body.get(items_key, []) if items_key else body
            out.extend(page or [])
            following = body.get(next_key) if next_key and isinstance(body, dict) else None
            if not following:
                following = _next_link(response_headers.get('link', ''))
            if not following:
                return out
            url = following
        raise ConnectorError('%s: more than %d pages from %s'
                             % (self.key, max_pages, urllib.parse.urlparse(url).path))

    # --------------------------------------------------------- transforming
    @abstractmethod
    def transform(self, payload: dict) -> GraphDelta:
        """Turn the vendor payload into nodes and edges."""

    # ---------------------------------------------------------------- running
    def run(self) -> tuple[RunResult, GraphDelta]:
        started = time.time()
        try:
            delta = self.transform(self.fetch())
        except ConnectorError as exc:
            return RunResult(connector=self.key, status='failed', mode=self.mode,
                             started_at=started, finished_at=time.time(),
                             error=str(exc)), GraphDelta()
        except Exception as exc:                      # noqa: BLE001
            # A connector is parsing somebody else's JSON. A malformed record
            # must not take the ingest process down with it.
            return RunResult(connector=self.key, status='failed', mode=self.mode,
                             started_at=started, finished_at=time.time(),
                             error='%s: %s' % (type(exc).__name__, exc)), GraphDelta()
        return RunResult(connector=self.key, status='success', mode=self.mode,
                         started_at=started, finished_at=time.time(),
                         nodes=len(delta.nodes), edges=len(delta.edges),
                         stats=delta.stats), delta

    def describe(self) -> dict:
        return {'key': self.key, 'vendor': self.vendor, 'product': self.product,
                'category': self.category, 'direction': self.direction,
                'mode': self.mode,
                'credentials': list(self.required_credentials),
                'api_reference': self.api_reference,
                'fixture': self.fixture_path().name}


class OutboundConnector(Connector):
    """Pushes a finding to a human system."""

    direction = 'outbound'

    def transform(self, payload: dict) -> GraphDelta:
        # An outbound connector contributes nothing to the graph. Declared
        # explicitly so the ABC is satisfied and the registry can treat
        # every connector the same way.
        return GraphDelta()

    @abstractmethod
    def deliver(self, finding: dict, *, idempotency_key: str) -> dict:
        """Send one finding. Must be safe to call twice with the same key."""

    def run(self) -> tuple[RunResult, GraphDelta]:
        started = time.time()
        return RunResult(connector=self.key, status='success', mode=self.mode,
                         started_at=started, finished_at=time.time(),
                         stats={'note': 'outbound connectors deliver on demand'}
                         ), GraphDelta()
