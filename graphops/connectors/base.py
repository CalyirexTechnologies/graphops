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

Two modes:

  * **replay**, the default, reads a committed fixture. Every connector ships
    one, so the whole pipeline runs with no vendor account, no API key and no
    network. This is how the tests run and how a reviewer sees it work.
  * **live** issues the real HTTP call. That code path is written and typed
    the same way, and it refuses to start without its credentials rather than
    falling back to the fixture. A connector that silently serves fixture
    data when a token expires would be worse than one that fails.

The fixtures are written from each vendor's published response schema. They
are synthetic records in the real shape, not captures from anyone's tenant.
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

    # ------------------------------------------------------------- fetching
    def fixture_path(self) -> Path:
        return FIXTURE_DIR / ('%s.json' % self.key)

    def load_fixture(self) -> dict:
        path = self.fixture_path()
        if not path.exists():
            raise ConnectorError('no fixture for %s at %s' % (self.key, path))
        with path.open(encoding='utf-8') as handle:
            return json.load(handle)

    def fetch(self) -> dict:
        """Return the vendor's raw payload."""
        if self.mode == MODE_REPLAY:
            return self.load_fixture()
        return self.fetch_live()

    def fetch_live(self) -> dict:
        raise NotImplementedError('%s has no live implementation' % self.key)

    def http_get_json(self, url: str, *, headers: dict | None = None) -> dict:
        """One place for the live HTTP call, so timeouts and errors are uniform."""
        require_http_url(url, self.key)
        request = urllib.request.Request(url, headers=headers or {},  # noqa: S310
                                         method='GET')
        try:
            # Scheme already checked by require_http_url above.
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            raise ConnectorError('%s returned HTTP %d' % (self.key, exc.code)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectorError('%s unreachable: %s' % (self.key, exc)) from exc
        except json.JSONDecodeError as exc:
            raise ConnectorError('%s returned non-JSON' % self.key) from exc

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
