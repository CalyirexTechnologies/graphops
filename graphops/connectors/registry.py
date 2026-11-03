"""The connector registry and the ingest pipeline.

`ingest` runs every inbound connector, merges what they return into one
estate, and records a run row per connector. The merge is where the value is,
and two rules govern it.

**A connector failing does not fail the ingest.** One vendor being down or
changing a field name must not cost the estate its other eleven sources. The
run is marked `degraded`, the failure is recorded against that connector, and
the merged graph is built from whatever did arrive. A security tool that goes
dark because CrowdStrike rotated a token is worse than one running on
yesterday's EDR data and saying so.

**Later sources refine earlier ones, they do not duplicate them.** Two
connectors describing the same host must produce one node. Nodes merge by id,
and on a conflict the record with a `crown_source` wins, because a CMDB
classification is evidence and a name-matching heuristic is a guess.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .base import MODE_REPLAY, Connector, GraphDelta, OutboundConnector, RunResult
from .cloud import CloudTrailConnector
from .edr import CrowdStrikeConnector
from .identity_provider import EntraIdConnector, OktaConnector
from .itsm import ServiceNowConnector
from .outbound import JiraConnector, PagerDutyConnector, SlackConnector, TeamsConnector
from .siem import SentinelConnector, SplunkConnector
from .vulnerability import QualysConnector, TenableConnector

#: Every connector the platform knows about, by key.
CONNECTORS: dict[str, type[Connector]] = {
    cls.key: cls for cls in (
        SplunkConnector, SentinelConnector,
        CrowdStrikeConnector,
        OktaConnector, EntraIdConnector,
        CloudTrailConnector,
        QualysConnector, TenableConnector,
        ServiceNowConnector,
        JiraConnector, SlackConnector, TeamsConnector, PagerDutyConnector,
    )
}

INBOUND = {k: v for k, v in CONNECTORS.items()
           if not issubclass(v, OutboundConnector)}
OUTBOUND = {k: v for k, v in CONNECTORS.items()
            if issubclass(v, OutboundConnector)}


def catalogue() -> list[dict]:
    """What the API exposes at /connectors. No credentials, ever."""
    out = []
    for key, cls in sorted(CONNECTORS.items()):
        out.append({'key': key, 'vendor': cls.vendor, 'product': cls.product,
                    'category': cls.category, 'direction': cls.direction,
                    'credentials': list(cls.required_credentials),
                    'api_reference': cls.api_reference})
    return out


def build(key: str, *, mode: str = MODE_REPLAY,
          credentials: dict | None = None) -> Connector:
    try:
        cls = CONNECTORS[key]
    except KeyError as exc:
        raise KeyError('unknown connector %r; known: %s'
                       % (key, ', '.join(sorted(CONNECTORS)))) from exc
    return cls(mode=mode, credentials=credentials)


@dataclass
class IngestResult:
    estate: dict
    runs: list[RunResult] = field(default_factory=list)
    ingest_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def status(self) -> str:
        if not self.runs:
            return 'empty'
        if all(run.status == 'success' for run in self.runs):
            return 'success'
        if any(run.status == 'success' for run in self.runs):
            return 'degraded'
        return 'failed'

    @property
    def failures(self) -> list[RunResult]:
        return [run for run in self.runs if run.status != 'success']

    def summary(self) -> dict:
        return {
            'ingest_id': self.ingest_id,
            'status': self.status,
            'connectors_run': len(self.runs),
            'connectors_failed': len(self.failures),
            'nodes': len(self.estate['nodes']),
            'edges': len(self.estate['edges']),
            'runs': [run.as_dict() for run in self.runs],
        }


def _merge_nodes(existing: dict, incoming: dict) -> dict:
    """Combine two records for the same node id.

    Evidence beats inference: a node classified as a crown jewel by a source
    that says how it knows keeps that classification, and a later source
    cannot quietly clear the flag.
    """
    merged = dict(existing)
    for field_name, value in incoming.items():
        if value in (None, '', []):
            continue
        if field_name == 'crown':
            # Once anything with a stated source says crown, it stays crown.
            if existing.get('crown_source'):
                continue
            merged['crown'] = bool(existing.get('crown')) or bool(value)
            continue
        if field_name == 'sources':
            continue
        merged[field_name] = value
    sources = set(existing.get('sources') or [])
    for record in (existing, incoming):
        if record.get('source'):
            sources.add(record['source'])
    if sources:
        merged['sources'] = sorted(sources)
    return merged


def merge(deltas) -> dict:
    """Fold connector output into one estate payload."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    for delta in deltas:
        for node in delta.nodes:
            node_id = node['id']
            if node_id in nodes:
                nodes[node_id] = _merge_nodes(nodes[node_id], node)
            else:
                record = dict(node)
                if record.get('source'):
                    record['sources'] = [record['source']]
                nodes[node_id] = record
        for edge in delta.edges:
            # One relationship of one kind between two nodes, keeping the
            # cheapest. Without this, two SIEM rows for the same request
            # become two routes and every count in the product doubles.
            signature = (edge['src'], edge['dst'], edge['kind'])
            if signature in seen_edges:
                for existing in edges:
                    if (existing['src'], existing['dst'],
                            existing['kind']) == signature:
                        if edge.get('cost', 1.0) < existing.get('cost', 1.0):
                            existing.update(edge)
                        break
                continue
            seen_edges.add(signature)
            edges.append(dict(edge))

    # An edge may name a node no connector described, for instance an asset
    # that only appears as the far end of a CMDB relationship. Dropping the
    # edge would lose a real route, so the node is created as a placeholder
    # and marked, which is visible in the viewer rather than silent.
    from ..vocab import NodeKind, Zone
    for edge in edges:
        for endpoint in (edge['src'], edge['dst']):
            if endpoint not in nodes:
                nodes[endpoint] = {
                    'id': endpoint, 'kind': NodeKind.ASSET,
                    'key': endpoint.split(':', 1)[-1],
                    'label': endpoint.split(':', 1)[-1],
                    'zone': Zone.INTERNAL, 'crown': False,
                    'inferred': True,
                    'sources': ['inferred from an edge'],
                }

    return {
        'name': 'Estate assembled from connectors',
        'generated': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime()),
        'note': 'Merged connector output. See each node\'s "sources".',
        'nodes': list(nodes.values()),
        'edges': edges,
    }


def ingest(keys=None, *, mode: str = MODE_REPLAY,
           credentials: dict | None = None) -> IngestResult:
    """Run the inbound connectors and merge their output."""
    chosen = list(keys) if keys else list(INBOUND)
    deltas: list[GraphDelta] = []
    runs: list[RunResult] = []

    for key in chosen:
        if key not in INBOUND:
            runs.append(RunResult(connector=key, status='failed', mode=mode,
                                  started_at=time.time(), finished_at=time.time(),
                                  error='not an inbound connector'))
            continue
        try:
            connector = build(key, mode=mode,
                              credentials=(credentials or {}).get(key))
        except Exception as exc:                      # noqa: BLE001
            runs.append(RunResult(connector=key, status='failed', mode=mode,
                                  started_at=time.time(), finished_at=time.time(),
                                  error=str(exc)))
            continue
        result, delta = connector.run()
        runs.append(result)
        if result.status == 'success':
            deltas.append(delta)

    return IngestResult(estate=merge(deltas), runs=runs)
