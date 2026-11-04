"""What the API keeps between requests.

Three things the console design relies on, which the API used to forget:

  * WHICH ESTATE IS SERVED. It was fixed at startup, so running ingest
    ingested, resolved, audited and then threw its own result away. Now an
    ingest replaces the estate its tenant is served, and only its tenant's:
    replacing one shared estate would let one tenant's "Run ingest" change
    what another tenant sees.
  * WHAT HAPPENED. `connector_runs` and `findings` were created as tables
    and never written. Ingests are now recorded with each connector's
    result, and findings are kept by fingerprint so a problem keeps the
    date it was first seen, and a problem that stops being true is marked
    resolved rather than silently vanishing.
  * WHAT A TENANT SAID MATTERS. A crown jewel override is the tenant's
    statement over its sources', applied to that tenant's view only.

Everything here is keyed by organization. The one shared thing is the
estate the server loaded at startup, which a tenant sees until it runs an
ingest of its own.
"""
from __future__ import annotations

import json
import threading
import time
import uuid

from .. import analysis
from ..vocab import Zone


def _payload_of(estate) -> dict:
    """An Estate back to the payload it was built from."""
    return {'name': estate.name, 'nodes': estate.nodes, 'edges': estate.edges,
            'as_of': estate.as_of.isoformat() if estate.as_of else None,
            'mode': estate.mode}


def apply_overrides(base, overrides: dict) -> analysis.Estate:
    """A tenant's view of an estate: its own crown jewel decisions on top.

    A marked node takes the crown zone so the flag and the zone never
    disagree, and records that its classification came from the tenant.
    An unmarked crown jewel drops to internal and keeps the record of what
    its source had said, so a reviewer can see the override was a choice.
    """
    nodes = []
    for node in base.nodes:
        decision = overrides.get(node['id'])
        if decision is None:
            nodes.append(node)
            continue
        changed = dict(node)
        if decision['crown']:
            changed['crown'] = True
            changed['zone'] = Zone.CROWN
            changed['crown_source'] = 'tenant override'
        else:
            if node.get('crown_source'):
                changed['crown_source_overridden'] = node['crown_source']
            changed['crown'] = False
            changed['crown_source'] = None
            if node.get('zone') == Zone.CROWN:
                changed['zone'] = Zone.INTERNAL
        changed['crown_override'] = {'by': decision['set_by'],
                                     'at': decision['set_at'],
                                     'reason': decision['reason']}
        nodes.append(changed)
    payload = _payload_of(base)
    payload['nodes'] = nodes
    return analysis.Estate(payload)


class EstateService:
    """The estate each tenant is served, and everything that changes it."""

    def __init__(self, db, provider, clock=time.time):
        self.db = db
        self.provider = provider
        self.clock = clock
        self._lock = threading.RLock()
        self._ingested: dict[str, analysis.Estate] = {}
        self._versions: dict[str, int] = {}
        self._views: dict[str, tuple] = {}      # org -> (base, version, estate)
        self._findings: dict[str, tuple] = {}   # org -> (estate, findings)

    # ------------------------------------------------------------ estates
    def base(self, organization: str):
        estate = self._ingested.get(organization)
        if estate is not None:
            return estate
        return self.provider() if self.provider is not None else None

    def for_org(self, organization: str):
        """The estate this tenant sees, with its own overrides applied."""
        with self._lock:
            base = self.base(organization)
            if base is None:
                return None
            version = self._versions.get(organization, 0)
            cached = self._views.get(organization)
            if cached and cached[0] is base and cached[1] == version:
                return cached[2]
            overrides = self.overrides(organization)
            view = apply_overrides(base, overrides) if overrides else base
            self._views[organization] = (base, version, view)
            return view

    def _bump(self, organization: str) -> None:
        self._versions[organization] = self._versions.get(organization, 0) + 1

    def replace(self, organization: str, payload: dict) -> analysis.Estate:
        with self._lock:
            estate = analysis.Estate(payload)
            self._ingested[organization] = estate
            self._bump(organization)
            return estate

    # ------------------------------------------------------- crown jewels
    def overrides(self, organization: str) -> dict:
        rows = self.db.query('SELECT * FROM crown_overrides WHERE organization_id = ?',
                             (organization,))
        return {row['node_id']: {'crown': bool(row['crown']), 'reason': row['reason'],
                                 'set_by': row['set_by'], 'set_at': row['set_at']}
                for row in rows}

    def set_crown(self, organization: str, node_id: str, crown: bool,
                  reason: str, actor: str) -> None:
        with self._lock, self.db.write() as cur:
            cur.execute(
                'INSERT INTO crown_overrides (organization_id, node_id, crown,'
                ' reason, set_by, set_at) VALUES (?, ?, ?, ?, ?, ?)'
                ' ON CONFLICT (organization_id, node_id) DO UPDATE SET'
                ' crown = excluded.crown, reason = excluded.reason,'
                ' set_by = excluded.set_by, set_at = excluded.set_at',
                (organization, node_id, 1 if crown else 0, reason or '', actor,
                 int(self.clock())))
            self._bump(organization)

    # ------------------------------------------------------------ ingests
    def record_ingest(self, organization, actor, result, resolved,
                      started_at, finished_at) -> dict:
        """Write one ingest and each connector's result for it."""
        runs = [run.as_dict() for run in result.runs]
        row = {
            'id': result.ingest_id, 'organization_id': organization,
            'actor_id': actor, 'mode': resolved.get('mode') or 'replay',
            'status': result.status, 'started_at': int(started_at),
            'finished_at': int(finished_at), 'as_of': resolved.get('as_of'),
            'connectors_run': len(result.runs),
            'connectors_failed': len(result.failures),
            'merged': int((resolved.get('resolution') or {}).get('merged', 0)),
            'entities': len(resolved.get('nodes', [])),
            'relationships': len(resolved.get('edges', [])),
            'runs': json.dumps(runs),
        }
        with self.db.write() as cur:
            cur.execute(
                'INSERT INTO ingests (id, organization_id, actor_id, mode, status,'
                ' started_at, finished_at, as_of, connectors_run, connectors_failed,'
                ' merged, entities, relationships, runs)'
                ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (row['id'], row['organization_id'], row['actor_id'], row['mode'],
                 row['status'], row['started_at'], row['finished_at'], row['as_of'],
                 row['connectors_run'], row['connectors_failed'], row['merged'],
                 row['entities'], row['relationships'], row['runs']))
        return self._ingest_out(row)

    @staticmethod
    def _ingest_out(row) -> dict:
        record = dict(row)
        record['runs'] = json.loads(record.get('runs') or '[]')
        record['duration_seconds'] = max(0, int(record['finished_at'])
                                         - int(record['started_at']))
        record['succeeded'] = record['connectors_run'] - record['connectors_failed']
        return record

    def latest_ingest(self, organization: str) -> dict | None:
        """This tenant's last ingest, or the server's startup one."""
        row = self.db.query_one(
            'SELECT * FROM ingests WHERE organization_id = ?'
            ' ORDER BY finished_at DESC, rowid DESC LIMIT 1', (organization,))
        if row is None:
            row = self.db.query_one(
                'SELECT * FROM ingests WHERE organization_id IS NULL'
                ' ORDER BY finished_at DESC, rowid DESC LIMIT 1')
        return self._ingest_out(dict(row)) if row is not None else None

    # ----------------------------------------------------------- findings
    def findings(self, organization: str) -> list[dict]:
        """Current findings, each with its history from the store.

        Derived once per estate and kept, because deriving runs the whole
        analysis. Synced with the store each time the estate changes, which
        is the moment a finding can appear, return or stop being true.
        """
        from .. import findings as findings_module
        estate = self.for_org(organization)
        if estate is None:
            return []
        with self._lock:
            cached = self._findings.get(organization)
            if cached and cached[0] is estate:
                return cached[1]
            derived = findings_module.derive(estate)
            history = self._sync(organization, derived)
            current = []
            for finding in derived:
                stored = history[finding['fingerprint']]
                current.append(dict(finding, first_seen=stored['first_seen'],
                                    last_seen=stored['last_seen'],
                                    status='open', resolved_at=None))
            self._findings[organization] = (estate, current)
            return current

    def resolved_findings(self, organization: str) -> list[dict]:
        self.findings(organization)     # the sync is what resolves them
        rows = self.db.query(
            "SELECT * FROM findings WHERE organization_id = ? AND status = 'resolved'"
            ' ORDER BY resolved_at DESC', (organization,))
        out = []
        for row in rows:
            detail = json.loads(row['detail'] or '{}')
            out.append({'id': row['fingerprint'], 'fingerprint': row['fingerprint'],
                        'kind': row['kind'], 'severity': row['severity'],
                        'title': row['title'], 'routes': detail.get('routes', 0),
                        'status': 'resolved', 'first_seen': row['first_seen'],
                        'last_seen': row['last_seen'],
                        'resolved_at': row['resolved_at']})
        return out

    def _sync(self, organization: str, derived: list[dict]) -> dict:
        now = int(self.clock())
        existing = {row['fingerprint']: row for row in self.db.query(
            'SELECT * FROM findings WHERE organization_id = ?', (organization,))}
        seen = set()
        with self.db.write() as cur:
            for finding in derived:
                fingerprint = finding['fingerprint']
                seen.add(fingerprint)
                detail = json.dumps({'routes': int(finding.get('routes') or 0)})
                if fingerprint in existing:
                    cur.execute(
                        "UPDATE findings SET kind = ?, severity = ?, title = ?,"
                        " detail = ?, last_seen = ?, status = 'open',"
                        ' resolved_at = NULL WHERE organization_id = ? AND fingerprint = ?',
                        (finding['kind'], finding['severity'], finding['title'],
                         detail, now, organization, fingerprint))
                else:
                    cur.execute(
                        'INSERT INTO findings (id, organization_id, kind, severity,'
                        ' title, detail, status, first_seen, last_seen, fingerprint)'
                        " VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
                        (str(uuid.uuid4()), organization, finding['kind'],
                         finding['severity'], finding['title'], detail, now, now,
                         fingerprint))
            for fingerprint, row in existing.items():
                if fingerprint not in seen and row['status'] == 'open':
                    cur.execute(
                        "UPDATE findings SET status = 'resolved', resolved_at = ?"
                        ' WHERE organization_id = ? AND fingerprint = ?',
                        (now, organization, fingerprint))
        rows = self.db.query('SELECT fingerprint, first_seen, last_seen FROM findings'
                             ' WHERE organization_id = ?', (organization,))
        return {row['fingerprint']: dict(row) for row in rows}
