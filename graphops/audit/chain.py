"""An append-only audit log whose entries are chained by hash.

Every entry stores the hash of the one before it, and its own hash covers
both its content and that link. Changing or removing any entry breaks every
hash after it, so `verify_chain` finds the first damaged sequence number
rather than merely reporting that something is wrong.

What this does and does not buy, stated plainly because audit logs attract
overclaiming:

  * It makes silent tampering detectable. Someone who edits a row must
    recompute every later row to stay consistent.
  * It does NOT stop a writer with database access from rewriting the whole
    chain from the edited point forward. Nothing stored next to the data can.
    Detecting that requires the head hash to leave the system: `head()`
    returns it so a deployment can publish it hourly to append-only storage
    or a transparency log, and `verify_chain(expected_head=...)` checks
    against a value anchored elsewhere.

The canonical form is JSON with sorted keys and no whitespace. Any ambiguity
in how an entry is serialised is a way to produce two entries with one hash,
so the serialisation is pinned here and the test suite asserts it.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field

#: The hash recorded by the first entry, which has no predecessor.
GENESIS_HASH = '0' * 64


class Outcome:
    SUCCESS = 'success'
    DENIED = 'denied'
    FAILURE = 'failure'


@dataclass(frozen=True)
class AuditEntry:
    id: str
    organization_id: str | None
    actor_id: str | None
    actor_kind: str
    on_behalf_of: str | None
    action: str
    resource: str
    outcome: str
    client_ip: str | None
    detail: dict
    occurred_at: int
    previous_hash: str
    entry_hash: str = ''

    def payload(self) -> dict:
        """Exactly the fields the hash covers, in a fixed order."""
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'actor_id': self.actor_id,
            'actor_kind': self.actor_kind,
            'on_behalf_of': self.on_behalf_of,
            'action': self.action,
            'resource': self.resource,
            'outcome': self.outcome,
            'client_ip': self.client_ip,
            'detail': self.detail,
            'occurred_at': self.occurred_at,
            'previous_hash': self.previous_hash,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(self.payload(), sort_keys=True,
                               separators=(',', ':'), ensure_ascii=False,
                               default=str)
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


#: Keys whose values are replaced before an entry is written. The audit log
#: is the one table most likely to be exported wholesale to a SIEM, so a
#: secret that reaches it has reached everywhere.
SENSITIVE_KEYS = frozenset({
    'password', 'new_password', 'old_password', 'secret', 'token',
    'access_token', 'refresh_token', 'api_key', 'key', 'authorization',
    'mfa_secret', 'signing_key', 'client_secret', 'private_key',
})
REDACTED = '[redacted]'


def scrub(detail, _depth: int = 0):
    """Replace sensitive values anywhere in a detail payload."""
    if _depth > 8:
        return '[too deep]'
    if isinstance(detail, dict):
        return {k: (REDACTED if str(k).lower() in SENSITIVE_KEYS
                    else scrub(v, _depth + 1))
                for k, v in detail.items()}
    if isinstance(detail, (list, tuple)):
        return [scrub(v, _depth + 1) for v in detail]
    return detail


@dataclass
class AuditLog:
    """Writes chained entries into the `audit_events` table."""

    db: object
    _cached_head: str | None = field(default=None, repr=False)

    def head(self) -> str:
        """The most recent entry hash, or the genesis value when empty."""
        row = self.db.query_one(
            'SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1')
        return row['entry_hash'] if row else GENESIS_HASH

    def record(self, *, action: str, outcome: str,
               organization_id: str | None = None,
               actor_id: str | None = None,
               actor_kind: str = 'user',
               on_behalf_of: str | None = None,
               resource: str = '',
               client_ip: str | None = None,
               detail: dict | None = None,
               occurred_at: int | None = None) -> AuditEntry:
        """Append one entry. Returns it, with its hash filled in."""
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            actor_id=actor_id,
            actor_kind=actor_kind,
            on_behalf_of=on_behalf_of,
            action=action,
            resource=resource,
            outcome=outcome,
            client_ip=client_ip,
            detail=scrub(detail or {}),
            occurred_at=int(time.time()) if occurred_at is None else int(occurred_at),
            previous_hash=GENESIS_HASH,
        )
        # The read of the head and the insert happen inside one write
        # transaction. Computing the hash outside it would let two concurrent
        # writers chain off the same predecessor and fork the chain.
        with self.db.write() as cur:
            cur.execute('SELECT entry_hash FROM audit_events'
                        ' ORDER BY seq DESC LIMIT 1')
            row = cur.fetchone()
            previous = row['entry_hash'] if row else GENESIS_HASH
            entry = AuditEntry(**{**entry.payload(), 'previous_hash': previous,
                                  'entry_hash': ''})
            entry = AuditEntry(**{**entry.payload(),
                                  'entry_hash': entry.compute_hash()})
            cur.execute(
                """INSERT INTO audit_events
                   (id, organization_id, actor_id, actor_kind, on_behalf_of,
                    action, resource, outcome, client_ip, detail,
                    occurred_at, previous_hash, entry_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (entry.id, entry.organization_id, entry.actor_id,
                 entry.actor_kind, entry.on_behalf_of, entry.action,
                 entry.resource, entry.outcome, entry.client_ip,
                 json.dumps(entry.detail, sort_keys=True, default=str),
                 entry.occurred_at, entry.previous_hash, entry.entry_hash))
        self._cached_head = entry.entry_hash
        return entry

    # ------------------------------------------------------------- reading
    def entries(self, *, organization_id: str | None = None,
                action: str | None = None,
                limit: int = 100, offset: int = 0) -> list[dict]:
        sql = ['SELECT * FROM audit_events WHERE 1=1']
        params: list = []
        if organization_id is not None:
            sql.append('AND organization_id = ?')
            params.append(organization_id)
        if action:
            sql.append('AND action = ?')
            params.append(action)
        sql.append('ORDER BY seq DESC LIMIT ? OFFSET ?')
        params.extend([max(1, min(int(limit), 1000)), max(0, int(offset))])
        rows = self.db.query(' '.join(sql), tuple(params))
        out = []
        for row in rows:
            record = dict(row)
            try:
                record['detail'] = json.loads(record['detail'])
            except (ValueError, TypeError):
                record['detail'] = {}
            out.append(record)
        return out

    def verify_chain(self, *, expected_head: str | None = None) -> dict:
        """Recompute every hash in order.

        Returns a report rather than raising, because a broken chain is a
        finding to be shown, not an exception to be swallowed by whatever
        called it.
        """
        rows = self.db.query('SELECT * FROM audit_events ORDER BY seq ASC')
        previous = GENESIS_HASH
        for row in rows:
            try:
                detail = json.loads(row['detail'])
            except (ValueError, TypeError):
                detail = {}
            rebuilt = AuditEntry(
                id=row['id'], organization_id=row['organization_id'],
                actor_id=row['actor_id'], actor_kind=row['actor_kind'],
                on_behalf_of=row['on_behalf_of'], action=row['action'],
                resource=row['resource'], outcome=row['outcome'],
                client_ip=row['client_ip'], detail=detail,
                occurred_at=row['occurred_at'], previous_hash=row['previous_hash'],
            )
            if row['previous_hash'] != previous:
                return {'valid': False, 'entries': len(rows),
                        'broken_at': row['seq'],
                        'reason': 'link does not match the previous entry hash'}
            if rebuilt.compute_hash() != row['entry_hash']:
                return {'valid': False, 'entries': len(rows),
                        'broken_at': row['seq'],
                        'reason': 'entry content does not match its hash'}
            previous = row['entry_hash']

        if expected_head is not None and previous != expected_head:
            # Internally consistent but not the chain we anchored. This is
            # what catches a wholesale rewrite.
            return {'valid': False, 'entries': len(rows), 'broken_at': None,
                    'reason': 'head does not match the anchored value',
                    'head': previous, 'expected_head': expected_head}

        return {'valid': True, 'entries': len(rows), 'head': previous}
