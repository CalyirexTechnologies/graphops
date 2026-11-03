"""Authorisation decisions, including the ones the graph makes special.

Most of this file is ordinary: `authorize` checks a permission and raises.
The part worth reading is redaction.

An attack-path answer is not a single object with a sensitivity label. It is
a route, and the sensitive part is usually the last node: *which* system the
route ends at. A product that handles this with a per-endpoint allow or deny
ends up with two bad options, showing a viewer the card database's name or
showing them nothing and making the dashboard useless.

So redaction is per node, and it pseudonymises rather than blanks. A crown
jewel a viewer may not identify becomes a stable token like
`crown-jewel-7f3a`, derived by HMAC from the node id under a per-organization
salt. Three properties follow, and all three are tested:

  * Stable. The same node reads the same across queries, so a viewer can
    still say "that one again" and follow a trend.
  * Not reversible, and not correlatable across tenants, because the salt is
    per organization and the construction is HMAC rather than a bare hash of
    a low-entropy identifier.
  * Honest about its own presence. The response says `redacted: true` and
    names the permission that would lift it, instead of pretending the
    redacted name is the real one.

Counts are never redacted. "Twelve routes reach a crown jewel" is the number
a viewer is there to see, and hiding it would make the role pointless.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .permissions import Permission
from .principal import AccessDenied, Principal

#: Marker added to any structure that had something removed.
REDACTION_NOTICE = {
    'redacted': True,
    'unlocked_by': Permission.CROWN_REVEAL.value,
    'reason': 'crown jewel identities require the crown:reveal permission',
}


def authorize(principal: Principal, permission: Permission,
              detail: str = '') -> None:
    """Raise `AccessDenied` unless `principal` holds `permission`."""
    principal.require(permission, detail)


def ensure_same_tenant(principal: Principal, organization: str) -> None:
    """Refuse a cross-tenant reference.

    Called wherever an identifier arrives from the caller rather than from
    the principal. Cross-tenant access in a multi-tenant product is almost
    never a missing role; it is an object id from one tenant reaching a query
    scoped to another.
    """
    if principal.organization != organization:
        raise AccessDenied(
            Permission.ORG_READ,
            'principal belongs to %r, not %r' % (principal.organization,
                                                 organization))


def pseudonym(node_id: str, *, organization: str, salt: bytes) -> str:
    """A stable, per-tenant, non-reversible stand-in for a node id."""
    digest = hmac.new(salt,
                      ('%s|%s' % (organization, node_id)).encode('utf-8'),
                      hashlib.sha256).hexdigest()
    return 'crown-jewel-%s' % digest[:8]


class Redactor:
    """Applies the crown-jewel rule to engine output for one principal."""

    def __init__(self, principal: Principal, *, salt: bytes):
        self.principal = principal
        self.salt = salt
        self.may_reveal = principal.can(Permission.CROWN_REVEAL)
        self.redacted_count = 0

    # --------------------------------------------------------------- nodes
    @staticmethod
    def _is_crown(record: dict) -> bool:
        """Both spellings count.

        The estate payload stores `crown`; the engine's own output calls the
        same thing `is_crown_jewel`. Checking one would have let every
        analysis response through unredacted while the node-level tests
        passed, which is the kind of gap that only shows up in production.
        """
        return bool(record.get('crown') or record.get('is_crown_jewel'))

    def node(self, record: dict) -> dict:
        """Redact one node record if it is a crown jewel and may not be seen."""
        if self.may_reveal or not self._is_crown(record):
            return record
        self.redacted_count += 1
        alias = pseudonym(str(record.get('id', '')),
                          organization=self.principal.organization,
                          salt=self.salt)
        masked = dict(record)
        masked['id'] = alias
        masked['key'] = alias
        masked['label'] = alias
        masked.pop('detail', None)
        masked['redacted'] = True
        return masked

    def step(self, record: dict) -> dict:
        """A path step. The tactic stays; only the identity goes."""
        if self.may_reveal or not self._is_crown(record):
            return record
        return self.node(record)

    # --------------------------------------------------------------- trees
    def walk(self, value: Any) -> Any:
        """Recursively redact every node-shaped dict inside `value`.

        Node-shaped means it carries an `id` and a `crown` flag, which is
        what the engine emits. Walking the whole structure rather than
        listing known response fields means a new endpoint cannot leak a
        crown jewel by forgetting to call the redactor on its own shape.
        """
        if isinstance(value, dict):
            if 'id' in value and ('crown' in value or 'is_crown_jewel' in value):
                value = self.node(value)
            return {k: self.walk(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.walk(item) for item in value]
        return value

    def finish(self, payload: dict) -> dict:
        """Attach the notice when anything was removed."""
        if self.redacted_count:
            payload = dict(payload)
            payload['_redaction'] = dict(REDACTION_NOTICE,
                                         nodes_redacted=self.redacted_count)
        return payload


def redact(payload: dict, principal: Principal, *, salt: bytes) -> dict:
    """Convenience wrapper: walk a response and stamp the notice."""
    redactor = Redactor(principal, salt=salt)
    return redactor.finish(redactor.walk(payload))
