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

STRINGS ARE REDACTED TOO, AND THAT WAS LEARNED THE HARD WAY. The first version
masked node-shaped dicts and nothing else, so every sentence that named a
crown jewel walked straight past it. A finding titled "support-desk may reach
billing-database and never has" reached a viewer intact, as did compliance
evidence and the containment revocation sentences. The tests passed because
they checked the node fields and never the text. So the redactor now also
knows every name each crown jewel goes by and replaces it wherever it
appears, with the same pseudonym the masked node carries, which keeps a
sentence and the node beside it consistent with each other.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from .permissions import Permission
from .principal import AccessDenied, Principal

#: Fields dropped from a masked crown jewel because they identify it without
#: containing its name. "The PCI system owned by finance-ops" is enough to
#: name it for anyone who knows the business, which is the whole point of
#: the role being unable to see it.
_IDENTIFYING_FIELDS = ('arn', 'resolved_from', 'owner', 'environment',
                       'detail', 'platform')

#: Characters that continue an identifier. A name is replaced only where it
#: stands on its own, so `billing-database` inside `billing-database-replica`
#: is still caught (the hyphen is not in this set and the match is an
#: over-redaction, which is the safe direction) while `hr` is not found
#: inside `three`.
_IDENT = r'A-Za-z0-9_'


def _names_of(node: dict) -> set[str]:
    """Every string one crown jewel is known by."""
    from ..connectors.resolve import normalise_key
    names = set()
    for field in ('id', 'key', 'label', 'arn'):
        value = node.get(field)
        if value:
            names.add(str(value))
    for alias in node.get('resolved_from') or ():
        names.add(str(alias))
    normalised = normalise_key(str(node.get('key') or ''))
    if normalised:
        names.add(normalised)
    # A one-character name would match punctuation-delimited fragments all
    # over a response and carries no meaning worth protecting.
    return {name for name in names if len(name) >= 2}


def crown_index(estate) -> tuple[Any, dict[str, str]]:
    """Compile every crown jewel name in an estate into one pattern.

    Built once per estate object and kept on it, because a per-request
    compile over a few hundred alternatives would cost more than the query.
    Returns (pattern or None, lowercased name -> node id).
    """
    cached = getattr(estate, '_crown_index', None)
    if cached is not None:
        return cached
    owners: dict[str, str] = {}
    for node in getattr(estate, 'nodes', None) or ():
        if not node.get('crown'):
            continue
        node_id = str(node.get('id', ''))
        for name in _names_of(node):
            owners.setdefault(name.lower(), node_id)
    if owners:
        # Longest first, so `s3://nightly-backups` is replaced whole before
        # `nightly-backups` gets the chance to leave `s3://` behind.
        ordered = sorted(owners, key=len, reverse=True)
        pattern = re.compile(
            r'(?<![%s])(?:%s)(?![%s])' % (_IDENT, '|'.join(map(re.escape, ordered)),
                                         _IDENT),
            re.IGNORECASE)
        index = (pattern, owners)
    else:
        index = (None, {})
    try:
        estate._crown_index = index
    except AttributeError:
        pass        # an estate that refuses attributes is rebuilt each time
    return index

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

    def __init__(self, principal: Principal, *, salt: bytes, estate=None):
        self.principal = principal
        self.salt = salt
        self.may_reveal = principal.can(Permission.CROWN_REVEAL)
        self.redacted_count = 0
        self._pattern, self._owners = (crown_index(estate) if estate is not None
                                       and not self.may_reveal else (None, {}))

    def _alias(self, node_id: str) -> str:
        return pseudonym(node_id, organization=self.principal.organization,
                         salt=self.salt)

    def scrub(self, text: str) -> str:
        """Replace every crown jewel name in a string with its pseudonym."""
        if self._pattern is None or not text:
            return text

        def swap(match):
            self.redacted_count += 1
            return self._alias(self._owners[match.group(0).lower()])

        return self._pattern.sub(swap, text)

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
        if record.get('redacted'):
            # Already masked. Masking again would derive a pseudonym from the
            # pseudonym, so one crown jewel would carry two names in one
            # response depending on how many times it passed through here.
            return record
        self.redacted_count += 1
        alias = self._alias(str(record.get('id', '')))
        masked = dict(record)
        masked['id'] = alias
        masked['key'] = alias
        masked['label'] = alias
        for field in _IDENTIFYING_FIELDS:
            masked.pop(field, None)
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
        if self.may_reveal:
            return value
        if isinstance(value, dict):
            if 'id' in value and ('crown' in value or 'is_crown_jewel' in value):
                value = self.node(value)
            return {k: self.walk(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.walk(item) for item in value]
        if isinstance(value, str):
            return self.scrub(value)
        return value

    def finish(self, payload: dict) -> dict:
        """Attach the notice when anything was removed."""
        if self.redacted_count:
            payload = dict(payload)
            payload['_redaction'] = dict(REDACTION_NOTICE,
                                         nodes_redacted=self.redacted_count)
        return payload


def redact(payload: dict, principal: Principal, *, salt: bytes,
           estate=None) -> dict:
    """Convenience wrapper: walk a response and stamp the notice.

    `estate` supplies the crown jewel names to scrub from text. Without it
    only node-shaped dicts are masked, which is the behaviour that leaked.
    """
    redactor = Redactor(principal, salt=salt, estate=estate)
    return redactor.finish(redactor.walk(payload))
