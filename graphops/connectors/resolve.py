"""Entity resolution across connectors.

The problem this solves is the one that decides whether a multi-source
security graph works at all.

Okta calls the backups bucket `s3://nightly-backups`. CloudTrail calls it
`arn:aws:s3:::nightly-backups`, which this codebase shortens to
`nightly-backups`. ServiceNow calls the card store `billing-database` and
classifies it PCI; Okta calls the same thing `billing-database` but files it
as an application rather than an asset, so it lands under a different node id.

Left alone, the graph holds two nodes for each, and the consequences are
worse than cosmetic: Okta's entitlement points at one, ServiceNow's crown
classification sits on the other, and the query that should say "support-desk
can reach regulated data and never has" returns nothing. The product looks
like it works and quietly answers the wrong question.

So every node key is normalised to a canonical form, nodes that normalise
alike *and* are the same class of thing are merged, and every edge is
rewritten onto the survivor.

Two guards keep this from over-merging, which would be the worse failure:

  * Resolution happens only within a class. A person called `backup` and a
    bucket called `backup` are never the same node, because an identity and
    a system are different classes and are never compared.
  * The canonical survivor is chosen by evidence. A node a source classified
    explicitly beats one classified by a name heuristic, and the merged
    record keeps `resolved_from` listing every id that fed it, so a reviewer
    can see what was joined rather than taking it on trust.
"""
from __future__ import annotations

import re

from ..vocab import NodeKind

#: Nodes may only merge with nodes in the same class. Within a class the
#: names describe the same kind of thing; across classes they never do.
_CLASSES = {
    NodeKind.ASSET: 'system',
    NodeKind.SERVICE: 'system',
    NodeKind.IDENTITY: 'identity',
    NodeKind.ADDRESS: 'address',
    NodeKind.ENDPOINT: 'endpoint',
    NodeKind.VULNERABILITY: 'vulnerability',
    NodeKind.RULE: 'rule',
}

#: Stripped from the front of a key. Storage and cloud sources each prefix
#: the same object differently.
_SCHEMES = ('s3://', 'gs://', 'azblob://', 'https://', 'http://')

#: Stripped from the end. A CMDB holds short names and a scanner holds FQDNs
#: for the same host.
_INTERNAL_SUFFIXES = ('.internal.invalid', '.internal', '.local',
                      '.corp', '.lan')

_ARN = re.compile(r'^arn:[^:]*:[^:]*:[^:]*:[^:]*:(?P<tail>.+)$')


def normalise_key(key: str) -> str:
    """Reduce a vendor's name for a thing to a comparable form."""
    value = str(key or '').strip().lower()
    if not value:
        return ''
    match = _ARN.match(value)
    if match:
        value = match.group('tail')
    for scheme in _SCHEMES:
        if value.startswith(scheme):
            value = value[len(scheme):]
            break
    # An ARN or path tail may still carry a prefix such as assumed-role/.
    if '/' in value:
        value = value.rsplit('/', 1)[-1]
    value = value.rstrip('/.')
    for suffix in _INTERNAL_SUFFIXES:
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break
    return value


def class_of(node: dict) -> str:
    return _CLASSES.get(node.get('kind'), 'other')


def _evidence_rank(node: dict) -> tuple:
    """Higher sorts first when choosing which id survives.

    Order: an explicit classification beats a heuristic, a real record beats
    one inferred from a dangling edge, more sources beats fewer, and the id
    breaks ties so the result does not depend on dict ordering.
    """
    return (
        1 if node.get('crown_source') else 0,
        0 if node.get('inferred') else 1,
        len(node.get('sources') or []),
        # Prefer ASSET over SERVICE for systems: an asset is the CMDB's word
        # for a thing that exists, a service is often an app entry for it.
        1 if node.get('kind') == NodeKind.ASSET else 0,
        str(node.get('id', '')),
    )


def build_alias_map(nodes) -> dict[str, str]:
    """Map every node id to the id of the node it resolves to."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for node in nodes:
        key = normalise_key(node.get('key') or node.get('id', ''))
        if not key:
            continue
        groups.setdefault((class_of(node), key), []).append(node)

    aliases: dict[str, str] = {}
    for members in groups.values():
        if len(members) == 1:
            continue
        winner = sorted(members, key=_evidence_rank, reverse=True)[0]
        for member in members:
            if member['id'] != winner['id']:
                aliases[member['id']] = winner['id']
    return aliases


def _fold(winner: dict, loser: dict) -> dict:
    """Merge a resolved-away node's information into the survivor."""
    merged = dict(winner)
    for field, value in loser.items():
        if value in (None, '', [], False):
            continue
        if field in ('id', 'key', 'label', 'kind', 'sources', 'resolved_from'):
            continue
        if field == 'crown':
            # A crown classification is never lost by resolution, but a
            # stated source is not overwritten by an inferred one.
            if not merged.get('crown_source'):
                merged['crown'] = bool(merged.get('crown')) or bool(value)
            continue
        if field == 'crown_source' and merged.get('crown_source'):
            continue
        merged.setdefault(field, value)
        if field == 'crown_source':
            merged['crown_source'] = value
            merged['crown'] = True
    merged['sources'] = sorted(set(merged.get('sources') or [])
                               | set(loser.get('sources') or []))
    merged['resolved_from'] = sorted(set(merged.get('resolved_from') or [])
                                     | {loser['id']}
                                     | set(loser.get('resolved_from') or []))
    return merged


def resolve(estate: dict) -> dict:
    """Return a copy of `estate` with duplicate entities merged.

    Reports what it did under `resolution`, because a join that silently
    halves the node count is exactly the kind of thing a reviewer should be
    able to check.
    """
    nodes = estate.get('nodes', [])
    edges = estate.get('edges', [])
    aliases = build_alias_map(nodes)
    if not aliases:
        return dict(estate, resolution={'merged': 0, 'aliases': {}})

    by_id = {node['id']: dict(node) for node in nodes}
    for loser_id, winner_id in aliases.items():
        loser = by_id.pop(loser_id, None)
        winner = by_id.get(winner_id)
        if loser is None or winner is None:
            continue
        by_id[winner_id] = _fold(winner, loser)

    rewritten: list[dict] = []
    seen: set[tuple] = set()
    self_loops = 0
    for edge in edges:
        source = aliases.get(edge['src'], edge['src'])
        target = aliases.get(edge['dst'], edge['dst'])
        if source == target:
            # Two names for one thing had an edge between them. After
            # resolution it is a self-loop and carries no information.
            self_loops += 1
            continue
        signature = (source, target, edge['kind'])
        if signature in seen:
            for existing in rewritten:
                if (existing['src'], existing['dst'],
                        existing['kind']) == signature:
                    if edge.get('cost', 1.0) < existing.get('cost', 1.0):
                        existing.update(dict(edge, src=source, dst=target))
                    break
            continue
        seen.add(signature)
        rewritten.append(dict(edge, src=source, dst=target))

    resolved = dict(estate)
    resolved['nodes'] = list(by_id.values())
    resolved['edges'] = rewritten
    resolved['resolution'] = {
        'merged': len(aliases),
        'self_loops_dropped': self_loops,
        'edges_before': len(edges),
        'edges_after': len(rewritten),
        'aliases': aliases,
    }
    return resolved
