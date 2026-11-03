"""STIX 2.1 bundle.

Attack paths map onto STIX better than most security output does, because
STIX already has the right three objects. An `attack-pattern` is the
technique on a step, an `infrastructure` object is a system in the estate,
and a `relationship` joins them. The route itself becomes a `grouping`,
which is STIX's own answer to "these objects belong together as one thing".

Identifiers are deterministic UUIDv5 over the node id, so re-exporting an
unchanged estate produces an identical bundle. A consumer deduplicating on
id therefore sees one object rather than a new one per export, which is the
difference between an integration and a flood.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

#: A fixed namespace, so the same node always yields the same STIX id.
_NAMESPACE = uuid.UUID('5f4d2b1e-0c3a-4f6b-9d8e-1a2b3c4d5e6f')

SPEC_VERSION = '2.1'


def _stix_id(kind: str, value: str) -> str:
    return '%s--%s' % (kind, uuid.uuid5(_NAMESPACE, '%s:%s' % (kind, value)))


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def to_stix(estate) -> dict:
    from .. import analysis

    created = _now()
    objects: list[dict] = []
    seen: set[str] = set()

    identity_id = _stix_id('identity', 'graphops')
    objects.append({
        'type': 'identity', 'spec_version': SPEC_VERSION, 'id': identity_id,
        'created': created, 'modified': created,
        'name': 'GraphOps', 'identity_class': 'system',
    })

    def add(obj: dict) -> str:
        if obj['id'] not in seen:
            seen.add(obj['id'])
            objects.append(obj)
        return obj['id']

    exposure = analysis.exposure(estate)
    for index, path in enumerate(exposure.get('paths', [])):
        steps = path.get('steps', [])
        if not steps:
            continue
        member_ids: list[str] = []

        for step in steps:
            for end in ('from', 'to'):
                node = step.get(end, {})
                node_id = node.get('id')
                if not node_id:
                    continue
                if node.get('kind') == 'address':
                    member_ids.append(add({
                        'type': 'ipv4-addr', 'spec_version': SPEC_VERSION,
                        'id': _stix_id('ipv4-addr', node_id),
                        'value': node.get('key', node_id),
                    }))
                else:
                    member_ids.append(add({
                        'type': 'infrastructure', 'spec_version': SPEC_VERSION,
                        'id': _stix_id('infrastructure', node_id),
                        'created': created, 'modified': created,
                        'name': node.get('label') or node.get('key') or node_id,
                        'infrastructure_types': ['workstation'
                                                 if node.get('kind') == 'asset'
                                                 else 'unknown'],
                    }))

            technique = step.get('technique')
            if technique:
                member_ids.append(add({
                    'type': 'attack-pattern', 'spec_version': SPEC_VERSION,
                    'id': _stix_id('attack-pattern', technique),
                    'created': created, 'modified': created,
                    'name': step.get('tactic') or technique,
                    'external_references': [{
                        'source_name': 'mitre-attack',
                        'external_id': technique,
                        'url': 'https://attack.mitre.org/techniques/%s/'
                               % technique.replace('.', '/'),
                    }],
                }))

        target = steps[-1].get('to', {})
        add({
            'type': 'grouping', 'spec_version': SPEC_VERSION,
            'id': _stix_id('grouping', 'route-%s-%s'
                           % (steps[0].get('from', {}).get('id'),
                              target.get('id'))),
            'created': created, 'modified': created,
            'created_by_ref': identity_id,
            'name': 'Attack path %d to %s' % (index + 1,
                                              target.get('key', 'a crown jewel')),
            'context': 'suspicious-activity',
            'object_refs': list(dict.fromkeys(member_ids)),
        })

    return {
        'type': 'bundle',
        'id': 'bundle--%s' % uuid.uuid5(_NAMESPACE, 'graphops-export'),
        'objects': objects,
    }
