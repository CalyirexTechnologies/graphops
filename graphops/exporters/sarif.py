"""SARIF 2.1.0.

SARIF is the format GitHub code scanning, Azure DevOps and most IDEs already
render, so emitting it puts an attack path in the same queue a developer
already works. The mapping is not a perfect fit and the places it bends are
marked rather than smoothed over.

A SARIF `result` wants a physical location, meaning a file and a line. An
attack path has neither. Rather than invent a path, each result uses a
`logicalLocation` with the node's fully qualified name, which is exactly what
the specification provides for findings that are not about a file.

Severity maps to SARIF `level`, which has only error, warning, note and none.
Critical and high both become `error`, and `rank` carries the finer ordering,
because losing the distinction entirely would reorder somebody's queue.
"""
from __future__ import annotations

SCHEMA = ('https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/'
          'sarif-2.1/schema/sarif-schema-2.1.0.json')

_LEVEL = {'critical': 'error', 'high': 'error',
          'medium': 'warning', 'low': 'note'}
#: SARIF rank is 0.0 to 100.0, higher being more important.
_RANK = {'critical': 100.0, 'high': 75.0, 'medium': 50.0, 'low': 25.0}


def to_sarif(estate) -> dict:
    from ..findings import derive

    produced = derive(estate)

    # One rule per finding kind, which is what a SARIF consumer groups by.
    kinds = sorted({f['kind'] for f in produced})
    rules = [{
        'id': 'graphops/%s' % kind,
        'name': ''.join(part.title() for part in kind.split('-')),
        'shortDescription': {'text': _RULE_TEXT.get(kind, kind)},
        'fullDescription': {'text': _RULE_LONG.get(kind, _RULE_TEXT.get(kind, kind))},
        'defaultConfiguration': {'level': 'error'},
        'properties': {'tags': ['security', 'graph', kind]},
    } for kind in kinds]
    rule_index = {kind: index for index, kind in enumerate(kinds)}

    results = []
    for finding in produced:
        node = (finding.get('node') or finding.get('identity')
                or {'id': finding.get('target') or 'estate'})
        results.append({
            'ruleId': 'graphops/%s' % finding['kind'],
            'ruleIndex': rule_index[finding['kind']],
            'level': _LEVEL.get(finding['severity'], 'warning'),
            'rank': _RANK.get(finding['severity'], 50.0),
            'message': {'text': finding['title']},
            # No physicalLocation on purpose. See the module docstring.
            'locations': [{'logicalLocations': [{
                'name': str(node.get('key') or node.get('id') or 'estate'),
                'fullyQualifiedName': str(node.get('id') or 'estate'),
                'kind': str(node.get('kind') or 'resource'),
            }]}],
            'partialFingerprints': {'graphopsFingerprint/v1':
                                    finding['fingerprint']},
            'properties': {'routes': finding.get('routes', 0),
                           'remediation': finding.get('remediation', '')},
        })

    return {
        '$schema': SCHEMA,
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'GraphOps',
                'informationUri': 'https://example.invalid/graphops',
                'rules': rules,
            }},
            'results': results,
            'columnKind': 'utf16CodeUnits',
        }],
    }


_RULE_TEXT = {
    'choke-point': 'A node that several attack paths pass through.',
    'attack-path': 'A route from untrusted ground to regulated data.',
    'over-privilege': 'Standing access that has never been exercised.',
    'novel-activity': 'Newly reachable systems that no rule fired on.',
}

_RULE_LONG = {
    'choke-point': ('Several independent routes to regulated data pass '
                    'through this one node, so remediating it removes more '
                    'routes than fixing any single vulnerability on them.'),
    'attack-path': ('A path exists from an untrusted source to a system '
                    'holding regulated data. Ranked by attacker effort '
                    'rather than hop count.'),
    'over-privilege': ('An identity is entitled to reach a system and has '
                       'never done so. The grant is a live attack step '
                       'whether or not anyone has used it.'),
    'novel-activity': ('The structure of the graph changed in a way that no '
                       'individual detection rule covers, because each step '
                       'on its own is ordinary.'),
}
