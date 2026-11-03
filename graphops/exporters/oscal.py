"""OSCAL assessment results.

A GRC team's question is not "how many CVEs" but "show me the evidence for
this control". OSCAL is NIST's machine-readable format for exactly that, and
emitting it means the graph's output lands in their tooling rather than in a
screenshot pasted into a spreadsheet.

Only `assessment-results` is produced. Writing a full system security plan
from a telemetry graph would be a claim this cannot support: the graph knows
what is reachable, not what the organisation has promised to do about it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

_NAMESPACE = uuid.UUID('7c1e8a40-3b2d-4e5f-8a9b-0c1d2e3f4a5b')
OSCAL_VERSION = '1.1.2'


def _uuid(value: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, value))


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+00:00')


def to_oscal(estate, *, framework: str = 'soc2') -> dict:
    from ..compliance.assess import assess
    from ..findings import derive

    assessment = assess(estate, framework=framework)
    produced = derive(estate)
    moment = _now()

    observations = []
    findings_out = []

    for finding in produced:
        observation_uuid = _uuid('observation:%s' % finding['fingerprint'])
        observations.append({
            'uuid': observation_uuid,
            'title': finding['title'],
            'description': finding.get('remediation', ''),
            'methods': ['TEST'],
            'types': ['finding'],
            'collected': moment,
            'props': [
                {'name': 'kind', 'value': finding['kind']},
                {'name': 'severity', 'value': finding['severity']},
                {'name': 'routes', 'value': str(finding.get('routes', 0))},
            ],
        })
        findings_out.append({
            'uuid': _uuid('finding:%s' % finding['fingerprint']),
            'title': finding['title'],
            'description': finding.get('remediation', ''),
            'target': {
                'type': 'objective-id',
                'target-id': finding['kind'],
                'status': {'state': 'not-satisfied'},
            },
            'related-observations': [{'observation-uuid': observation_uuid}],
        })

    return {
        'assessment-results': {
            'uuid': _uuid('assessment:%s' % framework),
            'metadata': {
                'title': 'GraphOps assessment results (%s)' % framework.upper(),
                'last-modified': moment,
                'version': '1.0.0',
                'oscal-version': OSCAL_VERSION,
                'roles': [{'id': 'assessor', 'title': 'GraphOps'}],
            },
            'import-ap': {'href': '#graphops-assessment-plan'},
            'results': [{
                'uuid': _uuid('result:%s' % framework),
                'title': 'Reachability assessment',
                'description': ('Control coverage derived from the estate '
                                'graph rather than from questionnaire '
                                'responses.'),
                'start': moment,
                'reviewed-controls': {
                    'control-selections': [{
                        'include-controls': [
                            {'control-id': control['id']}
                            for control in assessment.get('controls', [])
                        ],
                    }],
                },
                'observations': observations,
                'findings': findings_out,
            }],
        }
    }
