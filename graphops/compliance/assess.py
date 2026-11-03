"""Assess controls against what the graph can see.

The one rule, repeated from `controls.py` because it is the part that is
easy to erode: a control with no contradicting evidence is `not-assessed`,
never `satisfied`. Reporting green on silence is how a compliance dashboard
becomes actively harmful, and it is a single edit away at all times, so the
test suite asserts it directly.
"""
from __future__ import annotations

from .controls import Control, controls_for

NOT_SATISFIED = 'not-satisfied'
NOT_ASSESSED = 'not-assessed'


def _evidence_for(control: Control, findings) -> list[dict]:
    return [f for f in findings if f['kind'] in control.contradicted_by]


def assess(estate, *, framework: str = 'soc2') -> dict:
    from ..findings import derive

    findings = derive(estate)
    controls = controls_for(framework)

    assessed: list[dict] = []
    contradicted = 0
    for control in controls:
        evidence = _evidence_for(control, findings)
        if evidence:
            contradicted += 1
        worst = min((f['severity'] for f in evidence),
                    key=lambda s: ('critical', 'high', 'medium', 'low').index(s),
                    default=None)
        assessed.append({
            'id': control.id,
            'framework': control.framework,
            'title': control.title,
            'question': control.question,
            # Only two outcomes are possible. There is deliberately no
            # 'satisfied'.
            'status': NOT_SATISFIED if evidence else NOT_ASSESSED,
            'severity': worst,
            'evidence_count': len(evidence),
            'evidence': [{'fingerprint': f['fingerprint'],
                          'title': f['title'],
                          'severity': f['severity']} for f in evidence],
        })

    return {
        'framework': framework,
        'controls': assessed,
        'controls_assessed': len(controls),
        'controls_contradicted': contradicted,
        'disclaimer': (
            'This is structural evidence from telemetry, not an audit '
            'opinion. A control with no contradicting evidence is reported '
            'as not-assessed rather than satisfied, because the absence of '
            'evidence in this graph is not evidence that the control '
            'operates.'),
    }
