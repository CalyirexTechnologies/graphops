"""Control definitions, and what graph evidence bears on each one.

The claim being made here is narrow and worth stating exactly, because
compliance mapping is where security products overreach hardest.

This does **not** say an organisation is SOC 2 compliant. Compliance is a
judgement an auditor makes about design and operating effectiveness over a
period, and no telemetry graph can make it. What this does is answer, for a
small set of controls, the one question the graph genuinely knows: is there
structural evidence against this control right now.

So every control below carries a `question` naming what the graph actually
checks, and an assessment returns `not-satisfied` only when a finding
contradicts the control. Absence of evidence is reported as `not-assessed`,
never as `satisfied`. A tool that reports a green control because it had no
data is worse than no tool.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    id: str
    framework: str
    title: str
    #: What the graph can actually determine. Narrower than the control.
    question: str
    #: Finding kinds that contradict this control.
    contradicted_by: tuple[str, ...]


SOC2 = (
    Control('CC6.1', 'soc2',
            'Logical access security over protected information assets',
            'Does a route exist from an untrusted source to a system holding '
            'regulated data?',
            ('attack-path', 'choke-point')),
    Control('CC6.2', 'soc2',
            'Registration and authorisation of new internal and external users',
            'Are there identities entitled to regulated data that have never '
            'exercised the grant?',
            ('over-privilege',)),
    Control('CC6.3', 'soc2',
            'Role-based access and least privilege',
            'Is standing access broader than observed use?',
            ('over-privilege',)),
    Control('CC7.2', 'soc2',
            'Monitoring for anomalies indicative of malicious acts',
            'Did the reachable structure change without any detection rule '
            'firing?',
            ('novel-activity',)),
)

ISO27001 = (
    Control('A.5.15', 'iso27001', 'Access control',
            'Does a route exist from an untrusted source to regulated data?',
            ('attack-path', 'choke-point')),
    Control('A.5.18', 'iso27001', 'Access rights',
            'Are access rights held beyond demonstrated need?',
            ('over-privilege',)),
    Control('A.8.16', 'iso27001', 'Monitoring activities',
            'Is new reachability appearing without a corresponding alert?',
            ('novel-activity',)),
)

CIS = (
    Control('5.4', 'cis', 'Restrict administrator privileges',
            'Are privileged grants held without use?',
            ('over-privilege',)),
    Control('13.1', 'cis', 'Centralise security event alerting',
            'Is structural change going unalerted?',
            ('novel-activity',)),
    Control('4.1', 'cis', 'Establish and maintain a secure configuration process',
            'Do routes reach regulated data from untrusted ground?',
            ('attack-path', 'choke-point')),
)

FRAMEWORKS = {'soc2': SOC2, 'iso27001': ISO27001, 'cis': CIS}


def controls_for(framework: str) -> tuple[Control, ...]:
    try:
        return FRAMEWORKS[framework]
    except KeyError as exc:
        raise ValueError('unknown framework %r; known: %s'
                         % (framework, ', '.join(sorted(FRAMEWORKS)))) from exc
