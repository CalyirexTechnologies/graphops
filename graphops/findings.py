"""Turning analysis output into findings somebody can be assigned.

A finding is not an answer. `exposure()` returns twelve routes; a finding is
"these five routes all pass through /api/orders, fix that one thing". The
difference is the whole gap between a tool that produces work and a tool that
produces a list.

Two properties matter and both are tested.

**A stable fingerprint.** The same structural problem must produce the same
finding id across ingest runs, or every re-run opens duplicate tickets and
the integration gets switched off within a week. The fingerprint covers what
the finding is *about*, never when it was seen or how many times.

**Severity from reachability, not from CVSS.** A critical CVE on a host
nothing can reach is not a critical finding. Severity here is a function of
whether a route exists, whether it ends at regulated data, and how cheap it
is for an attacker, which is information no scanner has on its own.
"""
from __future__ import annotations

import hashlib

SEVERITIES = ('critical', 'high', 'medium', 'low')


def fingerprint(kind: str, *parts: str) -> str:
    """A stable id for a finding, covering only what it is about."""
    material = '|'.join([kind] + [str(p) for p in parts])
    return hashlib.sha256(material.encode('utf-8')).hexdigest()[:32]


def _severity_for_route(cost: float, reaches_crown: bool) -> str:
    if not reaches_crown:
        return 'low'
    if cost <= 2.0:
        return 'critical'
    if cost <= 3.5:
        return 'high'
    return 'medium'


def derive(estate) -> list[dict]:
    """Produce the findings for an estate, most severe first."""
    from . import analysis

    produced: list[dict] = []
    exposure = analysis.exposure(estate)
    paths = exposure.get('paths', [])

    # ---- one finding per choke point, not one per route ------------------
    # A choke point is the actionable unit: closing it removes every route
    # through it. Emitting a finding per route would be technically accurate
    # and operationally useless.
    for choke in exposure.get('choke_points', []):
        through = int(choke.get('paths_through', 0))
        if through < 2:
            continue
        produced.append({
            'id': fingerprint('choke-point', choke['id']),
            'fingerprint': fingerprint('choke-point', choke['id']),
            'kind': 'choke-point',
            'severity': 'critical' if through >= 3 else 'high',
            'title': ('%s sits on %d of %d routes to regulated data'
                      % (choke.get('key', choke['id']), through, len(paths))),
            'node': choke,
            'routes': through,
            'target': 'crown jewels',
            'remediation': ('Breaking this one node removes %d of the %d '
                            'routes found.' % (through, len(paths))),
        })

    # ---- the cheapest route ---------------------------------------------
    if paths:
        cheapest = min(paths, key=lambda p: p.get('cost', 99))
        steps = cheapest.get('steps', [])
        if steps:
            start = steps[0]['from']
            end = steps[-1]['to']
            produced.append({
                'id': fingerprint('cheapest-route', start['id'], end['id']),
                'fingerprint': fingerprint('cheapest-route', start['id'], end['id']),
                'kind': 'attack-path',
                'severity': _severity_for_route(cheapest.get('cost', 99), True),
                'title': ('Cheapest route to regulated data: %s to %s in %d hops'
                          % (start.get('key'), end.get('key'), len(steps))),
                'routes': 1,
                'cost': cheapest.get('cost'),
                'target': end.get('key'),
                'path': cheapest,
                'remediation': ('Attacker effort %.1f, the lowest of %d routes.'
                                % (cheapest.get('cost', 0), len(paths))),
            })

    # ---- standing access nobody uses ------------------------------------
    for dormant in analysis.over_privilege(estate).get('dormant', []):
        identity = dormant.get('identity', {})
        target = dormant.get('target', {})
        reaches = bool(dormant.get('reaches_crown_jewel'))
        produced.append({
            'id': fingerprint('dormant-entitlement', identity.get('id', ''),
                              target.get('id', '')),
            'fingerprint': fingerprint('dormant-entitlement',
                                       identity.get('id', ''),
                                       target.get('id', '')),
            'kind': 'over-privilege',
            'severity': 'high' if reaches else 'low',
            'title': ('%s may reach %s and never has'
                      % (identity.get('key'), target.get('key'))),
            'identity': identity,
            'target': target.get('key') if reaches else None,
            'routes': 0,
            'remediation': ('Revoke the grant, or record why it is held. '
                            'Nobody has to be attacked for this to be worth '
                            'fixing.'),
        })

    # ---- new structure nothing alerted on -------------------------------
    novel = analysis.novel_activity(estate)
    unflagged = int(novel.get('new_reach_count', 0) or 0)
    if unflagged:
        produced.append({
            'id': fingerprint('novel-reach', str(novel.get('window_hours'))),
            'fingerprint': fingerprint('novel-reach',
                                       str(novel.get('window_hours'))),
            'kind': 'novel-activity',
            'severity': 'high',
            'title': ('%d newly reachable systems in the last %sh, from steps '
                      'no rule fired on'
                      % (unflagged, novel.get('window_hours'))),
            'routes': unflagged,
            'target': 'newly reachable systems',
            'remediation': ('Each individual step here looks ordinary. The '
                            'structure is what is new.'),
        })

    order = {name: index for index, name in enumerate(SEVERITIES)}
    produced.sort(key=lambda f: (order.get(f['severity'], 99),
                                 -int(f.get('routes', 0) or 0)))
    return produced
