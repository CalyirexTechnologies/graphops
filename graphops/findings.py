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

    # Simulated once and reused. Each cut re-runs the whole path search, so
    # calling this per finding would multiply the cost of deriving findings
    # by the number of choke points.
    contained = analysis.containment(estate)
    by_node = {option['cut']['id']: option
               for option in contained.get('options', [])
               if option['kind'] == 'node'}

    # ---- one finding per choke point, not one per route ------------------
    # A choke point is the actionable unit: closing it removes every route
    # through it. Emitting a finding per route would be technically accurate
    # and operationally useless.
    for choke in exposure.get('choke_points', []):
        through = int(choke.get('paths_through', 0))
        if through < 2:
            continue
        # The remediation line used to say only how many routes ran through
        # the node, which is a count rather than an outcome. What a team
        # needs to read is whether making the cut protects anything and
        # whether the attacker's cheapest option gets any harder, and both
        # of those come from making the cut rather than from counting.
        measured = by_node.get(choke['id'])
        protects = [j['key'] for j in measured['crown_jewels_cut_off']] if measured else []
        if measured is None:
            remediation = ('Removing this node removes %d of the %d routes '
                           'found.' % (through, len(paths)))
        elif protects:
            remediation = ('Simulated: removes %d of %d routes and puts %s out '
                           'of reach entirely. Attacker effort for what is '
                           'left goes from %.1f to %s.'
                           % (measured['routes_removed'], measured['routes_before'],
                              ', '.join(protects), measured['cheapest_before'],
                              ('%.1f' % measured['cheapest_after']
                               if measured['cheapest_after'] is not None
                               else 'no route at all')))
        elif measured['effort_added']:
            remediation = ('Simulated: removes %d of %d routes and raises the '
                           'attacker effort for what is left from %.1f to %.1f. '
                           'No crown jewel goes out of reach.'
                           % (measured['routes_removed'], measured['routes_before'],
                              measured['cheapest_before'], measured['cheapest_after']))
        else:
            remediation = ('Simulated: removes %d of %d routes, but every crown '
                           'jewel stays reachable and the cheapest route still '
                           'costs %.1f. Worth doing, and it does not contain '
                           'anything on its own.'
                           % (measured['routes_removed'], measured['routes_before'],
                              measured['cheapest_before']))
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
            'protects_if_cut': protects,
            'effort_added_if_cut': measured['effort_added'] if measured else None,
            'remediation': remediation,
        })

    # ---- the one action worth doing first --------------------------------
    # Ranked by what it was measured to remove rather than by what it sits
    # on, and it may well be an entitlement revocation rather than a system
    # being taken down. That comparison is the thing a count cannot make.
    best = next(iter(contained.get('options', [])), None)
    if best is not None and (best['crown_jewels_cut_off'] or best['fully_contained']):
        cut = best['cut']
        produced.append({
            'id': fingerprint('containment', cut['id'], best['kind']),
            'fingerprint': fingerprint('containment', cut['id'], best['kind']),
            'kind': 'containment',
            'severity': 'critical' if best['fully_contained'] else 'high',
            'title': ('Best single action: %s, which puts %s out of reach'
                      % (cut.get('action', 'cut %s' % cut.get('key')),
                         ', '.join(j['key'] for j in best['crown_jewels_cut_off'])
                         or 'every crown jewel')),
            'node': cut,
            'routes': best['routes_removed'],
            'target': ', '.join(j['key'] for j in best['crown_jewels_cut_off']),
            'remediation': ('Measured by making the cut and running the search '
                            'again: %d of %d routes gone.%s'
                            % (best['routes_removed'], best['routes_before'],
                               '' if best['kind'] != 'entitlement' else
                               ' This one is a grant nobody has ever exercised, '
                               'so revoking it needs no downtime.')),
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
    # One finding per grant that is dormant, and one per privileged grant
    # nothing reports on. The title says which of those it is. "Never used"
    # is a claim and is made only where a source reports use; "not used in
    # 200 days" is a different finding with a different fix; and a role held
    # with no usage data at all is worth raising only when it reaches a crown
    # jewel, and must say that it is unverified rather than unused.
    privilege = analysis.over_privilege(estate)
    for grant in privilege.get('grants', []):
        status = grant.get('status')
        reaches = bool(grant.get('reaches_crown_jewel'))
        if status not in ('never', 'idle') and not (status == 'unknown' and reaches):
            continue
        identity = grant.get('identity', {})
        target = grant.get('target', {})
        who, what = identity.get('key'), target.get('key')
        if status == 'never':
            title = '%s may reach %s and never has' % (who, what)
        elif status == 'idle':
            title = ('%s may reach %s and has not used it in %s%d days'
                     % (who, what, 'at least ' if grant.get('idle_at_least') else '',
                        grant.get('idle_days') or 0))
        else:
            title = ('%s holds %s, and nothing reports whether it is used'
                     % (who, what))
        if identity.get('suspended'):
            title += ', from a suspended account'
        remediation = ('Revoke the grant, or record why it is held. Nobody '
                       'has to be attacked for this to be worth fixing.')
        if status == 'unknown':
            remediation = ('Confirm whether this role is needed. The source '
                           'that grants it does not report use, so the '
                           'answer has to come from the owner.')
        produced.append({
            'id': fingerprint('dormant-entitlement', identity.get('id', ''),
                              target.get('id', '')),
            'fingerprint': fingerprint('dormant-entitlement',
                                       identity.get('id', ''),
                                       target.get('id', '')),
            'kind': 'over-privilege',
            'severity': 'high' if reaches else 'low',
            'title': title,
            'identity': identity,
            'target': what if reaches else None,
            'routes': int(grant.get('routes_through') or 0),
            'grant': {key: grant.get(key) for key in
                      ('status', 'permission', 'via', 'last_used', 'idle_days',
                       'idle_at_least')},
            'remediation': remediation,
        })

    # ---- new structure, and whether anything alerted on it --------------
    # The title used to say every new reach came "from steps no rule fired
    # on" while counting all of them. On the connector estate a Sentinel
    # rule fires on each of the six routes, so the claim was false there,
    # and on the demo estate it was true of two of three. The claim is now
    # made only of the routes it is true of, and the severity follows it:
    # a new reach the rules cannot see is the high finding, and one they
    # already alert on is worth reading for what the alert leaves out.
    novel = analysis.novel_activity(estate)
    reached = int(novel.get('new_reach_count', 0) or 0)
    quiet = int(novel.get('unflagged_count', 0) or 0)
    window = novel.get('window_hours')
    if reached:
        if quiet == reached:
            title = ('%d newly reachable systems in the last %sh, from steps '
                     'no rule fired on' % (reached, window))
        elif quiet:
            title = ('%d newly reachable systems in the last %sh, %d of them by '
                     'steps no rule fired on' % (reached, window, quiet))
        else:
            title = ('%d newly reachable systems in the last %sh, each by a '
                     'route a detection rule fired on' % (reached, window))
        produced.append({
            'id': fingerprint('novel-reach', str(window)),
            'fingerprint': fingerprint('novel-reach', str(window)),
            'kind': 'novel-activity',
            'severity': 'high' if quiet else 'medium',
            'title': title,
            'routes': reached,
            'unflagged': quiet,
            'target': 'newly reachable systems',
            'remediation': (
                'Each individual step here looks ordinary. The structure is '
                'what is new.' if quiet else
                'A rule fired on a step of each route, and the alert names '
                'that step. It does not say what the actor can now reach, '
                'which is what the graph adds.'),
        })

    order = {name: index for index, name in enumerate(SEVERITIES)}
    produced.sort(key=lambda f: (order.get(f['severity'], 99),
                                 -int(f.get('routes', 0) or 0)))
    return produced
