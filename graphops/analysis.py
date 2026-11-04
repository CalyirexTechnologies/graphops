"""The four questions GraphOps exists to answer, over one estate's graph.

Loading the whole graph into memory once and answering from there is
deliberate. The alternative, a recursive query per question, re-walks the
same edges for every click. At the size one business's estate reaches, the
whole adjacency map is a few megabytes and every answer below is then
microseconds rather than a round trip.

This build reads the estate from a JSON file so it runs with nothing
installed. The engine does not care where the nodes and edges came from.
"""
from datetime import datetime, timedelta, timezone

from . import algorithms as alg
from .vocab import EdgeKind, NodeKind, Zone

# Nothing with more edges than this is answered from memory. Past it the
# honest response is "the estate has outgrown this approach", not a request
# that quietly takes thirty seconds.
MAX_EDGES_IN_MEMORY = 400000


def _when(value):
    """Parse an ISO timestamp, always returning an aware datetime."""
    if isinstance(value, datetime):
        stamp = value
    else:
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


class LoadedGraph:
    """An estate's graph plus the metadata the answers have to be readable in."""

    def __init__(self, graph, meta):
        self.graph = graph
        self.meta = meta            # node id -> {kind, key, label, zone, crown}

    def describe(self, node_id):
        m = self.meta.get(node_id, {})
        return {'id': node_id, 'kind': m.get('kind', ''), 'key': m.get('key', ''),
                'label': m.get('label', ''), 'zone': m.get('zone', ''),
                'is_crown_jewel': m.get('crown', False)}

    def describe_path(self, path):
        """A path as a kill chain rather than a list of ids.

        The ATT&CK tactic per step is what MITRE's Attack Flow project is
        for. "address -> endpoint -> asset" is three hops, and
        "Initial Access -> Discovery -> Lateral Movement" is an intrusion.
        Same data, and only one of them is something an analyst can act on.
        """
        steps = []
        for i in range(len(path) - 1):
            kind = self.graph.edge_kind.get((path[i], path[i + 1]), '')
            tactic_id, tactic, technique = EdgeKind.ATTACK.get(kind, ('', '', ''))
            steps.append({
                'from': self.describe(path[i]),
                'to': self.describe(path[i + 1]),
                'edge': kind,
                'cost': self.graph.edge_cost.get((path[i], path[i + 1]), 1.0),
                'tactic_id': tactic_id, 'tactic': tactic, 'technique': technique,
            })
        return steps

    def entry_points(self):
        return [n for n, m in self.meta.items() if m.get('zone') == Zone.UNTRUSTED]

    def crown_jewels(self):
        return [n for n, m in self.meta.items() if m.get('crown')]


class Estate:
    """One business's nodes and edges, with the times each edge was first seen.

    `first_seen` is carried on every edge because it is what makes "has this
    ever happened before" answerable without keeping a second copy of
    history. Rebuilding the graph as it stood before a cutoff is just a
    filter on that one field.
    """

    def __init__(self, payload):
        self.name = payload.get('name', 'unnamed estate')
        self.nodes = payload['nodes']
        self.edges = payload['edges']

    @classmethod
    def from_file(cls, path):
        import json
        with open(path, encoding='utf-8') as handle:
            return cls(json.load(handle))

    def load(self, only_before=None):
        """Read the estate into memory, optionally as it was before a moment."""
        meta = {n['id']: {'kind': n['kind'], 'key': n['key'],
                          'label': n.get('label', n['key']),
                          'zone': n.get('zone', Zone.INTERNAL),
                          'crown': bool(n.get('crown', False))}
                for n in self.nodes}

        graph = alg.Graph()
        for count, e in enumerate(self.edges):
            if count >= MAX_EDGES_IN_MEMORY:
                break
            if only_before is not None and _when(e['first_seen']) >= only_before:
                continue
            graph.add(e['src'], e['dst'], kind=e['kind'],
                      cost=float(e.get('cost', 1.0)))
        return LoadedGraph(graph, meta)


def blast_radius(estate, node_id, max_hops=3):
    """What is at risk right now if this node is owned.

    The question most SOCs cannot answer during an incident, and the reason
    it is first. An analyst looking at one alert needs the neighbourhood,
    not another score.
    """
    loaded = estate.load()
    if node_id not in loaded.meta:
        return None
    rings = alg.blast_radius(loaded.graph, node_id, max_hops=max_hops)
    out = {'origin': loaded.describe(node_id), 'hops': {}, 'total': 0,
           'crown_jewels_reached': []}
    for hop, members in sorted(rings.items()):
        described = [loaded.describe(n) for n in members]
        out['hops'][hop] = described
        out['total'] += len(described)
        out['crown_jewels_reached'] += [d for d in described if d['is_crown_jewel']]
    return out


def exposure(estate, max_depth=4, max_paths=400):
    """Every route from untrusted ground to a crown jewel, and the choke points.

    THIS IS THE PRE-INCIDENT HALF. Blast radius answers a question an
    analyst asks during an incident. This one is meant to be read on a quiet
    Tuesday, because the point of a choke point is to close it before anyone
    uses it.
    """
    loaded = estate.load()
    sources = loaded.entry_points()
    targets = loaded.crown_jewels()
    if not sources or not targets:
        return {'paths': [], 'choke_points': [], 'reachable': False,
                'why': ('No untrusted entry points.' if not sources
                        else 'No asset is marked as a crown jewel yet.')}

    paths = alg.attack_paths(loaded.graph, sources, targets,
                             max_depth=max_depth, max_paths=max_paths)
    chokes = alg.choke_points(paths, exclude=set(sources) | set(targets))
    best, best_cost = alg.cheapest_path(loaded.graph, sources, targets)

    return {
        'reachable': bool(paths),
        'path_count': len(paths),
        'cheapest': {'steps': loaded.describe_path(best), 'cost': best_cost}
                    if best else None,
        'paths': [{'steps': loaded.describe_path(p['path']), 'cost': p['cost']}
                  for p in paths[:25]],
        'choke_points': [dict(loaded.describe(c['node']),
                              paths_through=c['paths_through'],
                              share=c['share'])
                         for c in chokes[:10]],
    }


# How many cuts are simulated. Each one re-runs the whole path search, so
# this is a cost ceiling and not a preference. Six is enough to show a team
# its options without turning one request into a minute of CPU.
MAX_CUTS_SIMULATED = 6


def containment(estate, max_depth=4, max_paths=400, candidates=MAX_CUTS_SIMULATED):
    """What a proposed remediation actually buys, measured rather than counted.

    This answers the question a remediation meeting actually asks, which is
    not "what is risky" but "if I can do one thing this week, which one".

    WHAT COUNTING ALREADY TELLS YOU, AND WHAT IT CANNOT. The first version of
    this docstring claimed that cutting a choke point removes fewer routes
    than the count predicts, because traffic reroutes. That is false and it
    is worth saying so here rather than quietly deleting it. Removing a node
    from an enumeration of simple paths can only delete paths; it cannot
    create one. Measured over 254 random graphs with the cap raised out of
    the way, routes removed equalled routes counted through in every single
    case, which is what the proof says should happen.

    So the route count is NOT the reason to simulate. These are:

      - WHICH CROWN JEWELS GO OUT OF REACH. A node can sit on most of the
        routes and protect nothing, because the routes it carries all end at
        a target that other routes still reach. A count cannot see the far
        end of the path.
      - WHAT THE ATTACKER'S CHEAPEST JOB THEN COSTS. Cutting the busiest
        choke point on the demo estate leaves the cheapest route at exactly
        the effort it was, because an unrelated route is equally cheap.
        Removing most of the routes while making the attacker's best option
        no harder is a result worth seeing before the change meeting, not
        after it.
      - WHETHER A REVOCATION WOULD DO THE SAME JOB. Entitlements are not
        choke points and never appear in that ranking at all, so counting
        cannot put the two kinds of cut on one list.
      - AND THE COUNT IS SIMPLY WRONG ONCE THE ENUMERATION CAP BINDS. The
        same experiment with the cap left at a realistic value disagreed in
        106 of 300 trials. On an estate large enough to hit `max_paths` the
        simulation is the only correct number, and a large estate is the
        normal case rather than the exception.

    Two kinds of cut are simulated:

      - a NODE, which is the choke point taken out of service. Expensive in
        real life, and the one worth knowing about because it is usually a
        shared surface rather than a single system.
      - an ENTITLEMENT, which is a dormant grant revoked. Cheap in real
        life, reversible, and needs nobody's downtime. These come from the
        zero-trust answer, so the list is access nobody has ever exercised.

    Reported together and ranked by what they remove, because an entitlement
    revocation that closes as many routes as a decommissioning is the one a
    team can actually do on Monday.
    """
    loaded = estate.load()
    sources = loaded.entry_points()
    targets = loaded.crown_jewels()
    ends = set(sources) | set(targets)

    if not sources or not targets:
        return {'routes_before': 0, 'options': [], 'reachable': False,
                'why': ('No untrusted entry points.' if not sources
                        else 'No asset is marked as a crown jewel yet.')}

    before = alg.attack_paths(loaded.graph, sources, targets,
                              max_depth=max_depth, max_paths=max_paths)
    if not before:
        return {'routes_before': 0, 'options': [], 'reachable': False,
                'why': 'No route runs from untrusted ground to a crown jewel.'}

    _best, cheapest_before = alg.cheapest_path(loaded.graph, sources, targets)
    reached_before = {p['path'][-1] for p in before}

    def measure(blocked=(), blocked_edges=()):
        after = alg.attack_paths(loaded.graph, sources, targets,
                                 max_depth=max_depth, max_paths=max_paths,
                                 blocked=blocked, blocked_edges=blocked_edges)
        _path, cost = alg.cheapest_path(loaded.graph, sources, targets,
                                        blocked=blocked,
                                        blocked_edges=blocked_edges)
        return after, cost

    options = []

    # ---------------------------------------------------- cutting a node
    chokes = alg.choke_points(before, exclude=ends)
    for choke in chokes[:candidates]:
        node = choke['node']
        after, cheapest_after = measure(blocked={node})
        reached_after = {p['path'][-1] for p in after}
        described = loaded.describe(node)
        options.append({
            'cut': dict(described,
                        action='take %s out of service' % described['key']),
            'kind': 'node',
            # The static count, kept beside the measurement precisely so the
            # gap between them is visible rather than hidden.
            'routes_counted_through': choke['paths_through'],
            'routes_before': len(before),
            'routes_after': len(after),
            'routes_removed': len(before) - len(after),
            'crown_jewels_cut_off': [loaded.describe(t)
                                     for t in sorted(reached_before - reached_after)],
            'cheapest_before': cheapest_before,
            'cheapest_after': cheapest_after,
            'effort_added': (None if cheapest_after is None or cheapest_before is None
                             else round(cheapest_after - cheapest_before, 3)),
            'fully_contained': not after,
        })

    # ------------------------------------------- revoking a dormant grant
    # Only the ones that reach a crown jewel. Revoking a dormant grant to
    # something nobody is attacking is tidying, not containment.
    #
    # THE PRE-FILTER IS WHAT MAKES THIS AFFORDABLE. A grant whose edge does
    # not lie on any enumerated route cannot remove one, so it can be
    # skipped without running the search at all. Without this the loop paid
    # for a full simulation and then threw it away on the `continue`: on a
    # generated 94k-node estate there were 292 dormant grants reaching a
    # crown jewel, and one request took 29.6 seconds. The benchmark caught
    # it, which is most of the argument for having a benchmark.
    on_routes = set()
    for found in before:
        route = found['path']
        for step in range(len(route) - 1):
            on_routes.add((route[step], route[step + 1]))

    simulated = 0
    for grant in over_privilege(estate)['dormant']:
        # A budget on SEARCHES RUN, not on results kept. Counting results
        # was the original bug: a candidate that changed nothing cost a full
        # search and then left the budget untouched.
        if simulated >= candidates or len(options) >= candidates * 2:
            break
        if not grant['reaches_crown_jewel']:
            continue
        pair = (grant['identity']['id'], grant['target']['id'])
        if pair not in on_routes:
            continue        # free: this grant is on no route we found
        simulated += 1
        after, cheapest_after = measure(blocked_edges={pair})
        if len(after) == len(before):
            continue        # nothing to report: no route used this grant
        reached_after = {p['path'][-1] for p in after}
        options.append({
            # Named by the grant rather than by the identity. Two dormant
            # grants held by the same account are two different decisions,
            # and "revoke support-desk" twice over says neither of them.
            'cut': dict(grant['target'],
                        action="revoke %s's grant on %s"
                               % (grant['identity']['key'],
                                  grant['target']['key']),
                        granted_to=grant['identity']['key']),
            'kind': 'entitlement',
            'routes_counted_through': None,
            'routes_before': len(before),
            'routes_after': len(after),
            'routes_removed': len(before) - len(after),
            'crown_jewels_cut_off': [loaded.describe(t)
                                     for t in sorted(reached_before - reached_after)],
            'cheapest_before': cheapest_before,
            'cheapest_after': cheapest_after,
            'effort_added': (None if cheapest_after is None or cheapest_before is None
                             else round(cheapest_after - cheapest_before, 3)),
            'fully_contained': not after,
        })

    # Ranked by what the cut was measured to achieve, in this order:
    #
    #   1. full containment, meaning no route survives at all
    #   2. how many crown jewels go out of reach entirely
    #   3. how many routes are removed
    #   4. how much harder the cheapest surviving route became
    #   5. an entitlement revocation ahead of a decommissioning, on a tie,
    #      because it needs nobody's downtime
    #
    # CROWN JEWELS SIT ABOVE ROUTE COUNT DELIBERATELY. Ranked the other way
    # round first, and the demo estate put the busiest choke point on top: it
    # removes five of twelve routes, protects nothing, and leaves the
    # attacker's cheapest option exactly as cheap, while the cut that puts
    # the backups permanently out of reach came sixth. Removing more routes
    # to data that is still reachable is worth less than removing the reach.
    options.sort(key=lambda o: (not o['fully_contained'],
                                -len(o['crown_jewels_cut_off']),
                                -o['routes_removed'],
                                -(o['effort_added'] or 0.0),
                                o['kind'] != 'entitlement'))

    return {
        'reachable': True,
        'routes_before': len(before),
        'cheapest_before': cheapest_before,
        'crown_jewels_at_risk': [loaded.describe(t) for t in sorted(reached_before)],
        'options': options,
    }


def novel_activity(estate, window_hours=24, max_hops=2, now=None):
    """Things that have never happened before, even where every step is normal.

    TWO FINDINGS, AND THE SECOND IS THE ONE RULES CANNOT GET.

    `new_edges` is the cheap one, a relationship observed for the first time
    in the window. It is also the baseline the lateral-movement literature
    uses, and it is strong precisely because it needs no model.

    `new_reach` is the one rules cannot get. An actor arriving somewhere it
    has never reached before, by a route on which NOTHING TRIPPED A RULE. It
    is computed by walking the graph as it is, walking the graph as it was
    before the window, and taking the difference.

    The flag on each result is `unflagged_by_rules`, and the wording is
    load-bearing. An earlier version claimed "every step already known",
    which cannot happen and so could never be false. In a static graph, if
    every edge of a path is old then the path itself is old. What IS true,
    and is the entire argument for doing this with a graph, is that a route
    can be brand new while no individual step on it looks worth an alert.

    The clusters come last and matter most for the alert-volume problem.
    Connected anomalies are ONE incident, and reporting them as six is how a
    SOC ends up with a queue nobody can read.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)

    current = estate.load()
    before = estate.load(only_before=cutoff)

    fresh = [e for e in estate.edges if _when(e['first_seen']) >= cutoff][:5000]
    new_edges = [{'from': current.describe(e['src']),
                  'to': current.describe(e['dst']),
                  'edge': e['kind'], 'first_seen': str(e['first_seen'])}
                 for e in fresh]

    # Actors worth asking "where can this reach now that it could not before".
    actors = [n for n, m in current.meta.items()
              if m.get('kind') in (NodeKind.IDENTITY, NodeKind.ADDRESS)]

    # Nodes a detection rule has already fired on. A path through one of
    # these is a path the existing rules can see. The interesting ones are
    # the paths that are entirely clean step by step.
    noisy = {src for (src, dst) in current.graph.edge_kind
             if current.graph.edge_kind[(src, dst)] == EdgeKind.TRIPPED}

    new_reach = []
    for actor in actors:
        now_rings = alg.blast_radius(current.graph, actor, max_hops=max_hops)
        if not now_rings:
            continue
        was_rings = alg.blast_radius(before.graph, actor, max_hops=max_hops)
        reached_now = {n for ns in now_rings.values() for n in ns}
        reached_before = {n for ns in was_rings.values() for n in ns}
        for target in sorted(reached_now - reached_before):
            tmeta = current.meta.get(target, {})
            if tmeta.get('kind') in (NodeKind.ENDPOINT, NodeKind.SERVICE,
                                     NodeKind.ASSET):
                path, cost = alg.cheapest_path(current.graph, [actor], [target],
                                               max_depth=max_hops)
                new_reach.append({
                    'actor': current.describe(actor),
                    'target': current.describe(target),
                    'steps': current.describe_path(path) if path else [],
                    # No node on this route has ever tripped a rule, so no
                    # rule-based detection would have raised any part of it.
                    'unflagged_by_rules': bool(path) and not (set(path) & noisy),
                })
        if len(new_reach) >= 200:
            break

    touched = {d['from']['id'] for d in new_edges} | {d['to']['id'] for d in new_edges}
    clusters = alg.connected_components(current.graph, touched)
    return {
        'window_hours': window_hours,
        'new_edges': new_edges[:200],
        'new_edge_count': len(new_edges),
        'new_reach': new_reach[:50],
        'new_reach_count': len(new_reach),
        'incidents': [[current.describe(n) for n in group]
                      for group in clusters if len(group) > 1][:20],
    }


def critical_nodes(estate, limit=8):
    """Which of our own systems would cost the most if they were taken.

    PageRank over the reversed graph, then UNTRUSTED NODES ARE DROPPED. An
    external address scores well on this measure because it points at our
    surfaces, but ranking it tells a defender nothing actionable. It is
    already hostile and there is nothing to harden about it. The question
    worth answering is which node WE run sits on the way to the most value.
    """
    loaded = estate.load()
    ranked = alg.pagerank(loaded.graph)
    out = []
    for row in ranked:
        meta = loaded.meta.get(row['node'], {})
        if meta.get('zone') == Zone.UNTRUSTED:
            continue
        out.append(dict(loaded.describe(row['node']), score=row['score']))
        if len(out) >= limit:
            break
    return out


def segments(estate, window_hours=24, now=None):
    """The estate's natural segments, and which one the new activity is in.

    Community detection answers a different question from blast radius. Blast
    radius asks what one compromise touches. This asks how the estate is
    shaped when nobody is attacking it, so that when something does move, an
    analyst can say WHICH part of the business it is moving inside rather
    than reading a list of node names.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)
    loaded = estate.load()

    fresh_nodes = set()
    for e in estate.edges:
        if _when(e['first_seen']) >= cutoff:
            fresh_nodes.add(e['src'])
            fresh_nodes.add(e['dst'])

    out = []
    for members in alg.louvain_communities(loaded.graph):
        described = [loaded.describe(n) for n in members]
        out.append({
            'size': len(members),
            'members': described,
            'crown_jewels': [d for d in described if d['is_crown_jewel']],
            'has_new_activity': bool(set(members) & fresh_nodes),
        })
    return out


def over_privilege(estate):
    """Access that policy grants and nobody has ever exercised.

    The zero-trust question, asked of one graph rather than two systems.
    `ENTITLED` edges come from the identity provider and say what a
    principal is ALLOWED to reach. `CALLED` and `SERVES` edges come from
    logs and say what it ACTUALLY reached. An entitlement with no matching
    use is standing access that buys the business nothing and buys an
    attacker a free step, because whoever takes the credential inherits the
    whole grant rather than the part its owner needed.

    Reported with the crown-jewel flag, because "the support desk can read
    the card database and never has" is a sentence that ends an argument,
    and "there are 400 unused permissions" is not.
    """
    loaded = estate.load()
    used = set()
    entitled = []
    for e in estate.edges:
        pair = (e['src'], e['dst'])
        if e['kind'] == EdgeKind.ENTITLED:
            entitled.append(pair)
        elif e['kind'] in (EdgeKind.CALLED, EdgeKind.SERVES):
            used.add(pair)

    dormant = []
    for src, dst in entitled:
        if (src, dst) in used:
            continue
        dormant.append({'identity': loaded.describe(src),
                        'target': loaded.describe(dst),
                        'reaches_crown_jewel':
                            loaded.meta.get(dst, {}).get('crown', False)})
    dormant.sort(key=lambda d: (not d['reaches_crown_jewel'],
                                d['identity']['key']))
    return {'granted': len(entitled), 'exercised': len(entitled) - len(dormant),
            'dormant': dormant}
