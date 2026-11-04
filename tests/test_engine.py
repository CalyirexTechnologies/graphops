"""The graph engine itself: the algorithms and the four questions.

THIS FILE EXISTS BECAUSE IT DID NOT. The suite covered identity, RBAC, the
audit chain, the connectors and the API, and reached the algorithms only
sideways through API responses. Centrality and community detection, both
named explicitly in the brief, had no test asserting they did anything in
particular, and `estate.py` had no test at all.

Every test below asserts a claim made in a docstring or in the write-up, so
a claim that stops being true fails here rather than in a demo.
"""
import random
from datetime import datetime, timedelta, timezone

import pytest

from graphops import algorithms as alg
from graphops import analysis
from graphops import estate as estate_module
from graphops.vocab import EdgeKind, NodeKind, Zone

# --------------------------------------------------------------------------
# Graph construction
# --------------------------------------------------------------------------

def test_a_repeated_edge_keeps_the_cheapest_way_of_making_the_step():
    """Two observations of one relationship are not two obstacles.

    The graph is built from several sources, so the same pair arrives more
    than once. Keeping the dearer cost would make an attacker's job look
    harder every time another tool confirmed the same thing.
    """
    graph = alg.Graph()
    graph.add('a', 'b', kind=EdgeKind.SERVES, cost=5.0)
    graph.add('a', 'b', kind=EdgeKind.YIELDS, cost=1.0)
    graph.add('a', 'b', kind=EdgeKind.EXPOSES, cost=9.0)

    assert graph.edge_cost[('a', 'b')] == 1.0
    # The kind travels with the cost it was recorded against, or the path
    # would report a tactic belonging to a step nobody is taking.
    assert graph.edge_kind[('a', 'b')] == EdgeKind.YIELDS
    assert graph.out['a'] == ['b'], 'the pair must not be listed twice'
    assert graph.inc['b'] == ['a']


def test_both_endpoints_of_an_edge_become_nodes():
    graph = alg.Graph()
    graph.add('a', 'b')
    assert graph.nodes == {'a', 'b'}


# --------------------------------------------------------------------------
# Blast radius
# --------------------------------------------------------------------------

def test_blast_radius_reports_each_node_at_its_shallowest_hop_only():
    """A node two steps away must not also pad the three-hop ring.

    Listing it twice makes the near ring look larger than the danger it
    describes, which is the number an analyst reads first during an incident.
    """
    graph = alg.Graph()
    graph.add('origin', 'near')
    graph.add('near', 'far')
    graph.add('origin', 'far')       # also reachable in one hop

    rings = alg.blast_radius(graph, 'origin', max_hops=3)
    assert set(rings[1]) == {'near', 'far'}
    assert rings.get(2, []) == [], 'already counted at hop 1'


def test_blast_radius_ignores_the_direction_the_log_happened_to_record():
    """Compromise does not respect edge direction.

    If an identity acted from an address, holding the address tells you
    about the identity and holding the identity tells you about the address.
    """
    graph = alg.Graph()
    graph.add('address', 'identity')

    assert 'address' in alg.blast_radius(graph, 'identity', max_hops=1)[1]
    assert 'identity' in alg.blast_radius(graph, 'address', max_hops=1)[1]


def test_blast_radius_cannot_be_asked_to_walk_past_the_hard_ceiling():
    """An unbounded walk over attacker-influenced data is a denial of service."""
    graph = alg.Graph()
    for i in range(40):
        graph.add('n%d' % i, 'n%d' % (i + 1))

    rings = alg.blast_radius(graph, 'n0', max_hops=999)
    assert max(rings) == alg.MAX_DEPTH


def test_blast_radius_stops_at_the_node_limit():
    graph = alg.Graph()
    for i in range(500):
        graph.add('hub', 'leaf%d' % i)

    rings = alg.blast_radius(graph, 'hub', max_hops=2, limit=10)
    assert sum(len(ring) for ring in rings.values()) < 500


# --------------------------------------------------------------------------
# Cheapest path. This is the headline claim about ranking.
# --------------------------------------------------------------------------

def test_the_cheapest_route_can_be_longer_than_the_shortest_one():
    """Effort, not hops. This is the whole argument against BloodHound CE's
    unweighted pathing, and the reason the write-up can say the cheapest
    route is not the obvious one.
    """
    graph = alg.Graph()
    # Two hops, but each needs an exploit landed.
    graph.add('start', 'hard', kind=EdgeKind.EXPOSES, cost=5.0)
    graph.add('hard', 'goal', kind=EdgeKind.EXPOSES, cost=5.0)
    # Three hops of reusing credentials the attacker already holds.
    graph.add('start', 'easy1', kind=EdgeKind.YIELDS, cost=1.0)
    graph.add('easy1', 'easy2', kind=EdgeKind.ENTITLED, cost=1.0)
    graph.add('easy2', 'goal', kind=EdgeKind.CALLED, cost=1.0)

    path, cost = alg.cheapest_path(graph, ['start'], ['goal'])
    assert path == ['start', 'easy1', 'easy2', 'goal']
    assert cost == 3.0
    assert len(path) > 3, 'the cheap route is the long one here, by design'


def test_cheapest_path_returns_nothing_when_the_target_is_unreachable():
    graph = alg.Graph()
    graph.add('a', 'b')
    assert alg.cheapest_path(graph, ['a'], ['elsewhere']) == (None, None)


def test_cheapest_path_with_no_targets_is_not_an_error():
    graph = alg.Graph()
    graph.add('a', 'b')
    assert alg.cheapest_path(graph, ['a'], []) == (None, None)


def test_cheapest_path_will_not_walk_past_its_depth_bound():
    graph = alg.Graph()
    for i in range(20):
        graph.add('n%d' % i, 'n%d' % (i + 1), cost=1.0)

    assert alg.cheapest_path(graph, ['n0'], ['n20'], max_depth=3) == (None, None)
    path, _cost = alg.cheapest_path(graph, ['n0'], ['n3'], max_depth=3)
    assert path == ['n0', 'n1', 'n2', 'n3']


# --------------------------------------------------------------------------
# Path enumeration
# --------------------------------------------------------------------------

def test_a_cycle_does_not_become_an_infinite_route():
    graph = alg.Graph()
    graph.add('a', 'b')
    graph.add('b', 'c')
    graph.add('c', 'a')          # back to the start
    graph.add('c', 'goal')

    paths = alg.attack_paths(graph, ['a'], ['goal'])
    assert [p['path'] for p in paths] == [['a', 'b', 'c', 'goal']]


def test_two_routes_through_one_node_are_both_kept():
    """A path-local visited set, not a global one. Collapsing these would
    undercount the choke point they share, which is the number the whole
    remediation argument rests on.
    """
    graph = alg.Graph()
    graph.add('in1', 'shared')
    graph.add('in2', 'shared')
    graph.add('shared', 'goal')

    paths = alg.attack_paths(graph, ['in1', 'in2'], ['goal'])
    assert len(paths) == 2


def test_paths_come_back_cheapest_first():
    graph = alg.Graph()
    graph.add('in', 'dear', cost=9.0)
    graph.add('dear', 'goal', cost=1.0)
    graph.add('in', 'cheap', cost=1.0)
    graph.add('cheap', 'goal', cost=1.0)

    paths = alg.attack_paths(graph, ['in'], ['goal'])
    assert [p['cost'] for p in paths] == [2.0, 10.0]


def test_path_enumeration_is_bounded_even_on_a_dense_graph():
    """The bound is what stops one analyst click costing unbounded CPU."""
    graph = alg.Graph()
    for i in range(30):
        for j in range(30):
            if i != j:
                graph.add('n%d' % i, 'n%d' % j)
    for i in range(30):
        graph.add('n%d' % i, 'goal')

    paths = alg.attack_paths(graph, ['n0'], ['goal'], max_depth=6, max_paths=50)
    assert len(paths) <= 50


def test_a_source_that_is_not_in_the_graph_is_skipped_quietly():
    graph = alg.Graph()
    graph.add('a', 'goal')
    assert len(alg.attack_paths(graph, ['a', 'ghost'], ['goal'])) == 1


# --------------------------------------------------------------------------
# Choke points
# --------------------------------------------------------------------------

def test_a_choke_point_is_counted_once_per_route_it_sits_on():
    paths = [
        {'path': ['in1', 'hub', 'goal'], 'cost': 2.0},
        {'path': ['in2', 'hub', 'goal'], 'cost': 2.0},
        {'path': ['in3', 'other', 'goal'], 'cost': 2.0},
    ]
    chokes = alg.choke_points(paths)
    assert chokes[0] == {'node': 'hub', 'paths_through': 2,
                         'share': round(2 / 3, 4)}


def test_the_ends_of_a_route_are_not_choke_points_on_it():
    """Every route runs through its own source and target, so scoring them
    tells you only what you already asked for.
    """
    paths = [{'path': ['in', 'middle', 'goal'], 'cost': 2.0}]
    nodes = {c['node'] for c in alg.choke_points(paths, exclude={'in', 'goal'})}
    assert nodes == {'middle'}


def test_no_paths_means_no_choke_points_rather_than_a_division_by_zero():
    assert alg.choke_points([]) == []


# --------------------------------------------------------------------------
# Centrality. Named in the brief; previously untested.
# --------------------------------------------------------------------------

def test_pagerank_ranks_the_way_in_above_the_thing_worth_stealing():
    """Read on the REVERSED graph, and this is the test that proves it.

    Edges point the way an attacker travels, so forwards the rank piles up
    on the crown jewel and tells a defender what they already knew. The
    question worth answering is which node LEADS to value, and the answer
    here must be the entry node rather than the target.
    """
    graph = alg.Graph()
    graph.add('entry', 'middle')
    graph.add('middle', 'treasure')

    ranked = alg.pagerank(graph)
    order = [row['node'] for row in ranked]
    assert order.index('entry') < order.index('treasure'), (
        'rank must flow back towards the way in, not forwards onto the prize')


def test_a_gateway_to_deep_value_outranks_one_with_the_same_degree():
    """Recursive, which is why it beats raw degree.

    MIND THE DIRECTION. An edge `x -> y` means an attacker standing on x can
    reach y, so a node that LEADS somewhere is the source of its edges. Both
    nodes below have exactly three outgoing edges, so degree cannot separate
    them. What separates them is what lies beyond: `gateway` opens onto three
    systems that each open onto three more, and `shallow` opens onto three
    dead ends.

    Written the other way round first, with the edges pointing INTO the two
    nodes, and the two scored identically to six decimal places. That is the
    right answer for that graph, because neither node receives any rank on
    the reversed graph. The test was wrong, not the algorithm.
    """
    graph = alg.Graph()
    for i in range(3):
        graph.add('gateway', 'tier1-%d' % i)
        for j in range(3):
            graph.add('tier1-%d' % i, 'treasure-%d-%d' % (i, j))
    for i in range(3):
        graph.add('shallow', 'deadend-%d' % i)

    scores = {row['node']: row['score'] for row in alg.pagerank(graph)}
    assert scores['gateway'] > scores['shallow']


def test_pagerank_scores_still_sum_to_one_with_dangling_nodes():
    """Dangling nodes would otherwise leak rank out of the system.

    A node with no outgoing edge is the normal case here, not an edge case:
    every crown jewel is one.
    """
    graph = alg.Graph()
    graph.add('a', 'b')
    graph.add('b', 'c')          # c dangles in the reversed graph
    graph.add('d', 'b')

    total = sum(row['score'] for row in alg.pagerank(graph))
    assert total == pytest.approx(1.0, abs=1e-6)


def test_pagerank_on_an_empty_graph_is_empty_rather_than_an_error():
    assert alg.pagerank(alg.Graph()) == []


# --------------------------------------------------------------------------
# Community detection. Also named in the brief; also previously untested.
# --------------------------------------------------------------------------

def test_louvain_separates_two_clusters_joined_by_a_single_weak_link():
    """Two triangles and one expensive edge between them.

    The edge weight is the INVERSE of attacker effort, because modularity
    wants affinity and the graph stores difficulty. A dear edge is therefore
    a weak tie, and the two triangles must stay apart.
    """
    graph = alg.Graph()
    for a, b in (('a1', 'a2'), ('a2', 'a3'), ('a3', 'a1')):
        graph.add(a, b, cost=1.0)
    for a, b in (('b1', 'b2'), ('b2', 'b3'), ('b3', 'b1')):
        graph.add(a, b, cost=1.0)
    graph.add('a1', 'b1', cost=10.0)      # the weak tie

    groups = alg.louvain_communities(graph)
    assert len(groups) == 2
    assert sorted(groups, key=lambda g: g[0]) == [['a1', 'a2', 'a3'],
                                                  ['b1', 'b2', 'b3']]


def test_louvain_can_be_restricted_to_a_subset_of_the_graph():
    """It is run over anomalous nodes rather than the whole estate."""
    graph = alg.Graph()
    graph.add('x1', 'x2', cost=1.0)
    graph.add('x2', 'x3', cost=1.0)
    graph.add('unrelated1', 'unrelated2', cost=1.0)

    groups = alg.louvain_communities(graph, among={'x1', 'x2', 'x3'})
    assert [n for group in groups for n in group] == ['x1', 'x2', 'x3']


def test_louvain_on_nodes_with_no_edges_between_them_returns_singletons():
    graph = alg.Graph()
    graph.add('a', 'b')
    groups = alg.louvain_communities(graph, among={'a', 'lonely'})
    assert sorted(groups) == [['a'], ['lonely']]


def test_louvain_on_an_empty_selection_is_empty():
    assert alg.louvain_communities(alg.Graph()) == []


# --------------------------------------------------------------------------
# Connected components, used to collapse several alerts into one incident
# --------------------------------------------------------------------------

def test_connected_anomalies_are_reported_as_one_incident():
    """Six alerts that are one intrusion should arrive as one thing.

    This is the alert-volume complaint SOC teams actually have, and it is
    why the clustering is run over the anomalous nodes rather than printed
    per edge.
    """
    graph = alg.Graph()
    graph.add('a', 'b')
    graph.add('b', 'c')
    graph.add('far1', 'far2')

    groups = alg.connected_components(graph, {'a', 'b', 'c', 'far1', 'far2'})
    assert groups == [['a', 'b', 'c'], ['far1', 'far2']]


def test_components_ignore_edges_that_leave_the_selection():
    """Two anomalous nodes joined only via a third, ordinary node are two
    incidents, not one. Otherwise every cluster grows through the hub that
    the whole estate happens to touch.
    """
    graph = alg.Graph()
    graph.add('a', 'hub')
    graph.add('hub', 'b')

    assert alg.connected_components(graph, {'a', 'b'}) == [['a'], ['b']]


# --------------------------------------------------------------------------
# The hand-authored estate. Its docstring promises three situations and the
# write-up quotes its numbers, so both are asserted here.
# --------------------------------------------------------------------------

@pytest.fixture(scope='module')
def demo_estate():
    return analysis.Estate(estate_module.build())


def test_the_demo_estate_is_built_from_documentation_addresses_only(demo_estate):
    """RFC 5737 reserves these ranges precisely so they route nowhere.

    Shipping a demo that names a routable address is how a sample dataset
    turns into a complaint from whoever owns it.
    """
    reserved = ('192.0.2.', '198.51.100.', '203.0.113.')
    addresses = [n['key'] for n in demo_estate.nodes
                 if n['kind'] == NodeKind.ADDRESS]
    assert addresses
    for address in addresses:
        assert address.startswith(reserved), address


def test_the_demo_estate_has_routes_that_converge(demo_estate):
    """Promise 1: closing one endpoint removes more routes than patching any
    single vulnerability.
    """
    result = analysis.exposure(demo_estate)
    assert result['reachable']
    assert result['path_count'] > 1
    busiest = result['choke_points'][0]
    assert busiest['paths_through'] > 1, 'no convergence means no choke point'


def test_the_demo_estate_reaches_a_crown_jewel_two_unrelated_ways(demo_estate):
    """Promise 2: one route through a web surface and one through a cloud
    credential, so the cheapest is not the obvious one.
    """
    result = analysis.exposure(demo_estate)
    kinds = {step['edge'] for path in result['paths'] for step in path['steps']}
    assert EdgeKind.SERVES in kinds, 'expected a route through a web surface'
    assert EdgeKind.YIELDS in kinds, 'expected a route through a credential'


def test_the_demo_estate_contains_a_new_route_no_rule_fired_on(demo_estate):
    """Promise 3: the contrast between a quiet route and a noisy scanner is
    the entire argument for structural detection over rules.
    """
    now = estate_module.GENERATED
    result = analysis.novel_activity(demo_estate, window_hours=24, now=now)
    unflagged = [r for r in result['new_reach'] if r['unflagged_by_rules']]
    assert unflagged, 'the demo must contain at least one silent new route'


def test_the_demo_estate_has_dormant_access_to_regulated_data(demo_estate):
    """The support desk can read the card database and never has."""
    result = analysis.over_privilege(demo_estate)
    assert result['granted'] > result['exercised']
    assert any(d['reaches_crown_jewel'] for d in result['dormant'])


def test_every_demo_edge_points_at_a_node_that_exists(demo_estate):
    """A dangling edge silently removes a node from every answer."""
    ids = {n['id'] for n in demo_estate.nodes}
    for edge in demo_estate.edges:
        assert edge['src'] in ids, edge
        assert edge['dst'] in ids, edge


def test_the_demo_estate_writes_and_reloads_unchanged(demo_estate, tmp_path):
    target = tmp_path / 'estate.json'
    written = estate_module.write(str(target))
    reloaded = analysis.Estate.from_file(str(target))
    assert len(reloaded.nodes) == len(written['nodes'])
    assert len(reloaded.edges) == len(written['edges'])


# --------------------------------------------------------------------------
# The analysis layer
# --------------------------------------------------------------------------

def test_critical_nodes_never_recommends_hardening_the_internet(demo_estate):
    """An external address scores well on centrality because it points at
    our surfaces. Ranking it tells a defender nothing they can act on.
    """
    loaded = demo_estate.load()
    for row in analysis.critical_nodes(demo_estate):
        assert loaded.meta[row['id']]['zone'] != Zone.UNTRUSTED


def test_a_path_reads_as_a_kill_chain_rather_than_a_list_of_names(demo_estate):
    """Every step carries its ATT&CK tactic, which is what makes the output
    something an analyst acts on instead of a graph dump.
    """
    cheapest = analysis.exposure(demo_estate)['cheapest']
    assert cheapest['steps']
    for step in cheapest['steps']:
        if step['edge'] == EdgeKind.TRIPPED:
            continue        # a detection annotation, not an attacker step
        assert step['tactic_id'].startswith('TA'), step
        assert step['tactic'], step


def test_segments_flag_the_part_of_the_business_new_activity_is_in(demo_estate):
    found = analysis.segments(demo_estate, window_hours=24,
                              now=estate_module.GENERATED)
    assert found
    assert any(segment['has_new_activity'] for segment in found)


def test_blast_radius_on_an_unknown_node_is_none_not_an_empty_answer(demo_estate):
    """An empty answer reads as 'nothing is at risk', which is the opposite
    of 'we have never heard of this node'.
    """
    assert analysis.blast_radius(demo_estate, 'no-such-node') is None


def test_an_estate_as_it_stood_before_a_cutoff_is_smaller(demo_estate):
    """Rebuilding history is a filter on first_seen, which is what makes
    'has this ever happened before' answerable without a second store.
    """
    cutoff = estate_module.GENERATED - timedelta(hours=24)
    now_graph = demo_estate.load().graph
    then_graph = demo_estate.load(only_before=cutoff).graph
    assert len(then_graph.edge_cost) < len(now_graph.edge_cost)


def test_exposure_says_why_when_it_has_nothing_to_report():
    """'No routes' and 'nothing is marked as a crown jewel' are different
    answers and the second one is a configuration problem.
    """
    payload = {'name': 'bare', 'nodes': [
        {'id': 'ip', 'kind': NodeKind.ADDRESS, 'key': '192.0.2.1',
         'zone': Zone.UNTRUSTED, 'crown': False},
        {'id': 'box', 'kind': NodeKind.ASSET, 'key': 'box',
         'zone': Zone.INTERNAL, 'crown': False}],
        'edges': [{'src': 'ip', 'dst': 'box', 'kind': EdgeKind.REQUESTED,
                   'cost': 2.0, 'first_seen': '2026-10-01T00:00:00+00:00'}]}
    result = analysis.exposure(analysis.Estate(payload))
    assert result['reachable'] is False
    assert 'crown jewel' in result['why']


def test_a_naive_timestamp_is_read_as_utc_rather_than_local_time():
    """A naive timestamp parsed as local time shifts every window by the
    offset of whichever machine happened to run it.
    """
    stamp = analysis._when('2026-11-03T09:00:00')
    assert stamp.tzinfo is not None
    assert stamp == datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Containment. What a cut buys, measured by making it.
# --------------------------------------------------------------------------

def test_a_blocked_node_is_not_walked_through():
    graph = alg.Graph()
    graph.add('in', 'hub')
    graph.add('hub', 'goal')

    assert alg.attack_paths(graph, ['in'], ['goal'], blocked={'hub'}) == []
    assert alg.cheapest_path(graph, ['in'], ['goal'], blocked={'hub'}) == (None, None)


def test_a_blocked_source_is_not_a_starting_point():
    graph = alg.Graph()
    graph.add('in', 'goal')
    assert alg.attack_paths(graph, ['in'], ['goal'], blocked={'in'}) == []


def test_blocking_one_edge_leaves_the_other_ways_into_the_same_node():
    """Revoking a grant is an edge cut, not a node cut. The system stays up."""
    graph = alg.Graph()
    graph.add('in', 'identity')
    graph.add('identity', 'goal', kind=EdgeKind.ENTITLED)
    graph.add('in', 'other')
    graph.add('other', 'goal', kind=EdgeKind.SERVES)

    paths = alg.attack_paths(graph, ['in'], ['goal'],
                             blocked_edges={('identity', 'goal')})
    assert [p['path'] for p in paths] == [['in', 'other', 'goal']]


def _assorted_graphs(count=120, seed=3):
    """Small random graphs, to check a property over shapes rather than one.

    Seeded, so a failure is reproducible rather than a story about a build
    that went red once. `random` is the right generator here and the S311
    warning is about cryptographic use, which this is not: the numbers pick
    graph shapes and nothing about them is secret.
    """
    rng = random.Random(seed)                        # noqa: S311 - see above
    for _ in range(count):
        graph = alg.Graph()
        for _ in range(40):
            a, b = rng.randrange(12), rng.randrange(12)
            if a != b:
                graph.add('n%d' % a, 'n%d' % b, cost=rng.choice([1.0, 2.0, 5.0]))
        yield graph


def _first_choke(graph, cap):
    """The busiest interior node, with the routes it was counted on."""
    before = alg.attack_paths(graph, ['n0'], ['n11'], max_depth=5, max_paths=cap)
    chokes = alg.choke_points(before, exclude={'n0', 'n11'})
    if len(before) < 2 or not chokes:
        return None
    after = alg.attack_paths(graph, ['n0'], ['n11'], max_depth=5,
                             max_paths=cap, blocked={chokes[0]['node']})
    return len(before) - len(after), chokes[0]['paths_through']


def test_a_cut_node_removes_exactly_the_routes_counted_through_it():
    """The property that makes the route count redundant, when uncapped.

    Deleting a node from an enumeration of simple paths can only delete
    paths; it cannot create one. So routes removed must equal routes counted
    through, every time, and the first version of the containment docstring
    claiming otherwise was wrong. Checked here over many shapes rather than
    asserted once, because this is the claim the docstring now rests on.
    """
    checked = 0
    for graph in _assorted_graphs():
        measured = _first_choke(graph, cap=alg.MAX_PATHS)
        if measured is None:
            continue
        removed, counted = measured
        assert removed == counted
        checked += 1
    assert checked > 50, 'the property was barely exercised'


def test_the_route_count_stops_being_reliable_once_the_cap_binds():
    """And this is why containment simulates instead of counting.

    With the enumeration capped, the paths through a node are only the ones
    the search happened to reach before it stopped. Cut the node and the
    freed budget admits routes the first pass never listed, so the count and
    the measurement disagree. On an estate large enough to hit max_paths,
    which is the normal case, the simulation is the correct number and the
    count is not.
    """
    disagreements = 0
    for graph in _assorted_graphs():
        measured = _first_choke(graph, cap=6)
        if measured is None:
            continue
        removed, counted = measured
        if removed != counted:
            disagreements += 1
    assert disagreements > 0, (
        'if this ever stops disagreeing, counting would be as good as '
        'simulating and the containment feature would not need to exist')


def test_containment_names_the_crown_jewel_a_cut_actually_protects(demo_estate):
    """A count cannot see the far end of a path. This can."""
    result = analysis.containment(demo_estate)
    protective = [o for o in result['options'] if o['crown_jewels_cut_off']]
    assert protective, 'expected at least one cut to put a target out of reach'
    for option in protective:
        for jewel in option['crown_jewels_cut_off']:
            assert jewel['is_crown_jewel']


def test_a_cut_can_remove_most_routes_and_leave_the_attacker_no_worse_off(demo_estate):
    """The result worth seeing before the change meeting rather than after.

    On the demo estate the busiest choke point carries most of the routes,
    and cutting it moves the cheapest route's effort by nothing at all,
    because an unrelated route is equally cheap. Counting paths through a
    node would have called this the top remediation.
    """
    result = analysis.containment(demo_estate)
    busiest = max(result['options'], key=lambda o: o['routes_removed'])
    assert busiest['routes_removed'] >= result['routes_before'] // 3
    assert busiest['effort_added'] == 0.0
    assert busiest['cheapest_after'] == result['cheapest_before']


def test_revoking_a_dormant_grant_is_offered_beside_taking_a_system_down(demo_estate):
    """The two kinds of cut on one list, which is the comparison a team needs.

    Entitlements are not choke points and never appear in that ranking, so
    counting alone cannot put them side by side with a decommissioning.
    """
    result = analysis.containment(demo_estate)
    kinds = {o['kind'] for o in result['options']}
    assert kinds == {'node', 'entitlement'}
    for option in result['options']:
        if option['kind'] == 'entitlement':
            assert option['cut']['action'].startswith('revoke ')
            assert option['routes_removed'] > 0, (
                'a revocation that removes nothing should not be offered')


def test_a_cut_that_closes_everything_is_ranked_first():
    payload = {'name': 'single way in', 'nodes': [
        {'id': 'ip', 'kind': NodeKind.ADDRESS, 'key': '192.0.2.1',
         'zone': Zone.UNTRUSTED, 'crown': False},
        {'id': 'gate', 'kind': NodeKind.ENDPOINT, 'key': '/gate',
         'zone': Zone.PERIMETER, 'crown': False},
        {'id': 'spare', 'kind': NodeKind.ENDPOINT, 'key': '/spare',
         'zone': Zone.PERIMETER, 'crown': False},
        {'id': 'vault', 'kind': NodeKind.ASSET, 'key': 'vault',
         'zone': Zone.CROWN, 'crown': True}],
        'edges': [
            {'src': 'ip', 'dst': 'gate', 'kind': EdgeKind.REQUESTED,
             'cost': 2.0, 'first_seen': '2026-10-01T00:00:00+00:00'},
            {'src': 'ip', 'dst': 'spare', 'kind': EdgeKind.REQUESTED,
             'cost': 2.0, 'first_seen': '2026-10-01T00:00:00+00:00'},
            {'src': 'gate', 'dst': 'vault', 'kind': EdgeKind.SERVES,
             'cost': 3.0, 'first_seen': '2026-10-01T00:00:00+00:00'}]}
    result = analysis.containment(analysis.Estate(payload))
    assert result['options'][0]['cut']['key'] == '/gate'
    assert result['options'][0]['fully_contained'] is True
    assert result['options'][0]['cheapest_after'] is None


def test_containment_says_why_when_there_is_nothing_to_contain():
    payload = {'name': 'bare', 'nodes': [
        {'id': 'ip', 'kind': NodeKind.ADDRESS, 'key': '192.0.2.1',
         'zone': Zone.UNTRUSTED, 'crown': False},
        {'id': 'box', 'kind': NodeKind.ASSET, 'key': 'box',
         'zone': Zone.INTERNAL, 'crown': False}],
        'edges': [{'src': 'ip', 'dst': 'box', 'kind': EdgeKind.REQUESTED,
                   'cost': 2.0, 'first_seen': '2026-10-01T00:00:00+00:00'}]}
    result = analysis.containment(analysis.Estate(payload))
    assert result['reachable'] is False
    assert result['options'] == []
    assert 'crown jewel' in result['why']


def test_containment_simulates_a_bounded_number_of_cuts(demo_estate):
    """Each cut re-runs the whole search, so the ceiling is a cost ceiling."""
    result = analysis.containment(demo_estate, candidates=2)
    assert len([o for o in result['options'] if o['kind'] == 'node']) <= 2
