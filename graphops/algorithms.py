"""Graph algorithms over one organisation's estate graph.

ALL OF THESE ARE HAND-WRITTEN AND SMALL, and that is a decision rather than
an omission. The four questions this engine has to answer need bounded BFS,
Dijkstra, a path-convergence count and connected components. Those are about
two hundred lines together. The only capability that would genuinely pay for
a library is Louvain community detection, which is the least load-bearing of
the four, so the dependency is not worth taking yet.

EVERY SEARCH IS BOUNDED. Depth, node count and path count all have caps that
the caller cannot raise past a hard ceiling. An unbounded traversal over a
graph built from attacker-controlled telemetry is a denial of service with
extra steps: an attacker who can create nodes can choose how much CPU a
single analyst click costs the server.
"""
import heapq
from collections import defaultdict, deque

# Hard ceilings. A caller may ask for less and never for more.
MAX_DEPTH = 6
MAX_NODES = 20000
MAX_PATHS = 2000


class Graph:
    """An adjacency map for one estate, loaded once and reused.

    Built from plain tuples rather than model instances so the algorithms
    never hold a database cursor open and can be unit-tested without one.
    """

    __slots__ = ('out', 'inc', 'nodes', 'edge_cost', 'edge_kind')

    def __init__(self):
        self.out = defaultdict(list)    # node -> [dst]
        self.inc = defaultdict(list)    # node -> [src]
        self.nodes = set()
        self.edge_cost = {}             # (src, dst) -> float
        self.edge_kind = {}             # (src, dst) -> str

    def add(self, src, dst, kind='', cost=1.0):
        if (src, dst) not in self.edge_cost:
            self.out[src].append(dst)
            self.inc[dst].append(src)
        # A repeated pair keeps the CHEAPEST way of making that step. Two
        # observations of the same relationship are not two obstacles.
        prev = self.edge_cost.get((src, dst))
        if prev is None or cost < prev:
            self.edge_cost[(src, dst)] = cost
            self.edge_kind[(src, dst)] = kind
        self.nodes.add(src)
        self.nodes.add(dst)

    def neighbours(self, node, undirected=False):
        if undirected:
            return self.out.get(node, []) + self.inc.get(node, [])
        return self.out.get(node, [])


def blast_radius(graph, origin, max_hops=3, limit=MAX_NODES):
    """Who is reachable from a compromised node, by hop.

    Returns {1: [...], 2: [...], 3: [...]}, each node appearing at the
    SHALLOWEST hop that reaches it and never again. An analyst asking "what
    is one step away" is asking which systems are at direct risk; listing a
    node at hop 3 as well, because some longer walk also arrives there,
    makes the one-hop list look larger than the danger it describes.

    UNDIRECTED ON PURPOSE. Compromise does not respect the direction we
    happened to record. If an identity acted from an address, holding that
    address tells you about the identity just as much as the reverse.
    """
    max_hops = max(1, min(int(max_hops), MAX_DEPTH))
    seen = {origin}
    rings = {}
    frontier = [origin]

    for hop in range(1, max_hops + 1):
        nxt = []
        for node in frontier:
            for peer in graph.neighbours(node, undirected=True):
                if peer in seen:
                    continue
                seen.add(peer)
                nxt.append(peer)
                if len(seen) >= limit:
                    break
            if len(seen) >= limit:
                break
        if not nxt:
            break
        rings[hop] = nxt
        frontier = nxt
        if len(seen) >= limit:
            break
    return rings


def cheapest_path(graph, sources, targets, max_depth=MAX_DEPTH):
    """The least effort an attacker needs to get from any source to any target.

    Dijkstra over edge cost, not hop count. A three-hop route that only
    reuses credentials is a likelier intrusion than a two-hop route that
    needs an exploit to land, and ranking by hops inverts those two.

    Returns (path, total_cost) or (None, None).
    """
    targets = set(targets)
    if not targets:
        return None, None

    dist = {}
    prev = {}
    heap = []
    for s in sources:
        if s in graph.nodes:
            dist[s] = 0.0
            heapq.heappush(heap, (0.0, 0, s))

    while heap:
        cost, depth, node = heapq.heappop(heap)
        if cost > dist.get(node, float('inf')):
            continue
        if node in targets:
            path = [node]
            while path[-1] in prev:
                path.append(prev[path[-1]])
            return list(reversed(path)), cost
        if depth >= max_depth:
            continue
        for peer in graph.out.get(node, []):
            step = cost + graph.edge_cost.get((node, peer), 1.0)
            if step < dist.get(peer, float('inf')):
                dist[peer] = step
                prev[peer] = node
                heapq.heappush(heap, (step, depth + 1, peer))
    return None, None


def attack_paths(graph, sources, targets, max_depth=4, max_paths=200):
    """Every route from untrusted ground to something that matters.

    Depth-first with an explicit stack and a path-local visited set, so a
    cycle cannot loop and two different routes through the same node both
    survive. Bounded twice over: by depth and by how many paths we will
    enumerate at all.
    """
    max_depth = max(1, min(int(max_depth), MAX_DEPTH))
    max_paths = max(1, min(int(max_paths), MAX_PATHS))
    targets = set(targets)
    found = []

    for src in sources:
        if src not in graph.nodes or len(found) >= max_paths:
            continue
        stack = [(src, [src], {src}, 0.0)]
        while stack and len(found) < max_paths:
            node, path, onpath, cost = stack.pop()
            if node in targets and len(path) > 1:
                found.append({'path': path, 'cost': round(cost, 3)})
                continue
            if len(path) > max_depth:
                continue
            for peer in graph.out.get(node, []):
                if peer in onpath:          # a cycle, not a route
                    continue
                stack.append((peer, path + [peer], onpath | {peer},
                              cost + graph.edge_cost.get((node, peer), 1.0)))
    found.sort(key=lambda p: (p['cost'], len(p['path'])))
    return found


def choke_points(paths, exclude=()):
    """The few nodes that, if cut, break the most routes.

    THIS IS XM CYBER'S IDEA AND IT IS THE BEST ONE IN THE FIELD: do not
    score every exposure, score the intersections where validated paths
    converge.
    They report roughly 2% of exposures sit on choke points, which is the
    difference between a remediation list a team can finish this week and
    one it will never finish.

    Counted over ENUMERATED PATHS rather than as global betweenness
    centrality, deliberately. Betweenness scores a node against all
    shortest paths in the graph, including the overwhelming majority that
    start and end somewhere nobody cares about. The number an analyst can
    act on is "this node is on 41 of the 60 ways in", and that is a count,
    not a centrality.

    The endpoints are excluded: an attack path necessarily runs through its
    own source and target, so scoring them tells you only what you asked.
    """
    exclude = set(exclude)
    total = len(paths)
    if not total:
        return []

    on_paths = defaultdict(int)
    for p in paths:
        interior = p['path'][1:-1]
        for node in set(interior):
            if node not in exclude:
                on_paths[node] += 1

    out = [{'node': n, 'paths_through': c, 'share': round(c / total, 4)}
           for n, c in on_paths.items()]
    out.sort(key=lambda r: (-r['paths_through'], r['node']))
    return out


def connected_components(graph, among):
    """Clusters inside a set of nodes, ignoring everything else.

    Used on the anomalous edges rather than on the whole graph. Clustering
    anomalies and treating a connected cluster as one incident is the
    standard move in the lateral-movement literature, and it is also the
    answer to the complaint SOC teams actually have: six separate alerts
    that are one intrusion should arrive as one thing.
    """
    among = set(among)
    seen = set()
    groups = []
    for start in sorted(among):
        if start in seen:
            continue
        group = []
        queue = deque([start])
        seen.add(start)
        while queue:
            node = queue.popleft()
            group.append(node)
            for peer in graph.neighbours(node, undirected=True):
                if peer in among and peer not in seen:
                    seen.add(peer)
                    queue.append(peer)
        groups.append(sorted(group))
    groups.sort(key=lambda g: (-len(g), g[0]))
    return groups


def pagerank(graph, damping=0.85, iterations=40, tolerance=1.0e-8):
    """Which nodes would cost the most if they were taken.

    The brief asks for centrality to identify the nodes that cause the most
    disruption when compromised, and PageRank answers that better than raw
    degree because it is recursive. A node matters if important nodes point
    at it, so a quiet server that three critical systems depend on outranks
    a busy endpoint that nothing depends on.

    READ IT ON THE REVERSED GRAPH. PageRank flows importance ALONG edges,
    and our edges point the way an attacker travels. Run forwards, the rank
    piles up on the crown jewels, which tells us what we already knew. Run
    on the reverse, it accumulates on the nodes that LEAD to valuable
    places, which is the question actually being asked.

    Dangling nodes, meaning anything with no outgoing edge, would otherwise
    leak rank out of the system and leave the scores not summing to one.
    Their mass is redistributed every iteration instead.
    """
    nodes = sorted(graph.nodes)
    if not nodes:
        return []
    n = len(nodes)

    # Reverse adjacency, for the reason in the docstring.
    out_to = defaultdict(list)
    for (src, dst) in graph.edge_cost:
        out_to[dst].append(src)
    out_degree = {node: len(out_to.get(node, ())) for node in nodes}

    rank = {node: 1.0 / n for node in nodes}
    for _ in range(iterations):
        dangling = sum(rank[node] for node in nodes if not out_degree[node])
        fresh = {node: (1.0 - damping) / n + damping * dangling / n
                 for node in nodes}
        for node in nodes:
            degree = out_degree[node]
            if not degree:
                continue
            share = damping * rank[node] / degree
            for peer in out_to[node]:
                fresh[peer] += share
        delta = sum(abs(fresh[node] - rank[node]) for node in nodes)
        rank = fresh
        if delta < tolerance:
            break

    out = [{'node': node, 'score': round(rank[node], 6)} for node in nodes]
    out.sort(key=lambda r: (-r['score'], r['node']))
    return out


def louvain_communities(graph, among=None, passes=12):
    """Cluster the graph by modularity, to group one intrusion into one thing.

    This is the LOCAL MOVING PHASE of Louvain and it is named that way on
    purpose. Full Louvain then collapses each community into a single node
    and repeats the whole procedure on the smaller graph, which usually
    changes the result on a large network. At the size one business's
    estate reaches, the first phase already separates the clusters an
    analyst cares about, and claiming the full algorithm when only half of
    it runs would be a lie that is easy to check.

    Modularity compares the edge weight actually inside a community against
    the weight that would fall there by chance given the same degrees. The
    graph is treated as undirected here, because an intrusion spreading
    between two systems is one relationship whichever way the log recorded
    it.
    """
    among = set(among) if among is not None else set(graph.nodes)
    nodes = sorted(among)
    if not nodes:
        return []

    weight = defaultdict(float)
    for (src, dst), cost in graph.edge_cost.items():
        if src in among and dst in among and src != dst:
            # A cheap edge is a STRONG relationship, so invert the cost.
            # Cost is attacker effort, and modularity wants affinity.
            w = 1.0 / max(cost, 0.1)
            weight[(src, dst)] += w
            weight[(dst, src)] += w

    neighbours = defaultdict(list)
    for (src, dst), w in weight.items():
        neighbours[src].append((dst, w))

    degree = defaultdict(float)
    for (src, _dst), w in weight.items():
        degree[src] += w
    total = sum(degree.values())
    if total <= 0:
        return [[node] for node in nodes]

    community = {node: node for node in nodes}
    comm_degree = dict(degree)

    for _ in range(passes):
        moved = False
        for node in nodes:
            own = community[node]
            comm_degree[own] -= degree[node]

            # Weight from this node into each candidate community.
            into = defaultdict(float)
            for peer, w in neighbours.get(node, ()):
                into[community[peer]] += w

            best, best_gain = own, into.get(own, 0.0) - \
                comm_degree.get(own, 0.0) * degree[node] / total
            for cand, w in into.items():
                gain = w - comm_degree.get(cand, 0.0) * degree[node] / total
                if gain > best_gain + 1.0e-12:
                    best, best_gain = cand, gain

            community[node] = best
            comm_degree[best] = comm_degree.get(best, 0.0) + degree[node]
            if best != own:
                moved = True
        if not moved:
            break

    grouped = defaultdict(list)
    for node, comm in community.items():
        grouped[comm].append(node)
    out = [sorted(members) for members in grouped.values()]
    out.sort(key=lambda g: (-len(g), g[0]))
    return out
