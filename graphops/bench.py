"""How the engine behaves on an estate the size of a real one.

    python3 -m graphops.bench                 # the default sweep
    python3 -m graphops.bench --scale 1000    # one size
    python3 -m graphops.bench --shape mesh    # the expensive shape

NEEDS NOTHING INSTALLED, like the rest of the engine. The generator is
committed rather than the generated data, because a 26 MB JSON file in the
repository would be worse than the fifty lines that produce it, and because a
benchmark nobody can re-run is a screenshot.

TWO SHAPES, AND THE SECOND ONE IS THE POINT. `layered` is what an estate
looks like: untrusted addresses reaching a thin perimeter, the perimeter
serving assets, identities holding entitlements. Node count is large and the
depth-4 neighbourhood of any one node is small. `mesh` is the shape that
costs: a dense perimeter where surfaces serve assets that are themselves
served by other surfaces, so the number of distinct routes grows with
branching rather than with nodes.

Running only `layered` would publish a flattering number. The honest summary
of both is that cost tracks perimeter density and search depth, not estate
size, and the sweep below shows it.

WHERE A NUMBER IS CAP-BOUND IT SAYS SO. `exposure` stops at max_paths and
`novel_activity` stops at 200 actors, so on a large estate those timings are
how long it takes to fill the cap, not how long a complete answer takes.
Printing them without the marker would be the most flattering lie available.
"""
import argparse
import random
import sys
import time

from . import analysis
from .vocab import DEFAULT_COST, EdgeKind, NodeKind, Zone

# Fixed, so two runs of the same size are the same estate.
SEED = 7
STAMP = '2026-10-01T09:00:00+00:00'
RECENT = '2026-11-04T09:00:00+00:00'

SHAPES = ('layered', 'mesh')
DEFAULT_SWEEP = (10, 100, 500, 1000)


def _peak_memory_mb():
    """Peak resident size, or None where the platform will not say.

    ru_maxrss is bytes on macOS and kilobytes on Linux, which is a trap
    worth naming rather than a detail: reporting one as the other is off by
    a factor of a thousand in the direction that flatters.
    """
    try:
        import resource
    except ImportError:                                  # pragma: no cover
        return None
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == 'darwin' else raw / 1024


def layered(scale, seed=SEED):
    """An estate shaped like a business: a thin perimeter, a wide interior."""
    rng = random.Random(seed)                            # noqa: S311
    nodes, edges = [], []

    counts = {'ip': 20 * scale, 'ep': 4 * scale, 'asset': 30 * scale,
              'id': 15 * scale, 'svc': 3 * scale, 'cve': 20 * scale,
              'rule': 2 * scale}
    kinds = {'ip': (NodeKind.ADDRESS, Zone.UNTRUSTED),
             'ep': (NodeKind.ENDPOINT, Zone.PERIMETER),
             'asset': (NodeKind.ASSET, Zone.INTERNAL),
             'id': (NodeKind.IDENTITY, Zone.INTERNAL),
             'svc': (NodeKind.SERVICE, Zone.INTERNAL),
             'cve': (NodeKind.VULNERABILITY, Zone.INTERNAL),
             'rule': (NodeKind.RULE, Zone.INTERNAL)}

    for prefix, total in counts.items():
        kind, zone = kinds[prefix]
        for i in range(total):
            # Roughly one asset in two hundred holds something worth taking,
            # which is the ratio that makes crown jewels mean anything.
            crown = (prefix == 'asset' and i % 200 == 0) or \
                    (prefix == 'svc' and i % 100 == 0)
            nid = '%s-%d' % (prefix, i)
            nodes.append({'id': nid, 'kind': kind, 'key': nid, 'label': nid,
                          'zone': Zone.CROWN if crown else zone, 'crown': crown})

    def edge(src, dst, kind, when=STAMP):
        edges.append({'src': src, 'dst': dst, 'kind': kind,
                      'cost': DEFAULT_COST[kind], 'first_seen': when})

    for i in range(counts['ip']):
        for _ in range(rng.randint(1, 3)):
            edge('ip-%d' % i, 'ep-%d' % rng.randrange(counts['ep']),
                 EdgeKind.REQUESTED)
        if i % 10 == 0:
            edge('ip-%d' % i, 'id-%d' % rng.randrange(counts['id']),
                 EdgeKind.YIELDS, RECENT if i % 100 == 0 else STAMP)
        if i % 25 == 0:
            edge('ip-%d' % i, 'rule-%d' % rng.randrange(counts['rule']),
                 EdgeKind.TRIPPED)

    for i in range(counts['ep']):
        for _ in range(rng.randint(1, 4)):
            edge('ep-%d' % i, 'asset-%d' % rng.randrange(counts['asset']),
                 EdgeKind.SERVES)

    for i in range(counts['asset']):
        if i % 3 == 0:
            edge('asset-%d' % i, 'cve-%d' % rng.randrange(counts['cve']),
                 EdgeKind.EXPOSES)

    for i in range(counts['id']):
        for _ in range(rng.randint(1, 3)):
            edge('id-%d' % i, 'svc-%d' % rng.randrange(counts['svc']),
                 EdgeKind.CALLED)
        for _ in range(rng.randint(1, 4)):
            if rng.random() < 0.5:
                edge('id-%d' % i, 'svc-%d' % rng.randrange(counts['svc']),
                     EdgeKind.ENTITLED)
            else:
                edge('id-%d' % i, 'asset-%d' % rng.randrange(counts['asset']),
                     EdgeKind.ENTITLED)

    return {'name': 'layered-%d' % scale, 'nodes': nodes, 'edges': edges}


def mesh(scale, seed=SEED):
    """The expensive shape: a dense perimeter that routes back into itself.

    Fewer nodes than `layered` at the same scale and far more routes, which
    is the whole point. Enumeration cost follows branching and depth, so a
    small tangled estate outruns a large tidy one.
    """
    rng = random.Random(seed)                            # noqa: S311
    nodes, edges = [], []
    n_addr, n_ep, fanout = 2 * scale, 2 * scale, 6

    for i in range(n_addr):
        nodes.append({'id': 'ip-%d' % i, 'kind': NodeKind.ADDRESS,
                      'key': 'ip-%d' % i, 'label': 'ip-%d' % i,
                      'zone': Zone.UNTRUSTED, 'crown': False})
    for i in range(n_ep):
        nodes.append({'id': 'ep-%d' % i, 'kind': NodeKind.ENDPOINT,
                      'key': 'ep-%d' % i, 'label': 'ep-%d' % i,
                      'zone': Zone.PERIMETER, 'crown': False})
        nodes.append({'id': 'asset-%d' % i, 'kind': NodeKind.ASSET,
                      'key': 'asset-%d' % i, 'label': 'asset-%d' % i,
                      'zone': Zone.INTERNAL, 'crown': False})
    nodes.append({'id': 'crown', 'kind': NodeKind.ASSET, 'key': 'crown-store',
                  'label': 'crown-store', 'zone': Zone.CROWN, 'crown': True})

    def edge(src, dst, kind):
        edges.append({'src': src, 'dst': dst, 'kind': kind,
                      'cost': DEFAULT_COST[kind], 'first_seen': STAMP})

    for i in range(n_addr):
        for _ in range(fanout):
            edge('ip-%d' % i, 'ep-%d' % rng.randrange(n_ep), EdgeKind.REQUESTED)
    for i in range(n_ep):
        for _ in range(fanout):
            edge('ep-%d' % i, 'asset-%d' % rng.randrange(n_ep), EdgeKind.SERVES)
        for _ in range(fanout):
            edge('asset-%d' % i, 'ep-%d' % rng.randrange(n_ep), EdgeKind.SERVES)
    edge('asset-0', 'crown', EdgeKind.SERVES)

    return {'name': 'mesh-%d' % scale, 'nodes': nodes, 'edges': edges}


BUILDERS = {'layered': layered, 'mesh': mesh}


def _time(fn):
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def run_one(shape, scale, verbose=True):
    """Time every question against one generated estate."""
    payload = BUILDERS[shape](scale)
    loaded = analysis.Estate(payload).load()

    rows = []

    def measure(label, fn, capped=None):
        # A fresh Estate per question. An estate memoises its loaded graph
        # and its route enumeration, which is right for a console screen
        # that asks four questions and wrong for a benchmark: the second
        # question would ride on the first one's work and look cheaper than
        # it is. Every number below is a cold answer.
        estate = analysis.Estate(payload)
        seconds, result = _time(lambda: fn(estate))
        rows.append({'query': label, 'seconds': seconds,
                     'result': result, 'capped': bool(capped and capped(result))})
        return result

    origin = payload['nodes'][0]['id']

    measure('load', lambda e: '%d nodes' % len(e.load().graph.nodes))
    exposure = measure(
        'exposure', analysis.exposure,
        capped=lambda r: r.get('path_count', 0) >= 400)
    measure('containment', analysis.containment)
    measure('blast_radius', lambda e: analysis.blast_radius(e, origin))
    measure('critical_nodes', analysis.critical_nodes)
    measure('segments', analysis.segments)
    measure('over_privilege', analysis.over_privilege)
    measure('novel_activity', analysis.novel_activity,
            capped=lambda r: r.get('new_reach_count', 0) >= 200)

    summary = {
        'shape': shape, 'scale': scale,
        'nodes_declared': len(payload['nodes']),
        'edges_declared': len(payload['edges']),
        'nodes_in_graph': len(loaded.graph.nodes),
        'edges_in_graph': len(loaded.graph.edge_cost),
        'routes_found': exposure.get('path_count', 0),
        'rows': rows,
    }

    if verbose:
        print('\n%s, scale %d: %d nodes and %d edges declared, '
              '%d nodes and %d edges in the graph'
              % (shape, scale, summary['nodes_declared'],
                 summary['edges_declared'], summary['nodes_in_graph'],
                 summary['edges_in_graph']))
        # Nodes with no edge never enter the adjacency map, which is why the
        # two node counts differ and why both are printed.
        for row in rows:
            print('    %-16s %8.3fs%s'
                  % (row['query'], row['seconds'],
                     '   (cap reached, so this is time to fill the cap '
                     'rather than to finish)' if row['capped'] else ''))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python3 -m graphops.bench',
        description='Time every question against a generated estate.')
    parser.add_argument('--scale', type=int, action='append', default=None,
                        help='estate size multiplier; repeatable')
    parser.add_argument('--shape', choices=SHAPES + ('both',), default='both')
    args = parser.parse_args(argv)

    scales = args.scale or list(DEFAULT_SWEEP)
    shapes = SHAPES if args.shape == 'both' else (args.shape,)

    print('GraphOps benchmark. Python %s on %s.'
          % (sys.version.split()[0], sys.platform))
    print('Timings are from one machine and are only meaningful next to each '
          'other.')

    results = []
    for shape in shapes:
        for scale in scales:
            # The mesh grows routes combinatorially, so the same scale number
            # means a much heavier graph. Stopping early is honest about the
            # shape rather than a missing row.
            if shape == 'mesh' and scale > 500:
                print('\nmesh, scale %d: skipped. Past 500 the route count '
                      'grows faster than the estate and the number stops '
                      'describing anything.' % scale)
                continue
            results.append(run_one(shape, scale))

    peak = _peak_memory_mb()
    print('\nPeak resident memory across the whole sweep: %s'
          % ('%.0f MB' % peak if peak is not None else 'not reported here'))
    print('Every estate above is generated from a fixed seed, so re-running '
          'this gives the same graphs.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
