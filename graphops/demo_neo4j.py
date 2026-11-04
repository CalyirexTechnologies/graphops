"""Load the estate into Neo4j, answer in Cypher, and check both agree.

    .venv/bin/python -m graphops.demo_neo4j

The point is not that Neo4j can do this. It is that the SAME questions,
asked of the same graph through two completely different engines, come back
with the same answers. If they disagree, one of them is wrong, and a
submission that only ever ran one of them would not know which.
"""
import os
import sys

from . import neo4j_store as store
from .analysis import Estate, blast_radius, containment, exposure

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ESTATE = os.path.join(HERE, 'data', 'estate.json')

URI = os.environ.get('NEO4J_URI', 'bolt://127.0.0.1:7687')
USER = os.environ.get('NEO4J_USER', 'neo4j')
# A local throwaway database that exists only for this demo. Anything real
# would read this from the environment and never carry a default.
PASSWORD = os.environ.get('NEO4J_PASSWORD', 'graphops-local-dev')

ORIGIN = 'asset-orders'
RULE = '=' * 72


def main():
    estate = Estate.from_file(ESTATE)

    try:
        driver = store.connect(URI, USER, PASSWORD)
        driver.verify_connectivity()
    except Exception as exc:
        print('Could not reach Neo4j at %s' % URI)
        print('  %s' % exc)
        print('\nStart one with `neo4j start`, or run `python3 -m graphops.demo`'
              ' which needs nothing.')
        return 2

    print(RULE)
    print('LOADING %d nodes and %d edges into Neo4j'
          % (len(estate.nodes), len(estate.edges)))
    print(RULE)
    written = store.push(driver, estate)
    print('Neo4j now holds %d nodes and %d relationships'
          % (written['nodes'], written['edges']))

    ok = True

    # ---------------------------------------------------------------- paths
    print('\n' + RULE)
    print('ATTACK PATHS, answered by Cypher')
    print(RULE)
    cypher_paths = store.attack_paths(driver)
    engine = exposure(estate)

    print('Cypher found %d routes, the engine found %d.'
          % (len(cypher_paths), engine['path_count']))
    if len(cypher_paths) != engine['path_count']:
        ok = False
        print('  MISMATCH on the route count.')

    best = cypher_paths[0] if cypher_paths else None
    if best:
        print('\nCheapest route by Cypher, cost %.1f' % best['cost'])
        print('  %s' % ' -> '.join(best['route']))
        engine_cost = engine['cheapest']['cost']
        engine_route = ([engine['cheapest']['steps'][0]['from']['key']]
                        + [s['to']['key'] for s in engine['cheapest']['steps']])
        print('Cheapest route by the engine, cost %.1f' % engine_cost)
        print('  %s' % ' -> '.join(engine_route))
        if abs(best['cost'] - engine_cost) > 1e-6 or best['route'] != engine_route:
            ok = False
            print('  MISMATCH on the cheapest route.')
        else:
            print('  Both agree.')

    # --------------------------------------------------------- choke points
    print('\n' + RULE)
    print('CHOKE POINTS, answered by Cypher')
    print(RULE)
    cypher_chokes = store.choke_points(driver)
    engine_chokes = {c['key']: c['paths_through'] for c in engine['choke_points']}
    for row in cypher_chokes[:5]:
        mine = engine_chokes.get(row['node'])
        agree = 'agrees' if mine == row['through'] else 'DIFFERS, engine says %s' % mine
        print('  %-30s on %2d routes   %s' % (row['node'][:30], row['through'], agree))
        if mine != row['through']:
            ok = False

    # ----------------------------------------------------------- containment
    # The cross-check that matters most, because this is the answer a team
    # acts on. Agreeing on a route count is reassuring; agreeing on which cut
    # protects which crown jewel is the claim worth defending.
    print('\n' + RULE)
    print('CONTAINMENT, answered by Cypher')
    print(RULE)
    cypher_cuts = store.containment(driver)
    engine_cuts = {o['cut']['key']: o
                   for o in containment(estate)['options'] if o['kind'] == 'node'}
    for row in cypher_cuts[:5]:
        mine = engine_cuts.get(row['candidate'])
        jewels = row['crown_jewels_cut_off']
        print('  cut %-22s removes %2d of %d routes, cheapest %.1f -> %s%s'
              % (row['candidate'][:22], row['routes_removed'],
                 row['routes_before'], row['cheapest_before'],
                 ('%.1f' % row['cheapest_after']
                  if row['cheapest_after'] is not None else 'no route left'),
                 (', protects %s' % ', '.join(jewels)) if jewels else ''))
        if mine is None:
            continue
        mine_jewels = sorted(j['key'] for j in mine['crown_jewels_cut_off'])
        if (mine['routes_removed'] != row['routes_removed']
                or mine_jewels != sorted(jewels)):
            ok = False
            print('      DIFFERS, engine removes %d and protects %s'
                  % (mine['routes_removed'], mine_jewels or 'nothing'))
        else:
            print('      agrees')

    # --------------------------------------------------------- blast radius
    print('\n' + RULE)
    print('BLAST RADIUS from %s, answered by Cypher' % ORIGIN)
    print(RULE)
    cypher_blast = store.blast_radius(driver, ORIGIN)
    engine_blast = blast_radius(estate, ORIGIN)
    for row in cypher_blast:
        mine = len(engine_blast['hops'].get(row['hop'], []))
        agree = 'agrees' if mine == row['count'] else 'DIFFERS, engine says %d' % mine
        print('  %d hop%s away: %2d   %s'
              % (row['hop'], '' if row['hop'] == 1 else 's', row['count'], agree))
        if mine != row['count']:
            ok = False

    driver.close()
    print('\n' + RULE)
    print('Both engines agree on every answer.' if ok
          else 'THE TWO ENGINES DISAGREE. See the lines marked above.')
    print(RULE)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
