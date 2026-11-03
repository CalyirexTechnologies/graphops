"""Run the four questions against the synthetic estate and print the answers.

    python3 -m graphops.demo

Nothing is installed and nothing is mocked. The numbers printed here are the
engine's real output over data/estate.json.
"""
import json
import os
import sys

from .analysis import (
    Estate,
    blast_radius,
    critical_nodes,
    exposure,
    novel_activity,
    over_privilege,
    segments,
)
from .estate import GENERATED

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ESTATE = os.path.join(HERE, 'data', 'estate.json')

RULE = '=' * 72


def heading(text):
    print('\n' + RULE)
    print(text)
    print(RULE)


def short(text, width):
    """Truncate without leaving a word sliced mid-token in a joined list."""
    text = str(text)
    return text if len(text) <= width else text[:width - 3] + '...'


def show_steps(steps, indent='    '):
    for step in steps:
        tactic = step['tactic'] or 'no tactic claimed'
        print('%s%-30s -> %-30s  %s' % (
            indent, short(step['from']['key'], 30), short(step['to']['key'], 30),
            '%s [%s]' % (tactic, step['technique'] or 'n/a')))


def main():
    estate = Estate.from_file(ESTATE)
    print('Estate: %s' % estate.name)
    print('%d nodes, %d edges' % (len(estate.nodes), len(estate.edges)))

    # ------------------------------------------------------------ question 1
    heading('1. EXPOSURE  Which routes run from the internet to something '
            'that matters')
    exp = exposure(estate)
    if not exp['reachable']:
        print(exp.get('why'))
    else:
        print('%d routes reach a crown jewel.' % exp['path_count'])
        print('\nThe cheapest one, by attacker effort rather than hop count '
              '(cost %.1f):' % exp['cheapest']['cost'])
        show_steps(exp['cheapest']['steps'])

        print('\nChoke points. Cutting one of these removes every route '
              'through it:')
        for c in exp['choke_points'][:5]:
            print('    %-34s on %2d of %d routes  (%.0f%%)' % (
                short(c['key'], 34), c['paths_through'], exp['path_count'],
                c['share'] * 100))

    # ------------------------------------------------------------ question 2
    heading('2. BLAST RADIUS  If this one system is taken, what else is '
            'in reach')
    blast = blast_radius(estate, 'asset-orders', max_hops=3)
    print('Origin: %s' % blast['origin']['key'])
    for hop, members in sorted(blast['hops'].items()):
        shown = ', '.join(short(m['key'], 24) for m in members[:3])
        if len(members) > 3:
            shown += ', and %d more' % (len(members) - 3)
        print('    %d hop%s away: %-2d  %s' % (
            hop, '' if hop == 1 else 's', len(members), shown))
    print('    reached in total: %d' % blast['total'])
    if blast['crown_jewels_reached']:
        print('    CROWN JEWELS REACHED: %s' % ', '.join(
            c['key'] for c in blast['crown_jewels_reached']))
    else:
        print('    no crown jewel in reach')

    # ------------------------------------------------------------ question 3
    heading('3. NEVER SEEN BEFORE  What is new, including where every '
            'single step looks normal')
    novel = novel_activity(estate, window_hours=24, now=GENERATED)
    print('%d relationships first seen in the last %d hours.'
          % (novel['new_edge_count'], novel['window_hours']))

    unflagged = [r for r in novel['new_reach'] if r['unflagged_by_rules']]
    print('%d actors reached somewhere they never had before. '
          '%d of those travelled a route no detection rule has ever fired on.'
          % (novel['new_reach_count'], len(unflagged)))
    for item in unflagged:
        print('\n    %s now reaches %s'
              % (item['actor']['key'], item['target']['key']))
        print('    No rule fired on any step of this route:')
        show_steps(item['steps'], indent='        ')

    # ------------------------------------------------------------ question 4
    heading('4. ONE INCIDENT, NOT SIX  Connected anomalies, grouped')
    for group in novel['incidents']:
        print('    %d connected: %s'
              % (len(group), ', '.join(short(g['key'], 24) for g in group)))
    if not novel['incidents']:
        print('    nothing connected')

    # ------------------------------------------------------------ question 5
    heading('5. WHAT WOULD HURT MOST  Centrality over our own systems')
    crit = critical_nodes(estate, limit=5)
    for row in crit:
        print('    %-30s %.4f   %s' % (short(row['key'], 30), row['score'],
                                       row['zone']))
    print('\n    External addresses are excluded. They score well on this '
          'measure\n    because they point at our surfaces, but there is '
          'nothing to harden\n    about an address that is already hostile.')

    # ------------------------------------------------------------ question 6
    heading('6. WHICH PART OF THE BUSINESS  Community detection')
    segs = segments(estate, now=GENERATED)
    for s in segs:
        if s['size'] < 2:
            continue
        crown = (' holds %s' % ', '.join(short(c['key'], 20)
                                         for c in s['crown_jewels'])
                 if s['crown_jewels'] else '')
        flag = '   <-- NEW ACTIVITY HERE' if s['has_new_activity'] else ''
        print('    segment of %-2d%s%s' % (s['size'], crown, flag))

    # ------------------------------------------------------------ question 7
    heading('7. GRANTED BUT NEVER USED  Standing access, before anyone '
            'exploits it')
    priv = over_privilege(estate)
    print('%d entitlements granted, %d ever exercised, %d dormant.'
          % (priv['granted'], priv['exercised'], len(priv['dormant'])))
    for d in priv['dormant']:
        mark = '  REACHES A CROWN JEWEL' if d['reaches_crown_jewel'] else ''
        print('    %-18s may reach %-26s%s'
              % (short(d['identity']['key'], 18),
                 short(d['target']['key'], 26), mark))
    print('\n    Nobody has to be attacked for this to be worth fixing, '
          'which is what\n    makes it the pre-incident half of the problem.')

    # The viewer reads this.
    out = os.path.join(HERE, 'data', 'answers.json')
    with open(out, 'w', encoding='utf-8') as handle:
        json.dump({'estate': {'name': estate.name,
                              'nodes': estate.nodes, 'edges': estate.edges},
                   'exposure': exp, 'blast': blast, 'novel': novel,
                   'critical': crit, 'segments': segs, 'privilege': priv},
                  handle, indent=2, default=str)
    print('\nWrote %s for the viewer.' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
