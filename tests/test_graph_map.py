"""The whole estate, drawable: analysis.estate_map and GET /v1/graph/map.

The console's Graph screen draws every system and relationship and lights
the other answers up on top. So the map has to be the estate exactly, it
has to line up with those answers for every role, and when it cannot show
everything it has to say so rather than draw a picture that looks complete.
"""
from __future__ import annotations

import json

import pytest

from graphops import analysis
from graphops.rbac.permissions import ROLE_PERMISSIONS, Permission, Role


def _ends(m):
    """Each drawn relationship as (from key, to key, kind)."""
    nodes = m['nodes']
    return sorted((nodes[e['s']]['key'], nodes[e['t']]['key'], e['kind'])
                  for e in m['edges'])


def _estate_ends(estate):
    key = {n['id']: n['key'] for n in estate.nodes}
    return sorted((key[e['src']], key[e['dst']], e['kind']) for e in estate.edges)


# ------------------------------------------------------------------ engine

@pytest.mark.parametrize('which', ['connector_estate', 'synthetic_estate'])
def test_the_map_is_every_system_and_every_relationship(which, request):
    estate = request.getfixturevalue(which)
    m = analysis.estate_map(estate)
    assert m['truncated'] is False and m['kept_by'] is None
    assert m['shown_nodes'] == m['total_nodes'] == len(estate.nodes)
    assert m['shown_edges'] == m['total_edges'] == len(estate.edges)
    assert sorted(n['id'] for n in m['nodes']) == sorted(n['id'] for n in estate.nodes)
    assert _ends(m) == _estate_ends(estate)


@pytest.mark.parametrize('which', ['connector_estate', 'synthetic_estate'])
def test_new_relationships_are_the_ones_novel_activity_counts(which, request):
    estate = request.getfixturevalue(which)
    m = analysis.estate_map(estate)
    assert sum(e['is_new'] for e in m['edges']) == \
        analysis.novel_activity(estate)['new_edge_count']


def test_edges_name_their_ends_by_position_and_never_by_id(connector_estate):
    """An id in an edge would be a second copy of a crown jewel's name, one
    the node masking does not touch."""
    m = analysis.estate_map(connector_estate)
    ids = {n['id'] for n in connector_estate.nodes}
    for e in m['edges']:
        assert set(e) == {'s', 't', 'kind', 'tactic', 'technique', 'cost',
                          'first_seen', 'is_new', 'sources'}
        assert 0 <= e['s'] < len(m['nodes']) and 0 <= e['t'] < len(m['nodes'])
        assert not ids & {v for v in e.values() if isinstance(v, str)}


def test_over_the_limit_every_crown_jewel_is_kept_and_the_cut_is_said(connector_estate):
    m = analysis.estate_map(connector_estate, limit=10)
    crown = {n['id'] for n in connector_estate.nodes if n.get('crown')}
    assert m['truncated'] is True and m['kept_by']
    assert m['shown_nodes'] == 10
    assert m['total_nodes'] == len(connector_estate.nodes)
    assert m['total_edges'] == len(connector_estate.edges)
    assert crown <= {n['id'] for n in m['nodes']}
    # Only relationships between kept systems, so nothing points off the map.
    assert all(e['s'] < 10 and e['t'] < 10 for e in m['edges'])


def test_systems_on_a_route_are_kept_before_merely_busy_ones(connector_estate):
    full = analysis.estate_map(connector_estate)
    wanted = {n['id'] for n in full['nodes'] if n['is_crown_jewel'] or n['on_route']}
    m = analysis.estate_map(connector_estate, limit=len(wanted))
    assert {n['id'] for n in m['nodes']} == wanted


def test_a_capped_dense_estate_still_draws_every_route_relationship(connector_estate):
    full = analysis.estate_map(connector_estate)
    on_route = [e for e in full['edges']
                if full['nodes'][e['s']]['on_route'] and full['nodes'][e['t']]['on_route']]
    m = analysis.estate_map(connector_estate, edge_limit=len(on_route))
    assert m['truncated'] is True and m['shown_edges'] == len(on_route)
    assert all(m['nodes'][e['s']]['on_route'] and m['nodes'][e['t']]['on_route']
               for e in m['edges'])


def test_the_same_estate_in_any_order_draws_the_same_map(connector_estate):
    first = analysis.estate_map(connector_estate)
    payload = {'name': connector_estate.name,
               'nodes': list(connector_estate.nodes),
               'edges': list(connector_estate.edges),
               'as_of': connector_estate.as_of.isoformat(),
               'mode': connector_estate.mode}
    # Reversed and rotated rather than shuffled: a fixed reordering needs no
    # random generator and still puts every record somewhere new.
    payload['nodes'].reverse()
    payload['edges'] = payload['edges'][17:] + payload['edges'][:17]
    shuffled = analysis.estate_map(analysis.Estate(payload))
    assert first['nodes'] == shuffled['nodes']
    assert _ends(first) == _ends(shuffled)


# --------------------------------------------------------------------- API

@pytest.mark.parametrize('role', sorted(r.value for r in ROLE_PERMISSIONS
                                        if r is not Role.SERVICE))
def test_the_map_needs_graph_query(client, auth_header, role):
    allowed = Permission.GRAPH_QUERY in ROLE_PERMISSIONS[Role(role)]
    response = client.get('/v1/graph/map', headers=auth_header(role))
    assert response.status_code == (200 if allowed else 403), (role, response.text)


def test_an_analyst_gets_the_whole_connector_estate(client, auth_header, connector_estate):
    body = client.get('/v1/graph/map', headers=auth_header('analyst')).json()
    assert body['total_nodes'] == len(connector_estate.nodes) == 35
    assert body['total_edges'] == len(connector_estate.edges) == 47
    assert body['truncated'] is False
    assert '_redaction' not in body


def test_an_auditor_sees_the_whole_map_and_no_crown_jewel_name(client, auth_header,
                                                               connector_estate):
    body = client.get('/v1/graph/map', headers=auth_header('auditor')).json()
    text = json.dumps(body).lower()
    names = set()
    for n in connector_estate.nodes:
        if n.get('crown'):
            names |= {str(n['key']).lower(), str(n.get('label') or n['key']).lower()}
    assert names and not {name for name in names if name in text}
    assert body['total_nodes'] == 35 and body['shown_nodes'] == 35
    jewels = [n for n in body['nodes'] if n['is_crown_jewel']]
    assert jewels and all(n.get('redacted') for n in jewels)
    assert body['_redaction']['nodes_redacted'] >= len(jewels)


def test_an_auditors_map_lines_up_with_the_auditors_routes(client, auth_header):
    """The Graph screen lights a route up by matching its step ids to map
    nodes. For a role that sees pseudonyms, the two answers must use the
    same ones, or a route would light up nothing."""
    headers = auth_header('auditor')
    body = client.get('/v1/graph/map', headers=headers).json()
    routes = client.get('/v1/graph/exposure', headers=headers).json()
    on_map = {n['id'] for n in body['nodes']}
    stepped = {end['id'] for path in routes['paths'] for step in path['steps']
               for end in (step['from'], step['to'])}
    assert stepped and stepped <= on_map
    assert any(i.startswith('crown-jewel-') for i in stepped)


@pytest.mark.parametrize('query', ['limit=0', 'limit=2001', 'window_hours=0'])
def test_the_map_refuses_bounds_it_does_not_offer(client, auth_header, query):
    response = client.get('/v1/graph/map?' + query, headers=auth_header('analyst'))
    assert response.status_code == 422
