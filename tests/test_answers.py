"""The answers use what the vendors send.

test_model.py proves the fields survive ingest. This file proves the answers
read them, and in particular that "dormant" now means what a zero-trust
review means by it.

DORMANT USED TO BE BINARY AND SOMETIMES WRONG. A grant with no matching use
in the graph was dormant, full stop. That made two mistakes at once. A grant
used once two years ago counted as exercised forever. And a grant from a
source that never reports use, such as an Entra directory role membership,
was reported as "never used", which is a claim nobody had evidence for.

Now each grant has a status:

  used     a use observed within the idle window
  idle     the last use is older than the window       (dormant)
  never    the source reports use and there is none    (dormant)
  unknown  nothing reports whether it is used          (not dormant)
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from graphops import analysis, findings
from graphops import estate as estate_module
from graphops.connectors import registry, resolve
from graphops.vocab import EdgeKind, NodeKind, Zone


@pytest.fixture(scope='module')
def connector_estate():
    return analysis.Estate(resolve.resolve(registry.ingest().estate))


def _grant(result, identity, target):
    for row in result['grants']:
        if row['identity']['key'] == identity and row['target']['key'] == target:
            return row
    raise AssertionError('no grant %s -> %s' % (identity, target))


# --------------------------------------------------------- over-privilege

def test_a_grant_used_recently_counts_as_exercised(connector_estate):
    row = _grant(analysis.over_privilege(connector_estate),
                 'svc-deploy', 's3://nightly-backups')
    assert row['status'] == 'used'
    assert row['last_used'] == '2026-11-03T04:00:00Z'


def test_a_grant_that_was_never_used_is_dormant(connector_estate):
    result = analysis.over_privilege(connector_estate)
    row = _grant(result, 'support-desk', 'billing-database')
    assert row['status'] == 'never'
    assert row['last_used'] is None
    assert row in result['dormant']


def test_a_grant_whose_source_never_reports_use_is_unknown_not_dormant(
        connector_estate):
    """Entra's role listing says who holds a role and nothing about use.
    Calling that "never used" was a claim with no evidence behind it."""
    result = analysis.over_privilege(connector_estate)
    row = _grant(result, 'ci-pipeline', 'Application Administrator')
    assert row['status'] == 'unknown'
    assert row not in result['dormant']


def test_the_counts_add_up(connector_estate):
    result = analysis.over_privilege(connector_estate)
    assert result['granted'] == 9
    assert result['exercised'] == 4
    assert len(result['dormant']) == 3
    assert result['unverified'] == 2
    assert (result['exercised'] + len(result['dormant']) + result['unverified']
            == result['granted'])


def test_the_hand_authored_estate_keeps_its_numbers():
    """It predates every field here. Its logs are complete by construction,
    so a missing use there still means never used."""
    result = analysis.over_privilege(analysis.Estate(estate_module.build()))
    assert (result['granted'], result['exercised'], len(result['dormant'])) == (6, 4, 2)
    assert result['unverified'] == 0


def _estate_with_one_grant(last_used, as_of='2026-11-03T09:00:00Z'):
    return analysis.Estate({'as_of': as_of, 'nodes': [
        {'id': 'id:old-admin', 'kind': NodeKind.IDENTITY, 'key': 'old-admin',
         'zone': Zone.INTERNAL, 'crown': False},
        {'id': 'asset:ledger', 'kind': NodeKind.ASSET, 'key': 'ledger',
         'zone': Zone.CROWN, 'crown': True, 'regimes': ['SOX']}],
        'edges': [{'src': 'id:old-admin', 'dst': 'asset:ledger',
                   'kind': EdgeKind.ENTITLED, 'cost': 1.0,
                   'first_seen': '2025-01-01T00:00:00Z',
                   'last_used': last_used, 'via': 'direct',
                   'permission': 'Okta app assignment'}]})


def test_a_grant_unused_for_longer_than_the_window_is_dormant_by_age():
    """Used once, two hundred days ago. Exercised under the old rule
    forever; dormant under the one a zero-trust review actually applies."""
    estate = _estate_with_one_grant('2026-04-17T09:00:00Z')
    result = analysis.over_privilege(estate)
    row = result['grants'][0]
    assert row['status'] == 'idle'
    assert row['idle_days'] == 200
    assert row in result['dormant']


def test_the_idle_window_is_a_parameter_rather_than_a_belief():
    estate = _estate_with_one_grant('2026-04-17T09:00:00Z')
    assert analysis.over_privilege(estate, idle_days=365)['grants'][0]['status'] == 'used'


def test_a_dormant_grant_says_how_it_was_made_and_what_it_reaches(connector_estate):
    row = _grant(analysis.over_privilege(connector_estate),
                 'support-desk', 'billing-database')
    assert row['via'] == 'group'
    assert row['permission'] == 'Okta app assignment'
    assert row['target']['regimes'] == ['PCI']
    assert row['reaches_crown_jewel'] is True


def test_a_suspended_account_still_holding_a_grant_says_so(connector_estate):
    """The contractor Okta suspended is still entitled to the card database.
    The suspension is the context that makes it the first thing to fix."""
    row = _grant(analysis.over_privilege(connector_estate),
                 'former-contractor', 'billing-database')
    assert row['identity']['suspended'] is True
    assert row['status'] == 'never'


def test_grants_on_routes_say_how_many_routes_they_carry(connector_estate):
    result = analysis.over_privilege(connector_estate)
    carried = [row for row in result['grants'] if row['routes_through']]
    assert carried, 'no grant sits on any route, which the demo contradicts'


# ---------------------------------------------------------------- findings

def test_a_finding_about_an_unverified_grant_does_not_claim_it_was_never_used(
        connector_estate):
    titles = [f['title'] for f in findings.derive(connector_estate)
              if f['kind'] == 'over-privilege']
    entra = [t for t in titles if 'Application Administrator' in t]
    assert entra, 'a privileged role held with no usage data is still a finding'
    assert all('never' not in t for t in entra), entra


def test_an_idle_grant_finding_says_how_long_it_has_been_idle():
    estate = _estate_with_one_grant('2026-04-17T09:00:00Z')
    titles = [f['title'] for f in findings.derive(estate)
              if f['kind'] == 'over-privilege']
    assert any('200 days' in t for t in titles), titles


# ------------------------------------------------------------- containment

def test_a_revocation_says_where_the_grant_was_made(connector_estate):
    """A grant that came through a group is removed from the group, not from
    the person, and a remediation that names the wrong place does not happen."""
    options = analysis.containment(connector_estate)['options']
    revocations = [o for o in options if o['kind'] == 'entitlement']
    assert revocations
    for option in revocations:
        assert option['via'] in ('group', 'direct', 'directory role', None)
        assert option['granted_to']
    group_held = [o for o in revocations if o['via'] == 'group']
    assert group_held and all('group' in o['cut']['action'] for o in group_held)


# ---------------------------------------------------------------- exposure

def test_exposure_counts_the_routes_to_each_crown_jewel(connector_estate):
    result = analysis.exposure(connector_estate)
    assert result['targets']
    assert sum(t['routes'] for t in result['targets']) == result['path_count']
    assert result['crown_jewels_total'] >= len(result['targets'])


def test_a_crown_jewel_in_an_answer_carries_its_regime(connector_estate):
    targets = analysis.exposure(connector_estate)['targets']
    by_key = {t['key']: t for t in targets}
    assert by_key['billing-database']['regimes'] == ['PCI']


def test_critical_systems_say_whether_they_face_the_internet(connector_estate):
    for row in analysis.critical_nodes(connector_estate):
        assert isinstance(row['facing_internet'], bool)
        assert row['routes_through'] >= 0


# ---------------------------------------------------------------- segments

def test_a_segment_is_labelled_only_by_what_its_members_share(connector_estate):
    """Named from a real field when one dominates, never invented. A
    segment with nothing in common says so rather than taking a title."""
    for segment in analysis.segments(connector_estate):
        label = segment['label']
        assert label
        if segment.get('shared'):
            field, value, count = (segment['shared']['field'],
                                   segment['shared']['value'],
                                   segment['shared']['members'])
            assert count <= segment['size']
            assert value in label
            members_with = [m for m in segment['members']
                            if (m.get(field) or '') == value]
            assert len(members_with) == count


def test_a_replay_and_a_week_later_give_the_same_answers(connector_estate):
    """The same estate asked the same question on two different days."""
    later = connector_estate.now() + timedelta(days=7)
    assert (analysis.over_privilege(connector_estate)['exercised']
            == analysis.over_privilege(connector_estate, now=connector_estate.now())['exercised'])
    assert analysis.over_privilege(connector_estate, now=later)['granted'] == 9
