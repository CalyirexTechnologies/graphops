"""Exporters, findings and control assessment."""
from __future__ import annotations

import csv
import io
import json

import pytest

from graphops.compliance.assess import NOT_ASSESSED, NOT_SATISFIED, assess
from graphops.compliance.controls import FRAMEWORKS
from graphops.exporters import EXPORTERS, export_estate
from graphops.findings import SEVERITIES, derive, fingerprint


# ---------------------------------------------------------------- findings
def test_a_fingerprint_is_stable_across_runs(connector_estate):
    first = {f['fingerprint'] for f in derive(connector_estate)}
    second = {f['fingerprint'] for f in derive(connector_estate)}
    assert first == second and first


def test_a_fingerprint_covers_what_a_finding_is_about_not_when():
    assert (fingerprint('choke-point', 'n1')
            == fingerprint('choke-point', 'n1'))
    assert (fingerprint('choke-point', 'n1')
            != fingerprint('choke-point', 'n2'))


def test_findings_are_ordered_most_severe_first(connector_estate):
    order = {name: index for index, name in enumerate(SEVERITIES)}
    produced = derive(connector_estate)
    ranks = [order[f['severity']] for f in produced]
    assert ranks == sorted(ranks)


def test_a_choke_point_produces_one_finding_not_one_per_route(connector_estate):
    produced = [f for f in derive(connector_estate)
                if f['kind'] == 'choke-point']
    for finding in produced:
        assert finding['routes'] >= 2, (
            'a choke point on one route is not a choke point')


def test_dormant_access_reaching_regulated_data_is_high(connector_estate):
    dormant = [f for f in derive(connector_estate)
               if f['kind'] == 'over-privilege' and f.get('target')]
    assert dormant
    assert all(f['severity'] == 'high' for f in dormant)


def test_every_finding_carries_remediation(connector_estate):
    assert all(f['remediation'] for f in derive(connector_estate))


# --------------------------------------------------------------- exporters
@pytest.mark.parametrize('fmt', sorted(EXPORTERS))
def test_every_exporter_returns_json_serialisable_output(connector_estate, fmt):
    payload = export_estate(connector_estate, fmt=fmt)
    json.dumps(payload)        # must not raise


def test_an_unknown_format_is_refused(connector_estate):
    with pytest.raises(ValueError, match='unknown export format'):
        export_estate(connector_estate, fmt='xlsx')


def test_stix_ids_are_deterministic(connector_estate):
    first = export_estate(connector_estate, fmt='stix')
    second = export_estate(connector_estate, fmt='stix')
    assert ([o['id'] for o in first['objects']]
            == [o['id'] for o in second['objects']]), (
        're-exporting an unchanged estate must not create new objects')


def test_stix_objects_declare_the_spec_version(connector_estate):
    bundle = export_estate(connector_estate, fmt='stix')
    assert bundle['type'] == 'bundle'
    for obj in bundle['objects']:
        if obj['type'] != 'bundle':
            assert obj.get('spec_version') == '2.1', obj['type']


def test_sarif_fingerprints_let_a_consumer_deduplicate(connector_estate):
    document = export_estate(connector_estate, fmt='sarif')
    assert document['version'] == '2.1.0'
    results = document['runs'][0]['results']
    assert results
    for result in results:
        assert result['partialFingerprints']['graphopsFingerprint/v1']
        # No physicalLocation: an attack path has no file and no line.
        assert 'physicalLocation' not in result['locations'][0]


def test_sarif_rule_indices_point_at_real_rules(connector_estate):
    run = export_estate(connector_estate, fmt='sarif')['runs'][0]
    rules = run['tool']['driver']['rules']
    for result in run['results']:
        assert rules[result['ruleIndex']]['id'] == result['ruleId']


def test_oscal_carries_an_observation_for_every_finding(connector_estate):
    document = export_estate(connector_estate, fmt='oscal')
    results = document['assessment-results']['results'][0]
    assert len(results['observations']) == len(derive(connector_estate))
    assert results['findings']


def test_csv_quotes_a_title_containing_a_comma():
    """Hand-rolled CSV breaks on the first comma in a finding title."""
    from graphops.exporters.csv_export import to_csv

    class Fake:
        pass

    import graphops.findings as findings_module
    original = findings_module.derive
    findings_module.derive = lambda estate: [{
        'fingerprint': 'f1', 'severity': 'high', 'kind': 'attack-path',
        'title': 'reaches billing-database, hr-database and more',
        'routes': 2, 'target': 'x', 'remediation': 'say "fix it"'}]
    try:
        payload = to_csv(Fake())
    finally:
        findings_module.derive = original
    rows = list(csv.reader(io.StringIO(payload['content'])))
    assert rows[1][3] == 'reaches billing-database, hr-database and more'
    assert rows[1][6] == 'say "fix it"'


def test_csv_neutralises_a_formula():
    """A cell starting with = executes when a spreadsheet opens it."""
    from graphops.exporters.csv_export import _safe
    assert _safe('=cmd|calc').startswith("'=")
    assert _safe('+1').startswith("'+")
    assert _safe('normal') == 'normal'


# -------------------------------------------------------------- compliance
@pytest.mark.parametrize('framework', sorted(FRAMEWORKS))
def test_every_framework_assesses(connector_estate, framework):
    report = assess(connector_estate, framework=framework)
    assert report['controls']
    assert report['controls_assessed'] == len(FRAMEWORKS[framework])


def test_a_control_is_never_reported_satisfied(connector_estate):
    """Absence of evidence is not evidence the control operates."""
    for framework in FRAMEWORKS:
        for control in assess(connector_estate,
                              framework=framework)['controls']:
            assert control['status'] in (NOT_SATISFIED, NOT_ASSESSED)
            assert control['status'] != 'satisfied'


def test_a_control_with_no_evidence_is_not_assessed():
    """An empty estate must produce not-assessed, never a green dashboard."""
    from graphops.analysis import Estate
    empty = Estate({'name': 'empty', 'nodes': [], 'edges': []})
    for control in assess(empty, framework='soc2')['controls']:
        assert control['status'] == NOT_ASSESSED
        assert control['evidence_count'] == 0


def test_contradicted_controls_name_their_evidence(connector_estate):
    report = assess(connector_estate, framework='soc2')
    contradicted = [c for c in report['controls']
                    if c['status'] == NOT_SATISFIED]
    assert contradicted
    for control in contradicted:
        assert control['evidence']
        assert all(item['fingerprint'] for item in control['evidence'])


def test_every_control_states_what_the_graph_actually_checks():
    for controls in FRAMEWORKS.values():
        for control in controls:
            assert control.question.endswith('?')
            assert control.contradicted_by


def test_the_disclaimer_is_present(connector_estate):
    report = assess(connector_estate, framework='soc2')
    assert 'not an audit opinion' in report['disclaimer']


def test_an_unknown_framework_is_refused(connector_estate):
    with pytest.raises(ValueError, match='unknown framework'):
        assess(connector_estate, framework='pci')
