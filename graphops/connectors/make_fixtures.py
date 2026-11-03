"""Generates the connector fixtures.

Run with `python3 -m graphops.connectors.make_fixtures`.

The fixtures are not nine unrelated samples. They describe one business seen
from nine angles, which is the point: the merged graph has to contain routes
that no single source could have shown, or the whole architecture is
decoration.

The story they encode, and which `demo_connectors` then finds:

  * Splunk sees ordinary scanning against the perimeter, and one address,
    192.0.2.41, that has only ever requested /login. No rule fires on it.
  * CloudTrail sees that same address assume the svc-deploy role five hours
    ago, and svc-deploy then read s3://nightly-backups.
  * Okta says svc-deploy was always entitled to the backups, and that
    support-desk is entitled to the billing and HR databases and has never
    used either.
  * ServiceNow is the only source that knows billing-database is PCI-scoped,
    so it is the only reason either is treated as a crown jewel.

Taken alone, each of these is unremarkable. The Splunk row is noise, the
CloudTrail call is an authorised role doing an authorised read, and the Okta
entitlement is a ticket somebody closed two years ago. Together they are a
route from the internet to every backup the company holds.

Every address is from the RFC 5737 documentation ranges and routes nowhere.
Every company, host, person and identifier is invented. These are synthetic
records in each vendor's published response shape, not captures from any
tenant.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent / 'fixtures'

GENERATED = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
OLD = GENERATED - timedelta(days=40)
RECENT = GENERATED - timedelta(days=6)
NEW = GENERATED - timedelta(hours=5)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace('+00:00', 'Z')


def splunk() -> dict:
    """Splunk saved-search results: src_ip, uri_path, count, notable_rule."""
    rows = []
    noisy = [('198.51.100.21', 'path-enumeration'),
             ('198.51.100.84', None),
             ('203.0.113.9', 'path-enumeration'),
             ('203.0.113.77', None),
             ('192.0.2.133', 'repeated-auth-failure')]
    for address, rule in noisy:
        for path in ('/login', '/api/orders'):
            rows.append({'_time': iso(OLD), 'src_ip': address,
                         'uri_path': path, 'count': 412,
                         'status': 404, 'notable_rule': rule})
    for address in ('198.51.100.21', '203.0.113.9', '192.0.2.133'):
        rows.append({'_time': iso(OLD), 'src_ip': address,
                     'uri_path': '/admin', 'count': 88, 'status': 403,
                     'notable_rule': 'path-enumeration'})
    for address in ('198.51.100.84', '203.0.113.77'):
        rows.append({'_time': iso(RECENT), 'src_ip': address,
                     'uri_path': '/api/uploads', 'count': 17, 'status': 200,
                     'notable_rule': None})
    # The quiet one. One ordinary request, no rule.
    rows.append({'_time': iso(OLD), 'src_ip': '192.0.2.41',
                 'uri_path': '/login', 'count': 3, 'status': 200,
                 'notable_rule': None})
    # A row with a missing field, so the skip path is exercised by the
    # fixture rather than only by a unit test.
    rows.append({'_time': iso(RECENT), 'src_ip': '', 'uri_path': '/login',
                 'count': 1, 'status': 200, 'notable_rule': None})
    return {'preview': False, 'init_offset': 0, 'messages': [],
            'fields': [{'name': k} for k in
                       ('_time', 'src_ip', 'uri_path', 'count',
                        'status', 'notable_rule')],
            'results': rows}


def sentinel() -> dict:
    """Sentinel incidents with relatedEntities, per the SecurityInsights API."""
    return {'value': [
        {'id': '/subscriptions/0000/incidents/1', 'name': 'inc-1',
         'type': 'Microsoft.SecurityInsights/Incidents',
         'properties': {
             'title': 'repeated-auth-failure', 'severity': 'Medium',
             'status': 'Active', 'createdTimeUtc': iso(RECENT),
             'incidentNumber': 1041,
             'relatedEntities': [
                 {'kind': 'Ip', 'value': '192.0.2.133'},
                 {'kind': 'Account', 'value': 'support-desk'},
             ]}},
        {'id': '/subscriptions/0000/incidents/2', 'name': 'inc-2',
         'type': 'Microsoft.SecurityInsights/Incidents',
         'properties': {
             'title': 'anomalous-role-assumption', 'severity': 'High',
             'status': 'New', 'createdTimeUtc': iso(NEW),
             'incidentNumber': 1042,
             'relatedEntities': [
                 {'kind': 'Ip', 'value': '192.0.2.41'},
                 {'kind': 'Account', 'value': 'svc-deploy'},
             ]}},
    ]}


def crowdstrike() -> dict:
    """Falcon detections, device plus behaviors."""
    return {'meta': {'query_time': 0.031}, 'errors': [], 'resources': [
        {'detection_id': 'ldt:1', 'created_timestamp': iso(RECENT),
         'max_severity_displayname': 'High',
         'device': {'device_id': 'd1', 'hostname': 'storefront-web',
                    'platform_name': 'Linux',
                    'external_ip': '198.51.100.84',
                    'local_ip': '10.2.0.11'},
         'behaviors': [
             {'behavior_id': 'b1', 'timestamp': iso(RECENT),
              'display_name': 'SuspiciousWebShellWrite',
              'tactic': 'Persistence', 'technique': 'Server Software Component',
              'technique_id': 'T1505.003', 'severity_name': 'High',
              'user_name': 'www-data'},
         ]},
        {'detection_id': 'ldt:2', 'created_timestamp': iso(NEW),
         'max_severity_displayname': 'Critical',
         'device': {'device_id': 'd2', 'hostname': 'order-service',
                    'platform_name': 'Linux',
                    'external_ip': '198.51.100.21',
                    'local_ip': '10.2.0.24'},
         'behaviors': [
             {'behavior_id': 'b2', 'timestamp': iso(NEW),
              'display_name': 'CredentialDumpingFromMemory',
              'tactic': 'Credential Access', 'technique': 'OS Credential Dumping',
              'technique_id': 'T1003.007', 'severity_name': 'Critical',
              'user_name': 'finance-admin'},
         ]},
    ]}


def okta() -> dict:
    """Okta users with appAssignments, and the app catalogue."""
    apps = [
        {'id': 'app1', 'label': 's3://nightly-backups', 'status': 'ACTIVE'},
        {'id': 'app2', 'label': 'billing-database', 'status': 'ACTIVE'},
        {'id': 'app3', 'label': 'hr-database', 'status': 'ACTIVE'},
        {'id': 'app4', 'label': 'iam', 'status': 'ACTIVE'},
    ]
    users = [
        {'id': 'u1', 'status': 'ACTIVE',
         'profile': {'login': 'svc-deploy', 'email': 'svc-deploy@example.invalid',
                     'firstName': 'Deployment', 'lastName': 'Service'},
         'appAssignments': [
             # Entitled long ago; first exercised five hours ago. That gap is
             # the finding.
             {'appId': 'app1', 'scope': 'GROUP', 'created': iso(OLD),
              'lastSignOn': iso(NEW)},
             {'appId': 'app4', 'scope': 'USER', 'created': iso(OLD),
              'lastSignOn': iso(OLD)},
         ]},
        {'id': 'u2', 'status': 'ACTIVE',
         'profile': {'login': 'support-desk', 'email': 'support@example.invalid',
                     'firstName': 'Support', 'lastName': 'Desk'},
         'appAssignments': [
             {'appId': 'app4', 'scope': 'USER', 'created': iso(OLD),
              'lastSignOn': iso(OLD)},
             # Never signed on. Both of these end at regulated data.
             {'appId': 'app2', 'scope': 'GROUP', 'created': iso(OLD),
              'lastSignOn': None},
             {'appId': 'app3', 'scope': 'GROUP', 'created': iso(OLD),
              'lastSignOn': None},
         ]},
        {'id': 'u3', 'status': 'ACTIVE',
         'profile': {'login': 'svc-backup', 'email': 'svc-backup@example.invalid',
                     'firstName': 'Backup', 'lastName': 'Service'},
         'appAssignments': [
             {'appId': 'app1', 'scope': 'USER', 'created': iso(OLD),
              'lastSignOn': iso(OLD)},
         ]},
        {'id': 'u4', 'status': 'SUSPENDED',
         'profile': {'login': 'former-contractor',
                     'email': 'contractor@example.invalid',
                     'firstName': 'Former', 'lastName': 'Contractor'},
         # Suspended in Okta, still assigned. Whether the downstream app
         # honours the suspension is exactly the question worth asking.
         'appAssignments': [
             {'appId': 'app2', 'scope': 'USER', 'created': iso(OLD),
              'lastSignOn': None},
         ]},
    ]
    return {'users': users, 'apps': apps}


def entra() -> dict:
    """Entra ID directory roles with expanded members."""
    return {'value': [
        {'id': 'r1', 'displayName': 'Application Administrator',
         'description': 'Can manage all aspects of app registrations.',
         'members': [
             {'@odata.type': '#microsoft.graph.servicePrincipal',
              'id': 'sp1', 'displayName': 'ci-pipeline',
              'createdDateTime': iso(OLD)},
         ]},
        {'id': 'r2', 'displayName': 'Security Reader',
         'description': 'Can read security information.',
         'members': [
             {'@odata.type': '#microsoft.graph.user', 'id': 'au1',
              'userPrincipalName': 'auditor@example.invalid',
              'displayName': 'Auditor', 'createdDateTime': iso(OLD)},
         ]},
    ]}


def cloudtrail() -> dict:
    """CloudTrail records: the quiet address assuming a role, then reading."""
    return {'Records': [
        {'eventVersion': '1.08', 'eventTime': iso(NEW),
         'eventSource': 'sts.amazonaws.com', 'eventName': 'AssumeRole',
         'awsRegion': 'ap-south-1', 'sourceIPAddress': '192.0.2.41',
         'userIdentity': {'type': 'AssumedRole',
                          'principalId': 'AROAEXAMPLE:deploy',
                          'arn': 'arn:aws:sts::000000000000:assumed-role/svc-deploy',
                          'userName': 'svc-deploy'},
         'resources': [], 'responseElements': {'credentials': {}}},
        {'eventVersion': '1.08', 'eventTime': iso(NEW),
         'eventSource': 's3.amazonaws.com', 'eventName': 'GetObject',
         'awsRegion': 'ap-south-1', 'sourceIPAddress': '192.0.2.41',
         'userIdentity': {'type': 'AssumedRole',
                          'arn': 'arn:aws:sts::000000000000:assumed-role/svc-deploy',
                          'userName': 'svc-deploy'},
         'resources': [{'ARN': 'arn:aws:s3:::nightly-backups',
                        'type': 'AWS::S3::Object'}]},
        {'eventVersion': '1.08', 'eventTime': iso(OLD),
         'eventSource': 's3.amazonaws.com', 'eventName': 'GetObject',
         'awsRegion': 'ap-south-1', 'sourceIPAddress': 's3.amazonaws.com',
         'userIdentity': {'type': 'AssumedRole',
                          'arn': 'arn:aws:sts::000000000000:assumed-role/svc-backup',
                          'userName': 'svc-backup'},
         'resources': [{'ARN': 'arn:aws:s3:::nightly-backups',
                        'type': 'AWS::S3::Object'}]},
    ]}


def qualys() -> dict:
    """Qualys VMDR host detections."""
    return {'HOST_LIST': [
        {'ID': 1, 'IP': '10.2.0.11', 'DNS': 'storefront-web',
         'DETECTION_LIST': [
             {'QID': 38657, 'CVE': 'CVE-2025-9910', 'SEVERITY': 4,
              'CVSS_BASE': '7.5', 'EXPLOIT_MATURITY': 'poc',
              'FIRST_FOUND_DATETIME': iso(OLD), 'STATUS': 'ACTIVE'},
         ]},
        {'ID': 2, 'IP': '10.2.0.24', 'DNS': 'order-service',
         'DETECTION_LIST': [
             {'QID': 41102, 'CVE': 'CVE-2026-0442', 'SEVERITY': 5,
              'CVSS_BASE': '9.8', 'EXPLOIT_MATURITY': 'wild',
              'FIRST_FOUND_DATETIME': iso(OLD), 'STATUS': 'ACTIVE'},
         ]},
    ]}


def tenable() -> dict:
    """Tenable.io workbench vulnerabilities, nested the other way round."""
    return {'vulnerabilities': [
        {'plugin_id': 186234, 'plugin_name': 'Unauthenticated file upload',
         'cves': ['CVE-2026-1188'], 'severity': 4, 'cvss3_base_score': 9.1,
         'exploit_maturity': 'functional', 'first_found': iso(OLD),
         'count': 1,
         'assets': [{'id': 'a3', 'hostname': 'file-store',
                     'fqdn': 'file-store.internal.invalid'}]},
        {'plugin_id': 142991, 'plugin_name': 'Outdated TLS library',
         'cves': ['CVE-2025-9910'], 'severity': 3, 'cvss3_base_score': 7.5,
         'exploit_maturity': 'poc', 'first_found': iso(OLD), 'count': 1,
         'assets': [{'id': 'a1', 'hostname': 'storefront-web',
                     'fqdn': 'storefront-web.internal.invalid'}]},
    ]}


def servicenow() -> dict:
    """CMDB items and relationships. The only source of a real crown flag."""
    items = [
        {'sys_id': 'ci1', 'name': 'billing-database',
         'sys_class_name': 'cmdb_ci_db_instance',
         'data_classification': 'PCI', 'owned_by': 'finance-ops',
         'used_for': 'Production'},
        {'sys_id': 'ci2', 'name': 'hr-database',
         'sys_class_name': 'cmdb_ci_db_instance',
         'data_classification': 'PII', 'owned_by': 'people-ops',
         'used_for': 'Production'},
        {'sys_id': 'ci3', 'name': 'order-service',
         'sys_class_name': 'cmdb_ci_appl',
         'data_classification': 'Internal', 'owned_by': 'commerce',
         'used_for': 'Production'},
        {'sys_id': 'ci4', 'name': 'storefront-web',
         'sys_class_name': 'cmdb_ci_appl',
         'data_classification': 'Public', 'owned_by': 'commerce',
         'used_for': 'Production'},
        {'sys_id': 'ci5', 'name': 'file-store',
         'sys_class_name': 'cmdb_ci_appl',
         'data_classification': 'Internal', 'owned_by': 'platform',
         'used_for': 'Production'},
    ]
    relationships = [
        # The order service reads the billing database. This single CMDB row
        # is what makes a bug in the order tier a card-data problem.
        {'sys_id': 'rel1', 'parent': 'ci3', 'child': 'ci1',
         'type': 'Depends on::Used by', 'sys_created_on': iso(RECENT)},
        {'sys_id': 'rel2', 'parent': 'ci4', 'child': 'ci3',
         'type': 'Depends on::Used by', 'sys_created_on': iso(OLD)},
    ]
    return {'items': items, 'relationships': relationships}


BUILDERS = {
    'splunk': splunk, 'sentinel': sentinel, 'crowdstrike': crowdstrike,
    'okta': okta, 'entra': entra, 'cloudtrail': cloudtrail,
    'qualys': qualys, 'tenable': tenable, 'servicenow': servicenow,
}


def write_all() -> list[Path]:
    HERE.mkdir(parents=True, exist_ok=True)
    written = []
    for key, builder in sorted(BUILDERS.items()):
        path = HERE / ('%s.json' % key)
        with path.open('w', encoding='utf-8') as handle:
            json.dump(builder(), handle, indent=2, sort_keys=False)
            handle.write('\n')
        written.append(path)
    return written


if __name__ == '__main__':
    for path in write_all():
        print('wrote %s (%d bytes)' % (path.name, path.stat().st_size))
