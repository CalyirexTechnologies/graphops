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
Every company, host, person and identifier is invented.

EACH FILE IS A RECORDING OF HTTP EXCHANGES, not a payload. For every call a
connector's live path makes, the recording holds the request (method, path,
query and, where it matters, the JSON body) and the response in the shape
the vendor documents. Replay runs the live code against it, so a connector
that calls a vendor differently from its recording fails rather than
quietly passing. They are synthetic responses, not captures from a tenant.
The documentation each was checked against is on the connector as
`api_reference`.
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


def ex(method: str, path: str, *, query: dict | None = None, body=None,
       response=None, text: str | None = None, status: int = 200,
       match_body: bool = False) -> dict:
    """One recorded exchange."""
    request = {'method': method, 'path': path}
    if query:
        request['query'] = {k: str(v) for k, v in query.items()}
    if match_body:
        request['body'] = body
    reply = {'status': status}
    if text is not None:
        reply['text'] = text
    else:
        reply['body'] = response
    return {'request': request, 'response': reply}


def recording(vendor: str, docs: str, exchanges: list) -> dict:
    return {'vendor': vendor, 'documented_at': docs, 'recorded_at': iso(GENERATED),
            'exchanges': exchanges}


SPLUNK_SEARCH = 'GraphOps%20-%20Perimeter%20Access%20Summary'
SPLUNK_SID = 'scheduler__nobody__search__RMD5f1e2d3c4b5a69788_at_1793782800_412'


def splunk() -> dict:
    """The saved search's latest job, then that job's results."""
    rows = []
    noisy = [('198.51.100.21', 'path-enumeration'),
             ('198.51.100.84', None),
             ('203.0.113.9', 'path-enumeration'),
             ('203.0.113.77', None),
             ('192.0.2.133', 'repeated-auth-failure')]
    for address, rule in noisy:
        for path in ('/login', '/api/orders'):
            rows.append({'_time': iso(OLD), 'src_ip': address,
                         'uri_path': path, 'count': '412',
                         'status': '404', 'notable_rule': rule})
    for address in ('198.51.100.21', '203.0.113.9', '192.0.2.133'):
        rows.append({'_time': iso(OLD), 'src_ip': address,
                     'uri_path': '/admin', 'count': '88', 'status': '403',
                     'notable_rule': 'path-enumeration'})
    for address in ('198.51.100.84', '203.0.113.77'):
        rows.append({'_time': iso(RECENT), 'src_ip': address,
                     'uri_path': '/api/uploads', 'count': '17', 'status': '200',
                     'notable_rule': None})
    # The quiet one. One ordinary request, no rule.
    rows.append({'_time': iso(OLD), 'src_ip': '192.0.2.41',
                 'uri_path': '/login', 'count': '3', 'status': '200',
                 'notable_rule': None})
    # A row with a missing field, so the skip path is exercised by the
    # recording rather than only by a unit test.
    rows.append({'_time': iso(RECENT), 'src_ip': '', 'uri_path': '/login',
                 'count': '1', 'status': '200', 'notable_rule': None})
    history = {'links': {}, 'origin': '/services/saved/searches/%s/history' % SPLUNK_SEARCH,
               'updated': iso(GENERATED), 'generator': {'build': 'replay', 'version': '9.4.0'},
               'entry': [{'name': SPLUNK_SID, 'id': '/services/search/jobs/%s' % SPLUNK_SID,
                          'updated': iso(GENERATED - timedelta(hours=1)),
                          'published': iso(GENERATED - timedelta(hours=1)),
                          'content': {'dispatchState': 'DONE', 'isDone': True}}],
               'paging': {'total': 1, 'perPage': 30, 'offset': 0}, 'messages': []}
    results = {'preview': False, 'init_offset': 0, 'messages': [],
               'fields': [{'name': k} for k in
                          ('_time', 'src_ip', 'uri_path', 'count', 'status', 'notable_rule')],
               'results': rows, 'highlighted': {}}
    return recording('Splunk', 'Splunk REST API reference, search endpoints', [
        ex('GET', '/services/saved/searches/%s/history' % SPLUNK_SEARCH,
           query={'output_mode': 'json'}, response=history),
        ex('GET', '/services/search/v2/jobs/%s/results' % SPLUNK_SID,
           query={'output_mode': 'json', 'count': 0}, response=results),
    ])


SENTINEL_WS = ('/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/soc'
               '/providers/Microsoft.OperationalInsights/workspaces/sentinel-ws')
SENTINEL_INC = SENTINEL_WS + '/providers/Microsoft.SecurityInsights/incidents'
AZURE_TOKEN = {'token_type': 'Bearer', 'expires_in': 3599, 'ext_expires_in': 3599,
               'access_token': 'replay-token'}


def _sentinel_entity(kind: str, value: str, n: int) -> dict:
    guid = '00000000-0000-0000-0000-%012d' % n
    props = ({'address': value, 'friendlyName': value} if kind == 'Ip'
             else {'accountName': value, 'friendlyName': value})
    return {'id': SENTINEL_WS + '/providers/Microsoft.SecurityInsights/Entities/' + guid,
            'name': guid, 'type': 'Microsoft.SecurityInsights/Entities',
            'kind': kind, 'properties': props}


def sentinel() -> dict:
    """A token, incidents, then each incident's entities."""
    incidents = [
        ('6f1c2a90-1041-4a8e-9c1e-000000001041', 'repeated-auth-failure', 'Medium', 'Active',
         RECENT, 1041, [('Ip', '192.0.2.133'), ('Account', 'support-desk')]),
        ('6f1c2a90-1042-4a8e-9c1e-000000001042', 'anomalous-role-assumption', 'High', 'New',
         NEW, 1042, [('Ip', '192.0.2.41'), ('Account', 'svc-deploy')]),
    ]
    listing = {'value': [
        {'id': '%s/%s' % (SENTINEL_INC, name), 'name': name,
         'type': 'Microsoft.SecurityInsights/Incidents', 'etag': '"0300bf09-0000-0000-0000-5c37296e0000"',
         'properties': {'title': title, 'severity': severity, 'status': status,
                        'createdTimeUtc': iso(when), 'incidentNumber': number,
                        'additionalData': {'alertsCount': 1, 'alertProductNames': ['Azure Sentinel']}}}
        for name, title, severity, status, when, number, _ in incidents]}
    exchanges = [ex('POST', '/replay/oauth2/v2.0/token', response=AZURE_TOKEN),
                 ex('GET', SENTINEL_INC, query={'api-version': '2023-02-01'}, response=listing)]
    for i, (name, _t, _s, _st, _w, _n, entities) in enumerate(incidents):
        found = [_sentinel_entity(kind, value, i * 10 + j) for j, (kind, value) in enumerate(entities)]
        exchanges.append(ex('POST', '%s/%s/entities' % (SENTINEL_INC, name),
                            query={'api-version': '2023-02-01'}, body={}, match_body=True,
                            response={'entities': found, 'metaData': [
                                {'entityKind': kind, 'count': 1} for kind, _ in entities]}))
    return recording('Microsoft Sentinel', 'SecurityInsights REST API 2023-02-01', exchanges)


def crowdstrike() -> dict:
    """A token, alert IDs, then the alerts. One alert per behaviour."""
    alerts = [
        {'composite_id': '0000aaaa:ind:d2:1002', 'created_timestamp': iso(NEW),
         'timestamp': iso(NEW), 'product': 'epp', 'status': 'new',
         'severity': 90, 'severity_name': 'Critical',
         'name': 'CredentialDumpingFromMemory', 'display_name': 'CredentialDumpingFromMemory',
         'tactic': 'Credential Access', 'tactic_id': 'TA0006',
         'technique': 'OS Credential Dumping', 'technique_id': 'T1003.007',
         'user_name': 'finance-admin',
         'device': {'device_id': 'd2', 'hostname': 'order-service', 'platform_name': 'Linux',
                    'external_ip': '198.51.100.21', 'local_ip': '10.2.0.24'}},
        {'composite_id': '0000aaaa:ind:d1:1001', 'created_timestamp': iso(RECENT),
         'timestamp': iso(RECENT), 'product': 'epp', 'status': 'new',
         'severity': 70, 'severity_name': 'High',
         'name': 'SuspiciousWebShellWrite', 'display_name': 'SuspiciousWebShellWrite',
         'tactic': 'Persistence', 'tactic_id': 'TA0003',
         'technique': 'Server Software Component', 'technique_id': 'T1505.003',
         'user_name': 'www-data',
         'device': {'device_id': 'd1', 'hostname': 'storefront-web', 'platform_name': 'Linux',
                    'external_ip': '198.51.100.84', 'local_ip': '10.2.0.11'}},
    ]
    ids = [a['composite_id'] for a in alerts]
    meta = {'query_time': 0.031, 'powered_by': 'detectsapi', 'trace_id': 'replay'}
    return recording('CrowdStrike Falcon', 'Alerts v2 API', [
        ex('POST', '/oauth2/token', status=201,
           response={'access_token': 'replay-token', 'token_type': 'bearer', 'expires_in': 1799}),
        ex('GET', '/alerts/queries/alerts/v2', query={'limit': 500, 'sort': 'created_timestamp|desc'},
           response={'meta': meta, 'resources': ids, 'errors': []}),
        ex('POST', '/alerts/entities/alerts/v2', body={'composite_ids': ids}, match_body=True,
           response={'meta': meta, 'resources': alerts, 'errors': []}),
    ])


OKTA_APPS = [('0oa1backups0000001', 's3://nightly-backups'), ('0oa2billing0000001', 'billing-database'),
             ('0oa3hrdb0000000001', 'hr-database'), ('0oa4iam00000000001', 'iam')]
OKTA_USERS = [('00u1svcdeploy00001', 'svc-deploy', 'ACTIVE', 'Deployment', 'Service'),
              ('00u2support0000001', 'support-desk', 'ACTIVE', 'Support', 'Desk'),
              ('00u3svcbackup00001', 'svc-backup', 'ACTIVE', 'Backup', 'Service'),
              ('00u4contractor0001', 'former-contractor', 'SUSPENDED', 'Former', 'Contractor')]


def okta() -> dict:
    """Users, apps, each app's assigned users, and the System Log's sign-ons."""
    users = [{'id': uid, 'status': status, 'created': iso(OLD), 'activated': iso(OLD),
              'lastLogin': None, 'type': {'id': 'oty1default0000001'},
              'profile': {'login': login, 'email': '%s@example.invalid' % login,
                          'firstName': first, 'lastName': last}}
             for uid, login, status, first, last in OKTA_USERS]
    apps = [{'id': aid, 'name': 'bookmark', 'label': label, 'status': 'ACTIVE',
             'signOnMode': 'BOOKMARK', 'created': iso(OLD)} for aid, label in OKTA_APPS]
    login_of = {uid: login for uid, login, *_ in OKTA_USERS}
    # (app, user, scope). Suspended in Okta, still assigned: whether the
    # downstream app honours the suspension is the question worth asking.
    assigned = [(0, 0, 'GROUP'), (0, 2, 'USER'), (1, 1, 'GROUP'), (1, 3, 'USER'),
                (2, 1, 'GROUP'), (3, 0, 'USER'), (3, 1, 'USER')]
    exchanges = [ex('GET', '/api/v1/users', query={'limit': 200}, response=users),
                 ex('GET', '/api/v1/apps', query={'limit': 200}, response=apps)]
    for a, (aid, _label) in enumerate(OKTA_APPS):
        members = [{'id': OKTA_USERS[u][0], 'externalId': None, 'created': iso(OLD),
                    'lastUpdated': iso(OLD), 'scope': scope, 'status': 'ACTIVE',
                    'statusChanged': iso(OLD), 'syncState': 'DISABLED',
                    'credentials': {'userName': login_of[OKTA_USERS[u][0]]}, 'profile': {}}
                   for app, u, scope in assigned if app == a]
        exchanges.append(ex('GET', '/api/v1/apps/%s/users' % aid, query={'limit': 500},
                            response=members))
    # Sign-ons, as the System Log records them. svc-deploy was entitled to
    # the backups long ago and first signed on to them five hours ago; that
    # gap is the finding. support-desk has never signed on to the billing or
    # HR databases it is assigned.
    used = [(0, 0, NEW), (3, 0, OLD), (3, 1, OLD), (0, 2, OLD)]
    events = []
    for n, (a, u, when) in enumerate(used):
        uid, login = OKTA_USERS[u][0], OKTA_USERS[u][1]
        aid, label = OKTA_APPS[a]
        events.append({'uuid': 'a1b2c3d4-0000-4000-8000-%012d' % n, 'published': iso(when),
                       'eventType': 'user.authentication.sso', 'version': '0',
                       'displayMessage': 'User single sign on to app', 'severity': 'INFO',
                       'actor': {'id': uid, 'type': 'User', 'alternateId': '%s@example.invalid' % login,
                                 'displayName': login},
                       'client': {'ipAddress': '10.0.0.%d' % (10 + n)},
                       'outcome': {'result': 'SUCCESS'},
                       'target': [{'id': aid, 'type': 'AppInstance', 'alternateId': label,
                                   'displayName': label},
                                  {'id': uid, 'type': 'AppUser', 'alternateId': login,
                                   'displayName': login}]})
    exchanges.append(ex('GET', '/api/v1/logs', query={
        'filter': 'eventType eq "user.authentication.sso"',
        'since': (GENERATED - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'limit': 1000}, response=events))
    return recording('Okta', 'Okta Management API: Users, Applications, Application Users, System Log',
                     exchanges)


def entra() -> dict:
    """A token, then directory roles with their members expanded."""
    roles = {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#directoryRoles',
             'value': [
                 {'id': 'r1', 'deletedDateTime': None, 'displayName': 'Application Administrator',
                  'description': 'Can create and manage all aspects of app registrations and enterprise apps.',
                  'roleTemplateId': '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
                  'members': [{'@odata.type': '#microsoft.graph.servicePrincipal',
                               'id': 'sp1', 'displayName': 'ci-pipeline'}]},
                 {'id': 'r2', 'deletedDateTime': None, 'displayName': 'Security Reader',
                  'description': 'Can read security information and reports in Azure AD and Office 365.',
                  'roleTemplateId': '5d6b6bb7-de71-4623-b4af-96380a352509',
                  'members': [{'@odata.type': '#microsoft.graph.user', 'id': 'au1',
                               'displayName': 'Auditor',
                               'userPrincipalName': 'auditor@example.invalid'}]},
             ]}
    return recording('Microsoft Entra ID', 'Microsoft Graph v1.0, directoryRoles', [
        ex('POST', '/replay/oauth2/v2.0/token', response=AZURE_TOKEN),
        ex('GET', '/v1.0/directoryRoles', query={'$expand': 'members'}, response=roles),
    ])


def cloudtrail() -> dict:
    """One delivered CloudTrail log file. CloudTrail is read from files, not
    called, so this holds the file rather than HTTP exchanges."""
    records = [
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
    ]
    return {'vendor': 'AWS CloudTrail', 'documented_at': 'CloudTrail log file format',
            'recorded_at': iso(GENERATED),
            'files': [{'name': '000000000000_CloudTrail_ap-south-1_20261103T0400Z_replay.json.gz',
                       'content': {'Records': records}}]}


QUALYS_DETECTIONS = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/host_list_vm_detection_output.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>{generated}</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>1</ID>
        <IP>10.2.0.11</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS><![CDATA[storefront-web]]></DNS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>38657</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>4</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>{old}</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>{generated}</LAST_FOUND_DATETIME>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <ID>2</ID>
        <IP>10.2.0.24</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <DNS><![CDATA[order-service]]></DNS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>41102</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>{old}</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>{generated}</LAST_FOUND_DATETIME>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>
"""

QUALYS_KNOWLEDGE = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE KNOWLEDGE_BASE_VULN_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd">
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <DATETIME>{generated}</DATETIME>
    <VULN_LIST>
      <VULN>
        <QID>38657</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>4</SEVERITY_LEVEL>
        <TITLE><![CDATA[Outdated TLS library on storefront-web]]></TITLE>
        <CVE_LIST><CVE><ID><![CDATA[CVE-2025-9910]]></ID></CVE></CVE_LIST>
        <THREAT_INTELLIGENCE>
          <THREAT_INTEL id="2"><![CDATA[Exploit_Public]]></THREAT_INTEL>
        </THREAT_INTELLIGENCE>
      </VULN>
      <VULN>
        <QID>41102</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE><![CDATA[Order service deserialisation]]></TITLE>
        <CVE_LIST><CVE><ID><![CDATA[CVE-2026-0442]]></ID></CVE></CVE_LIST>
        <THREAT_INTELLIGENCE>
          <THREAT_INTEL id="2"><![CDATA[Exploit_Public]]></THREAT_INTEL>
          <THREAT_INTEL id="3"><![CDATA[Active_Attacks]]></THREAT_INTEL>
        </THREAT_INTELLIGENCE>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
"""


def qualys() -> dict:
    """Host detections, then the KnowledgeBase for the QIDs found. XML."""
    fill = {'generated': iso(GENERATED), 'old': iso(OLD)}
    return recording('Qualys VMDR', 'Host List Detection API and KnowledgeBase API, v2.0', [
        ex('GET', '/api/2.0/fo/asset/host/vm/detection/',
           query={'action': 'list', 'status': 'New,Active,Re-Opened'},
           text=QUALYS_DETECTIONS.format(**fill)),
        ex('GET', '/api/2.0/fo/knowledge_base/vuln/',
           query={'action': 'list', 'details': 'All', 'ids': '38657,41102'},
           text=QUALYS_KNOWLEDGE.format(**fill)),
    ])


TENABLE_EXPORT = '2f8c1d4a-6b3e-4c1a-9e7d-5a0b1c2d3e4f'


def tenable() -> dict:
    """Request an export, its status, then its one chunk."""
    findings = [
        {'asset': {'uuid': 'a3', 'hostname': 'file-store', 'fqdn': 'file-store.internal.invalid',
                   'ipv4': '10.2.0.31'},
         'plugin': {'id': 186234, 'name': 'Unauthenticated file upload', 'cve': ['CVE-2026-1188'],
                    'cvss3_base_score': 9.1, 'exploitability_ease': 'Exploits are available'},
         'severity': 'critical', 'state': 'OPEN', 'first_found': iso(OLD), 'last_found': iso(GENERATED)},
        {'asset': {'uuid': 'a1', 'hostname': 'storefront-web',
                   'fqdn': 'storefront-web.internal.invalid', 'ipv4': '10.2.0.11'},
         'plugin': {'id': 142991, 'name': 'Outdated TLS library', 'cve': ['CVE-2025-9910'],
                    'cvss3_base_score': 7.5, 'exploitability_ease': 'Exploits are available'},
         'severity': 'high', 'state': 'OPEN', 'first_found': iso(OLD), 'last_found': iso(GENERATED)},
    ]
    return recording('Tenable Vulnerability Management', 'Exports API: vulns', [
        ex('POST', '/vulns/export', body={'num_assets': 500}, match_body=True,
           response={'export_uuid': TENABLE_EXPORT}),
        ex('GET', '/vulns/export/%s/status' % TENABLE_EXPORT,
           response={'uuid': TENABLE_EXPORT, 'status': 'FINISHED', 'chunks_available': [1],
                     'chunks_failed': [], 'chunks_cancelled': [], 'total_chunks': 1}),
        ex('GET', '/vulns/export/%s/chunks/1' % TENABLE_EXPORT, response=findings),
    ])


SN_IDS = {'ci1': '6a1f0e2c1b8a4d10a0c0000000000001', 'ci2': '6a1f0e2c1b8a4d10a0c0000000000002',
          'ci3': '6a1f0e2c1b8a4d10a0c0000000000003', 'ci4': '6a1f0e2c1b8a4d10a0c0000000000004',
          'ci5': '6a1f0e2c1b8a4d10a0c0000000000005'}


def servicenow() -> dict:
    """CMDB items with display values, then relationships with both."""
    def snow_time(moment):
        return moment.strftime('%Y-%m-%d %H:%M:%S')
    items = [
        {'sys_id': SN_IDS['ci1'], 'name': 'billing-database', 'sys_class_name': 'Database Instance',
         'data_classification': 'PCI', 'owned_by': 'finance-ops', 'used_for': 'Production'},
        {'sys_id': SN_IDS['ci2'], 'name': 'hr-database', 'sys_class_name': 'Database Instance',
         'data_classification': 'PII', 'owned_by': 'people-ops', 'used_for': 'Production'},
        {'sys_id': SN_IDS['ci3'], 'name': 'order-service', 'sys_class_name': 'Application',
         'data_classification': 'Internal', 'owned_by': 'commerce', 'used_for': 'Production'},
        {'sys_id': SN_IDS['ci4'], 'name': 'storefront-web', 'sys_class_name': 'Application',
         'data_classification': 'Public', 'owned_by': 'commerce', 'used_for': 'Production'},
        {'sys_id': SN_IDS['ci5'], 'name': 'file-store', 'sys_class_name': 'Application',
         'data_classification': 'Internal', 'owned_by': 'platform', 'used_for': 'Production'},
    ]
    names = {SN_IDS[k]: v for k, v in (('ci1', 'billing-database'), ('ci3', 'order-service'),
                                       ('ci4', 'storefront-web'))}

    def ref(sys_id):
        return {'display_value': names[sys_id], 'value': sys_id,
                'link': 'https://replay.service-now.com/api/now/table/cmdb_ci/%s' % sys_id}
    depends = {'display_value': 'Depends on::Used by', 'value': '1a9cb166f1571100a92eb60da2bce5c5',
               'link': 'https://replay.service-now.com/api/now/table/cmdb_rel_type/1a9cb166f1571100a92eb60da2bce5c5'}
    relationships = [
        # The order service reads the billing database. This single CMDB row
        # is what makes a bug in the order tier a card-data problem.
        {'sys_id': {'display_value': 'rel1', 'value': 'b1c2000000000000000000000000rel1'},
         'parent': ref(SN_IDS['ci3']), 'child': ref(SN_IDS['ci1']), 'type': depends,
         'sys_created_on': {'display_value': snow_time(RECENT), 'value': snow_time(RECENT)}},
        {'sys_id': {'display_value': 'rel2', 'value': 'b1c2000000000000000000000000rel2'},
         'parent': ref(SN_IDS['ci4']), 'child': ref(SN_IDS['ci3']), 'type': depends,
         'sys_created_on': {'display_value': snow_time(OLD), 'value': snow_time(OLD)}},
    ]
    return recording('ServiceNow CMDB', 'Table API', [
        ex('GET', '/api/now/table/cmdb_ci', query={
            'sysparm_limit': 500, 'sysparm_display_value': 'true',
            'sysparm_exclude_reference_link': 'true',
            'sysparm_fields': 'sys_id,name,sys_class_name,used_for,owned_by,data_classification'},
           response={'result': items}),
        ex('GET', '/api/now/table/cmdb_rel_ci', query={
            'sysparm_limit': 1000, 'sysparm_display_value': 'all',
            'sysparm_fields': 'sys_id,parent,child,type,sys_created_on'},
           response={'result': relationships}),
    ])


BUILDERS = {
    'splunk': splunk, 'sentinel': sentinel, 'crowdstrike': crowdstrike,
    'okta': okta, 'entra': entra, 'cloudtrail': cloudtrail,
    'qualys': qualys, 'tenable': tenable, 'servicenow': servicenow,
}


#: Where the replay's own clock is recorded. A sidecar rather than a key
#: inside each fixture, so every fixture stays exactly in its vendor's
#: response shape and could be swapped for a real captured response.
RECORDED = 'RECORDED.json'


def write_all() -> list[Path]:
    HERE.mkdir(parents=True, exist_ok=True)
    written = []
    for key, builder in sorted(BUILDERS.items()):
        path = HERE / ('%s.json' % key)
        with path.open('w', encoding='utf-8') as handle:
            json.dump(builder(), handle, indent=2, sort_keys=False)
            handle.write('\n')
        written.append(path)
    # The moment the snapshot describes. Questions about "the last 24 hours"
    # are asked relative to this in replay mode, or a recording's newest
    # finding would expire a day after it was made.
    stamp = HERE / RECORDED
    with stamp.open('w', encoding='utf-8') as handle:
        json.dump({'recorded_at': GENERATED.isoformat().replace('+00:00', 'Z'),
                   'note': ('The time every fixture in this directory was '
                            'generated against. Replay mode answers as of '
                            'this moment; live mode uses the real clock.')},
                  handle, indent=2)
        handle.write('\n')
    written.append(stamp)
    return written


if __name__ == '__main__':
    for path in write_all():
        print('wrote %s (%d bytes)' % (path.name, path.stat().st_size))
