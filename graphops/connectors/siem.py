"""SIEM connectors: Splunk Enterprise Security and Microsoft Sentinel.

Both answer the same question for the graph, which addresses touched which
surfaces and which rules fired, and both express it differently enough to be
worth writing separately rather than behind one "SIEM" abstraction.

The modelling decision that matters is in `_request_edge`. A SIEM row reads
"this address hit this endpoint". The edge is stored in that direction
because that is also the direction an attacker moves. A rule firing is stored
as the address tripping the rule, so an address with no TRIPPED edge is
visibly unalerted rather than merely absent, which is what makes
`novel_activity` able to say "no rule fired on this".
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, GraphDelta


def _address_id(value: str) -> str:
    return 'addr:%s' % value


def _endpoint_id(path: str) -> str:
    return 'ep:%s' % path


def _rule_id(name: str) -> str:
    return 'rule:%s' % name


class SplunkConnector(Connector):
    """Splunk Enterprise Security, via a saved search's JSON results.

    Reads the output of a saved search rather than issuing ad hoc SPL. A
    saved search is reviewable by the customer's own Splunk admin, which
    matters more than flexibility when the integration is reading their
    security data.
    """

    key = 'splunk'
    vendor = 'Splunk'
    product = 'Enterprise Security'
    category = 'siem'
    required_credentials = ('SPLUNK_HOST', 'SPLUNK_TOKEN')
    api_reference = 'https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch'

    SAVED_SEARCH = 'GraphOps - Perimeter Access Summary'

    def collect(self) -> dict:
        """The latest run of the saved search, then that run's results.

        Two calls, as Splunk's REST API is shaped. A saved search's
        `history` lists the jobs it has dispatched; the rows are on the job,
        at `search/v2/jobs/{sid}/results`. The first version of this read the
        history response as though it held the rows.
        """
        import urllib.parse
        host = self.setting('SPLUNK_HOST').rstrip('/')
        headers = self.bearer(self.setting('SPLUNK_TOKEN'))
        history = self.request('GET', '%s/services/saved/searches/%s/history?output_mode=json'
                               % (host, urllib.parse.quote(self.SAVED_SEARCH, safe='')),
                               headers=headers)
        jobs = history.get('entry') or []
        if not jobs:
            return {'results': []}
        latest = max(jobs, key=lambda job: str(job.get('updated') or job.get('published') or ''))
        return self.request('GET', '%s/services/search/v2/jobs/%s/results?output_mode=json&count=0'
                            % (host, urllib.parse.quote(str(latest['name']), safe='')),
                            headers=headers)

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        seen_addresses: set[str] = set()
        seen_endpoints: set[str] = set()

        for row in payload.get('results', []):
            source = str(row.get('src_ip') or '').strip()
            target = str(row.get('uri_path') or '').strip()
            when = str(row.get('_time') or '')
            if not source or not target:
                # A SIEM row missing either end cannot become an edge. Count
                # it rather than guessing a value.
                delta.stats['skipped_rows'] = delta.stats.get('skipped_rows', 0) + 1
                continue

            if source not in seen_addresses:
                delta.add_node(_address_id(source), NodeKind.ADDRESS, source,
                               Zone.UNTRUSTED)
                seen_addresses.add(source)
            if target not in seen_endpoints:
                delta.add_node(_endpoint_id(target), NodeKind.ENDPOINT, target,
                               Zone.PERIMETER)
                seen_endpoints.add(target)

            delta.add_edge(_address_id(source), _endpoint_id(target),
                           EdgeKind.REQUESTED, when,
                           observations=int(row.get('count', 1) or 1))

            rule = str(row.get('notable_rule') or '').strip()
            if rule:
                delta.add_node(_rule_id(rule), NodeKind.RULE, rule, Zone.INTERNAL)
                delta.add_edge(_address_id(source), _rule_id(rule),
                               EdgeKind.TRIPPED, when)

        delta.stats['addresses'] = len(seen_addresses)
        delta.stats['endpoints'] = len(seen_endpoints)
        return delta


class SentinelConnector(Connector):
    """Microsoft Sentinel incidents and their entities, through the SecurityInsights REST API.

    Sentinel groups alerts into incidents, so one record here can carry
    several entities. The entity list is what becomes nodes; the incident
    itself becomes a rule node, because from the graph's point of view an
    incident is "something fired on these entities".
    """

    key = 'sentinel'
    vendor = 'Microsoft'
    product = 'Sentinel'
    category = 'siem'
    required_credentials = ('AZURE_TENANT_ID', 'AZURE_CLIENT_ID',
                            'AZURE_CLIENT_SECRET', 'SENTINEL_WORKSPACE_ID')
    api_reference = ('https://learn.microsoft.com/en-us/rest/api/'
                     'securityinsights/incidents/list-entities')
    defaults = {'AZURE_LOGIN_URL': 'https://login.microsoftonline.com',
                'AZURE_MANAGEMENT_URL': 'https://management.azure.com'}
    #: The workspace's full Azure resource ID. It is part of every request
    #: path, so the recording was made against this one.
    replay_settings = {'SENTINEL_WORKSPACE_ID': (
        '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/soc'
        '/providers/Microsoft.OperationalInsights/workspaces/sentinel-ws')}
    API_VERSION = '2023-02-01'

    def collect(self) -> dict:
        """Incidents, then each incident's entities.

        Entities are not part of an incident. Azure returns them from a
        separate POST per incident, which is how this calls them now; the
        first version read a `relatedEntities` field off the incident that
        the API does not return.
        """
        token = self.azure_token('https://management.azure.com/.default')
        headers = self.bearer(token)
        base = (self.setting('AZURE_MANAGEMENT_URL').rstrip('/')
                + self.setting('SENTINEL_WORKSPACE_ID')
                + '/providers/Microsoft.SecurityInsights/incidents')
        incidents = self.follow('%s?api-version=%s' % (base, self.API_VERSION),
                                headers=headers, items_key='value', next_key='nextLink')
        entities = {}
        for incident in incidents:
            name = str(incident.get('name') or '')
            if name:
                entities[name] = self.request(
                    'POST', '%s/%s/entities?api-version=%s' % (base, name, self.API_VERSION),
                    headers=headers, json_body={}).get('entities', [])
        return {'incidents': incidents, 'entities': entities}

    _SEVERITY_COST = {'High': 1.0, 'Medium': 2.0, 'Low': 3.0,
                      'Informational': 4.0}

    @staticmethod
    def _entity_value(entity: dict) -> tuple[str, str]:
        """(kind, value) from one documented Sentinel entity."""
        kind = str(entity.get('kind') or '').lower()
        props = entity.get('properties') or {}
        if kind == 'ip':
            return 'ip', str(props.get('address') or '').strip()
        if kind == 'account':
            return 'account', str(props.get('accountName') or props.get('friendlyName') or '').strip()
        if kind == 'host':
            return 'host', str(props.get('hostName') or props.get('friendlyName') or '').strip()
        return kind, str(props.get('friendlyName') or '').strip()

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for incident in payload.get('incidents', []):
            properties = incident.get('properties', {})
            title = str(properties.get('title') or 'sentinel incident')
            when = str(properties.get('createdTimeUtc') or '')
            severity = str(properties.get('severity') or 'Medium')
            rule_node = _rule_id(title)
            delta.add_node(rule_node, NodeKind.RULE, title, Zone.INTERNAL)
            addresses, accounts = [], []
            for entity in payload.get('entities', {}).get(incident.get('name'), []):
                kind, value = self._entity_value(entity)
                if not value:
                    continue
                if kind == 'ip':
                    addresses.append(value)
                    delta.add_node(_address_id(value), NodeKind.ADDRESS, value,
                                   Zone.UNTRUSTED)
                    delta.add_edge(_address_id(value), rule_node,
                                   EdgeKind.TRIPPED, when)
                elif kind == 'account':
                    accounts.append(value)
                    identity = 'id:%s' % value
                    delta.add_node(identity, NodeKind.IDENTITY, value,
                                   Zone.INTERNAL)
                    delta.add_edge(identity, rule_node, EdgeKind.TRIPPED, when)
                elif kind == 'host':
                    delta.add_node('asset:%s' % value, NodeKind.ASSET, value, Zone.INTERNAL)
            # An incident linking an address to an account is Sentinel saying
            # the address used that account. That is a YIELDS edge, and it is
            # the single most useful thing a SIEM gives this graph.
            for address in addresses:
                for account in accounts:
                    delta.add_edge(_address_id(address), 'id:%s' % account,
                                   EdgeKind.YIELDS, when,
                                   cost=self._SEVERITY_COST.get(severity, 2.0))
            delta.stats['incidents'] = delta.stats.get('incidents', 0) + 1
        return delta
