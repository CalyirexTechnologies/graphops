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

    def fetch_live(self) -> dict:
        host = self.credentials['SPLUNK_HOST'].rstrip('/')
        url = ('%s/services/saved/searches/%s/history?output_mode=json'
               % (host, self.SAVED_SEARCH.replace(' ', '%20')))
        return self.http_get_json(
            url, headers={'Authorization': 'Bearer %s'
                          % self.credentials['SPLUNK_TOKEN']})

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
    """Microsoft Sentinel incidents, through the Azure Log Analytics query API.

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
                     'securityinsights/incidents/list')

    def fetch_live(self) -> dict:
        workspace = self.credentials['SENTINEL_WORKSPACE_ID']
        url = ('https://management.azure.com%s/providers/'
               'Microsoft.SecurityInsights/incidents?api-version=2023-02-01'
               % workspace)
        # The bearer token is minted by the caller's Azure identity and
        # handed in; this connector never holds a client secret longer than
        # the request that uses it.
        return self.http_get_json(
            url, headers={'Authorization': 'Bearer %s'
                          % self.credentials.get('AZURE_ACCESS_TOKEN', '')})

    _SEVERITY_COST = {'High': 1.0, 'Medium': 2.0, 'Low': 3.0,
                      'Informational': 4.0}

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for incident in payload.get('value', []):
            properties = incident.get('properties', {})
            title = str(properties.get('title') or 'sentinel incident')
            when = str(properties.get('createdTimeUtc') or '')
            severity = str(properties.get('severity') or 'Medium')
            rule_node = _rule_id(title)
            delta.add_node(rule_node, NodeKind.RULE, title, Zone.INTERNAL)

            for entity in properties.get('relatedEntities', []):
                kind = str(entity.get('kind') or '').lower()
                value = str(entity.get('value') or '').strip()
                if not value:
                    continue
                if kind in ('ip', 'ipaddress'):
                    delta.add_node(_address_id(value), NodeKind.ADDRESS, value,
                                   Zone.UNTRUSTED)
                    delta.add_edge(_address_id(value), rule_node,
                                   EdgeKind.TRIPPED, when)
                elif kind in ('account', 'user'):
                    identity = 'id:%s' % value
                    delta.add_node(identity, NodeKind.IDENTITY, value,
                                   Zone.INTERNAL)
                    delta.add_edge(identity, rule_node, EdgeKind.TRIPPED, when)
                elif kind in ('host', 'azureresource'):
                    asset = 'asset:%s' % value
                    delta.add_node(asset, NodeKind.ASSET, value, Zone.INTERNAL)

            # An incident linking an address to an account is Sentinel saying
            # the address used that account. That is a YIELDS edge, and it is
            # the single most useful thing a SIEM gives this graph.
            addresses = [e.get('value') for e in properties.get('relatedEntities', [])
                         if str(e.get('kind', '')).lower() in ('ip', 'ipaddress')]
            accounts = [e.get('value') for e in properties.get('relatedEntities', [])
                        if str(e.get('kind', '')).lower() in ('account', 'user')]
            for address in addresses:
                for account in accounts:
                    delta.add_edge(_address_id(str(address)), 'id:%s' % account,
                                   EdgeKind.YIELDS, when,
                                   cost=self._SEVERITY_COST.get(severity, 2.0))
            delta.stats['incidents'] = delta.stats.get('incidents', 0) + 1
        return delta
