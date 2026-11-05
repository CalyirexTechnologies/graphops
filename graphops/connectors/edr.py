"""Endpoint detection: CrowdStrike Falcon.

An EDR knows two things the rest of the stack does not. Which host a
detection landed on, and which account was running when it did. The second is
what turns a detection from a dot on a dashboard into an edge: an attacker on
that host has the use of that account.
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, ConnectorError, GraphDelta


class CrowdStrikeConnector(Connector):
    """Falcon alerts, via the Alerts v2 API.

    THE DETECTS API IS GONE. CrowdStrike decommissioned /detects/* on 30
    September 2025 and this connector called it until 5 November 2026, so
    its live path would have answered 404 on every real tenant. Alerts
    differ in shape as well as in path: a detection grouped several
    behaviours, and an alert is one behaviour, with tactic, technique and
    user on the alert itself and the host under `device`.

    Severity maps to attacker effort rather than to a colour. A
    high-severity alert means the step is known to work in this environment,
    so it is cheap; a low-severity one may be noise, so it is expensive. That
    ordering is the opposite of a priority queue and is intentional: the
    path search models what an attacker would choose, not what an analyst
    should read first.
    """

    key = 'crowdstrike'
    vendor = 'CrowdStrike'
    product = 'Falcon'
    category = 'edr'
    required_credentials = ('FALCON_CLIENT_ID', 'FALCON_CLIENT_SECRET')
    api_reference = 'https://developer.crowdstrike.com/api-reference/collections/alerts/'
    #: US-1 by default. US-2, EU-1 and GovCloud customers set their own.
    defaults = {'FALCON_BASE_URL': 'https://api.crowdstrike.com'}
    PAGE = 500

    _SEVERITY_COST = {'Critical': 1.0, 'High': 1.5, 'Medium': 2.5, 'Low': 4.0}

    def collect(self) -> dict:
        """Token, then alert IDs, then the alerts. Three calls, as documented.

        The client ID and secret are exchanged for a bearer token at
        /oauth2/token. The first version named those credentials and then
        read a FALCON_ACCESS_TOKEN that nothing supplied.
        """
        base = self.setting('FALCON_BASE_URL').rstrip('/')
        token = self.request('POST', '%s/oauth2/token' % base,
                             form={'client_id': self.setting('FALCON_CLIENT_ID'),
                                   'client_secret': self.setting('FALCON_CLIENT_SECRET')}
                             ).get('access_token')
        if not token:
            raise ConnectorError('crowdstrike: /oauth2/token returned no token')
        headers = self.bearer(token)
        ids = self.request('GET', '%s/alerts/queries/alerts/v2?limit=%d&sort=created_timestamp%%7Cdesc'
                           % (base, self.PAGE), headers=headers).get('resources') or []
        if not ids:
            return {'resources': []}
        return self.request('POST', '%s/alerts/entities/alerts/v2' % base,
                            headers=headers, json_body={'composite_ids': ids})

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for alert in payload.get('resources', []):
            device = alert.get('device') or {}
            hostname = str(device.get('hostname') or '').strip()
            if not hostname:
                delta.stats['skipped'] = delta.stats.get('skipped', 0) + 1
                continue
            asset = 'asset:%s' % hostname
            delta.add_node(asset, NodeKind.ASSET, hostname, Zone.INTERNAL,
                           label=hostname, source='crowdstrike',
                           platform=str(device.get('platform_name') or ''))
            external = str(device.get('external_ip') or '').strip()
            if external:
                delta.add_node('addr:%s' % external, NodeKind.ADDRESS,
                               external, Zone.UNTRUSTED)
            tactic = str(alert.get('tactic') or '')
            technique_id = str(alert.get('technique_id') or '')
            severity = str(alert.get('severity_name') or 'Medium')
            when = str(alert.get('created_timestamp') or alert.get('timestamp') or '')
            rule_name = '%s (%s)' % (alert.get('display_name') or alert.get('name') or tactic,
                                     technique_id or 'no technique')
            rule_node = 'rule:%s' % rule_name
            delta.add_node(rule_node, NodeKind.RULE, rule_name, Zone.INTERNAL,
                           source='crowdstrike')
            if external:
                delta.add_edge('addr:%s' % external, rule_node, EdgeKind.TRIPPED, when)
            account = str(alert.get('user_name') or '').strip()
            if account:
                identity = 'id:%s' % account
                delta.add_node(identity, NodeKind.IDENTITY, account,
                               Zone.INTERNAL, source='crowdstrike')
                # The host had this account's token in memory. Anyone who
                # owns the host owns the account.
                delta.add_edge(asset, identity, EdgeKind.YIELDS, when,
                               cost=self._SEVERITY_COST.get(severity, 2.5),
                               technique=technique_id, tactic=tactic)
            delta.stats['alerts'] = delta.stats.get('alerts', 0) + 1
        return delta
