"""Endpoint detection: CrowdStrike Falcon.

An EDR knows two things the rest of the stack does not. Which host a
detection landed on, and which account was running when it did. The second is
what turns a detection from a dot on a dashboard into an edge: an attacker on
that host has the use of that account.
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, GraphDelta


class CrowdStrikeConnector(Connector):
    """Falcon detections, via the /detects API.

    Severity maps to attacker effort rather than to a colour. A high-severity
    detection means the step is known to work in this environment, so it is
    cheap; a low-severity one may be noise, so it is expensive. That ordering
    is the opposite of a priority queue and is intentional: the path search
    is modelling what an attacker would choose, not what an analyst should
    read first.
    """

    key = 'crowdstrike'
    vendor = 'CrowdStrike'
    product = 'Falcon'
    category = 'edr'
    required_credentials = ('FALCON_CLIENT_ID', 'FALCON_CLIENT_SECRET')
    api_reference = ('https://falcon.crowdstrike.com/documentation/page/'
                     'detections-apis')

    _SEVERITY_COST = {'Critical': 1.0, 'High': 1.5, 'Medium': 2.5, 'Low': 4.0}

    def fetch_live(self) -> dict:
        token = self.credentials.get('FALCON_ACCESS_TOKEN', '')
        return self.http_get_json(
            'https://api.crowdstrike.com/detects/queries/detects/v1?limit=200',
            headers={'Authorization': 'Bearer %s' % token})

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for detection in payload.get('resources', []):
            device = detection.get('device', {})
            hostname = str(device.get('hostname') or '').strip()
            behaviours = detection.get('behaviors', [])
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

            for behaviour in behaviours:
                tactic = str(behaviour.get('tactic') or '')
                technique_id = str(behaviour.get('technique_id') or '')
                severity = str(behaviour.get('severity_name') or 'Medium')
                when = str(behaviour.get('timestamp') or detection.get('created_timestamp') or '')
                rule_name = '%s (%s)' % (behaviour.get('display_name') or tactic,
                                         technique_id or 'no technique')
                rule_node = 'rule:%s' % rule_name
                delta.add_node(rule_node, NodeKind.RULE, rule_name, Zone.INTERNAL,
                               source='crowdstrike')

                if external:
                    delta.add_edge('addr:%s' % external, rule_node,
                                   EdgeKind.TRIPPED, when)

                account = str(behaviour.get('user_name') or '').strip()
                if account:
                    identity = 'id:%s' % account
                    delta.add_node(identity, NodeKind.IDENTITY, account,
                                   Zone.INTERNAL, source='crowdstrike')
                    # The host had this account's token in memory. Anyone who
                    # owns the host owns the account.
                    delta.add_edge(asset, identity, EdgeKind.YIELDS, when,
                                   cost=self._SEVERITY_COST.get(severity, 2.5),
                                   technique=technique_id, tactic=tactic)
                delta.stats['behaviours'] = delta.stats.get('behaviours', 0) + 1
            delta.stats['detections'] = delta.stats.get('detections', 0) + 1
        return delta
