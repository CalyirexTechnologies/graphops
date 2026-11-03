"""IT service management: ServiceNow CMDB.

The CMDB is where a graph finds out what a system is *for*. A scanner knows
`db-prod-07` has an open port; the CMDB knows it is the billing database, who
owns it, and which business service depends on it.

That is the only reliable source of the `crown` flag. Everything else in this
platform infers it from a name, which works until a customer calls their card
vault `aurora-3`. When ServiceNow is connected, its classification wins, and
`crown_source` records which answer was used so a reviewer can see the
difference.
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, GraphDelta

#: ServiceNow's own data-classification values that mean regulated data.
_REGULATED = frozenset({'pci', 'phi', 'pii', 'sox', 'confidential',
                        'restricted'})


class ServiceNowConnector(Connector):
    """ServiceNow CMDB configuration items and their relationships."""

    key = 'servicenow'
    vendor = 'ServiceNow'
    product = 'CMDB'
    category = 'itsm'
    required_credentials = ('SERVICENOW_INSTANCE', 'SERVICENOW_USERNAME',
                            'SERVICENOW_PASSWORD')
    api_reference = ('https://developer.servicenow.com/dev.do#!/reference/'
                     'api/latest/rest/c_TableAPI')

    def fetch_live(self) -> dict:
        import base64
        instance = self.credentials['SERVICENOW_INSTANCE'].rstrip('/')
        token = base64.b64encode(
            ('%s:%s' % (self.credentials['SERVICENOW_USERNAME'],
                        self.credentials['SERVICENOW_PASSWORD'])).encode()).decode()
        headers = {'Authorization': 'Basic %s' % token,
                   'Accept': 'application/json'}
        return {
            'items': self.http_get_json(
                '%s/api/now/table/cmdb_ci?sysparm_limit=500' % instance,
                headers=headers).get('result', []),
            'relationships': self.http_get_json(
                '%s/api/now/table/cmdb_rel_ci?sysparm_limit=1000' % instance,
                headers=headers).get('result', []),
        }

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        names: dict[str, str] = {}

        for item in payload.get('items', []):
            sys_id = str(item.get('sys_id') or '')
            name = str(item.get('name') or '').strip()
            if not sys_id or not name:
                continue
            names[sys_id] = name
            classification = str(item.get('data_classification') or '').lower()
            crown = classification in _REGULATED
            delta.add_node('asset:%s' % name, NodeKind.ASSET, name,
                           Zone.CROWN if crown else Zone.INTERNAL,
                           label=('%s (%s)' % (name, classification.upper())
                                  if crown else name),
                           crown=crown, source='servicenow',
                           crown_source='servicenow.data_classification'
                                        if crown else None,
                           owner=str(item.get('owned_by') or ''),
                           environment=str(item.get('used_for') or ''))
            delta.stats['configuration_items'] = \
                delta.stats.get('configuration_items', 0) + 1

        for relation in payload.get('relationships', []):
            parent = names.get(str(relation.get('parent') or ''))
            child = names.get(str(relation.get('child') or ''))
            if not parent or not child:
                continue
            # "Depends on" in the CMDB means the parent reads the child, so
            # an attacker on the parent reaches the child.
            delta.add_edge('asset:%s' % parent, 'asset:%s' % child,
                           EdgeKind.SERVES,
                           str(relation.get('sys_created_on') or ''),
                           relation=str(relation.get('type') or ''))
            delta.stats['relationships'] = \
                delta.stats.get('relationships', 0) + 1
        return delta
