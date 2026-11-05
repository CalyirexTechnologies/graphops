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

#: The subset that names a regulation rather than a sensitivity level.
#: Confidential and Restricted still make a crown jewel, and they are not
#: regimes: no regulator has a view on them, and a regime column that showed
#: them would invite someone to scope an audit by them.
_REGIMES = frozenset({'pci', 'phi', 'pii', 'sox'})


def _value(field) -> str:
    """The stored value of a Table API field, whether it came back as a
    reference object or as a plain string."""
    if isinstance(field, dict):
        return str(field.get('value') or '')
    return str(field or '')


def _snow_time(value: str) -> str:
    """ServiceNow stores 'YYYY-MM-DD HH:MM:SS' in UTC. Written as ISO 8601
    so it compares and parses like every other source's timestamps."""
    value = str(value or '').strip()
    if len(value) == 19 and value[10] == ' ':
        return value.replace(' ', 'T') + 'Z'
    return value


def _display(field) -> str:
    if isinstance(field, dict):
        return str(field.get('display_value') or field.get('value') or '')
    return str(field or '')


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

    #: ServiceNow has no out-of-the-box data classification field on a CI;
    #: customers add one. Its name is a setting, defaulting to the common one.
    defaults = {'SERVICENOW_CLASSIFICATION_FIELD': 'data_classification'}

    def collect(self) -> dict:
        """Configuration items, then the relationships between them.

        Reference fields come back from the Table API as `{link, value}`
        objects, not strings. Items are read with display values, so an
        owner reads as a name; relationships are read raw, so `parent` and
        `child` carry the sys_id that joins them to the items, with the
        relationship type's name asked for separately. The first version
        read every reference field as a plain string.
        """
        import base64
        instance = self.setting('SERVICENOW_INSTANCE').rstrip('/')
        token = base64.b64encode(('%s:%s' % (self.setting('SERVICENOW_USERNAME'),
                                             self.setting('SERVICENOW_PASSWORD'))).encode()).decode()
        headers = {'Authorization': 'Basic %s' % token, 'Accept': 'application/json'}
        field = self.setting('SERVICENOW_CLASSIFICATION_FIELD')
        items = self.request('GET', '%s/api/now/table/cmdb_ci?sysparm_limit=500'
                             '&sysparm_display_value=true&sysparm_exclude_reference_link=true'
                             '&sysparm_fields=sys_id,name,sys_class_name,used_for,owned_by,%s'
                             % (instance, field), headers=headers).get('result', [])
        relationships = self.request('GET', '%s/api/now/table/cmdb_rel_ci?sysparm_limit=1000'
                                     '&sysparm_display_value=all'
                                     '&sysparm_fields=sys_id,parent,child,type,sys_created_on'
                                     % instance, headers=headers).get('result', [])
        return {'items': items, 'relationships': relationships, 'classification_field': field}

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        names: dict[str, str] = {}

        field = payload.get('classification_field', 'data_classification')
        for item in payload.get('items', []):
            sys_id = str(item.get('sys_id') or '')
            name = str(item.get('name') or '').strip()
            if not sys_id or not name:
                continue
            names[sys_id] = name
            stated = str(item.get(field) or '').strip()
            classification = stated.lower()
            crown = classification in _REGULATED
            delta.add_node('asset:%s' % name, NodeKind.ASSET, name,
                           Zone.CROWN if crown else Zone.INTERNAL,
                           label=('%s (%s)' % (name, classification.upper())
                                  if crown else name),
                           crown=crown, source='servicenow',
                           crown_source='servicenow.data_classification'
                                        if crown else None,
                           # Kept as data, not only as a label suffix, so a
                           # screen or a compliance control can filter by it.
                           classification=stated or None,
                           regimes=[classification.upper()]
                                   if classification in _REGIMES else [],
                           owner=str(item.get('owned_by') or ''),
                           environment=str(item.get('used_for') or ''))
            delta.stats['configuration_items'] = \
                delta.stats.get('configuration_items', 0) + 1

        for relation in payload.get('relationships', []):
            parent = names.get(_value(relation.get('parent')))
            child = names.get(_value(relation.get('child')))
            if not parent or not child:
                continue
            # "Depends on" in the CMDB means the parent reads the child, so
            # an attacker on the parent reaches the child.
            delta.add_edge('asset:%s' % parent, 'asset:%s' % child,
                           EdgeKind.SERVES, _snow_time(_value(relation.get('sys_created_on'))),
                           relation=_display(relation.get('type')))
            delta.stats['relationships'] = \
                delta.stats.get('relationships', 0) + 1
        return delta
