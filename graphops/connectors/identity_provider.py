"""Identity provider connectors: Okta and Microsoft Entra ID.

These are the connectors that make the zero-trust question answerable. A SIEM
says what happened; an identity provider says what is *allowed*. Holding both
in one graph is what lets `over_privilege()` subtract one from the other and
name the access nobody has ever used.

So every assignment read here becomes an `ENTITLED` edge, and it is written
whether or not anything has ever exercised it. An entitlement with no
matching observed use is not missing data, it is the finding.
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, GraphDelta

#: Applications whose names mark them as holding regulated data. Matching is
#: on the customer's own naming, so it is a hint, not a classification: the
#: API lets an operator override `crown` per node.
_CROWN_HINTS = ('billing', 'card', 'payment', 'payroll', 'hr-', 'patient',
                'finance', 'backup')


def _looks_like_crown(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _CROWN_HINTS)


class OktaConnector(Connector):
    """Okta users, groups and application assignments.

    Reads three endpoints and joins them locally rather than asking Okta for
    an expanded view, because the expanded forms differ between Okta's
    classic and Identity Engine tenants and the three primitive calls do not.
    """

    key = 'okta'
    vendor = 'Okta'
    product = 'Workforce Identity'
    category = 'idp'
    required_credentials = ('OKTA_DOMAIN', 'OKTA_API_TOKEN')
    api_reference = 'https://developer.okta.com/docs/reference/api/users/'

    def fetch_live(self) -> dict:
        domain = self.credentials['OKTA_DOMAIN'].rstrip('/')
        headers = {'Authorization': 'SSWS %s' % self.credentials['OKTA_API_TOKEN'],
                   'Accept': 'application/json'}
        return {
            'users': self.http_get_json('%s/api/v1/users?limit=200' % domain,
                                        headers=headers),
            'apps': self.http_get_json('%s/api/v1/apps?limit=200' % domain,
                                       headers=headers),
        }

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        users = payload.get('users', [])
        apps = payload.get('apps', [])

        app_names: dict[str, str] = {}
        for app in apps:
            app_id = str(app.get('id') or '')
            label = str(app.get('label') or app.get('name') or app_id)
            if not app_id:
                continue
            app_names[app_id] = label
            node_id = 'svc:%s' % label
            crown = _looks_like_crown(label)
            delta.add_node(node_id, NodeKind.SERVICE, label,
                           Zone.CROWN if crown else Zone.INTERNAL,
                           label=label, crown=crown, source='okta')

        for user in users:
            profile = user.get('profile', {})
            login = str(profile.get('login') or user.get('id') or '').strip()
            if not login:
                continue
            status = str(user.get('status') or '').upper()
            identity = 'id:%s' % login
            delta.add_node(identity, NodeKind.IDENTITY, login, Zone.INTERNAL,
                           label=login, source='okta',
                           suspended=status in ('SUSPENDED', 'DEPROVISIONED'))

            for assignment in user.get('appAssignments', []):
                app_id = str(assignment.get('appId') or '')
                label = app_names.get(app_id)
                if not label:
                    continue
                scope = str(assignment.get('scope') or 'USER').upper()
                last_sign_on = assignment.get('lastSignOn') or None
                # The entitlement, recorded whether or not it has been used.
                # `via` and `last_used` are read straight off Okta's own
                # assignment record. A grant arriving through a group is
                # revoked in a different place from a direct one, and a
                # remediation that names the wrong place does not happen.
                delta.add_edge(identity, 'svc:%s' % label, EdgeKind.ENTITLED,
                               str(assignment.get('created') or ''),
                               scope=scope,
                               via='group' if scope == 'GROUP' else 'direct',
                               permission='Okta app assignment',
                               last_used=str(last_sign_on) if last_sign_on else None)
                delta.stats['entitlements'] = delta.stats.get('entitlements', 0) + 1

                if last_sign_on:
                    # Okta reporting a sign-on is the observed use that makes
                    # the entitlement non-dormant. Named by Okta's own System
                    # Log event type, so it reads the same as Okta's console.
                    delta.add_edge(identity, 'svc:%s' % label, EdgeKind.CALLED,
                                   str(last_sign_on),
                                   last_seen=str(last_sign_on),
                                   actions=['user.authentication.sso'])
                    delta.stats['exercised'] = delta.stats.get('exercised', 0) + 1

            delta.stats['users'] = delta.stats.get('users', 0) + 1
        return delta


class EntraIdConnector(Connector):
    """Microsoft Entra ID directory roles and service principals.

    Directory role membership is the interesting part: a service principal
    holding a privileged directory role is an entitlement that no sign-in log
    will show being used until the day it is.
    """

    key = 'entra'
    vendor = 'Microsoft'
    product = 'Entra ID'
    category = 'idp'
    required_credentials = ('AZURE_TENANT_ID', 'AZURE_CLIENT_ID',
                            'AZURE_CLIENT_SECRET')
    api_reference = ('https://learn.microsoft.com/en-us/graph/api/'
                     'directoryrole-list-members')

    #: Roles that can reach anything in the tenant. Cost 1.0 because an
    #: attacker holding one does not need a second step.
    _HIGH_PRIVILEGE = frozenset({
        'Global Administrator', 'Privileged Role Administrator',
        'Application Administrator', 'Cloud Application Administrator',
    })

    def fetch_live(self) -> dict:
        headers = {'Authorization': 'Bearer %s'
                   % self.credentials.get('AZURE_ACCESS_TOKEN', '')}
        return self.http_get_json(
            'https://graph.microsoft.com/v1.0/directoryRoles?$expand=members',
            headers=headers)

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for role in payload.get('value', []):
            role_name = str(role.get('displayName') or '').strip()
            if not role_name:
                continue
            privileged = role_name in self._HIGH_PRIVILEGE
            role_node = 'svc:entra/%s' % role_name
            delta.add_node(role_node, NodeKind.SERVICE, role_name,
                           Zone.CROWN if privileged else Zone.INTERNAL,
                           label='Entra role: %s' % role_name, crown=privileged,
                           source='entra')

            for member in role.get('members', []):
                name = str(member.get('userPrincipalName')
                           or member.get('displayName') or '').strip()
                if not name:
                    continue
                identity = 'id:%s' % name
                is_service = str(member.get('@odata.type', '')).endswith('servicePrincipal')
                delta.add_node(identity, NodeKind.IDENTITY, name, Zone.INTERNAL,
                               label=name, source='entra',
                               principal_type='service' if is_service else 'user')
                # The role name is the permission. Entra does not report
                # directory role use per member here, so `last_used` is left
                # out rather than set to None: absent means "this source does
                # not say", and None would claim "never used".
                delta.add_edge(identity, role_node, EdgeKind.ENTITLED,
                               str(member.get('createdDateTime') or ''),
                               cost=1.0 if privileged else None,
                               permission=role_name, via='directory role')
                delta.stats['role_members'] = delta.stats.get('role_members', 0) + 1
        return delta
