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
    """Okta users, apps, app assignments and single sign-on events.

    Four documented listings, joined here. Users and apps name things.
    `/api/v1/apps/{id}/users` says who is assigned to each app and whether
    the assignment came through a group. The System Log says who actually
    signed on to it, as `user.authentication.sso` events whose targets
    include the app instance.

    THE FIRST VERSION READ A FIELD OKTA DOES NOT HAVE. It expected each user
    to carry `appAssignments[]`, each with a `lastSignOn`. Okta's User and
    AppUser objects have neither (checked against the models Okta generates
    its SDK from), so the live path would have found no assignments at all
    and every entitlement in the graph would have vanished. Use now comes
    from where Okta records it.

    The System Log is retained for 90 days, so the request covers exactly
    that and each grant records the window as `usage_since`. A grant with no
    sign-on in the window was "not used in 90 days", and is "never used"
    only when it was itself granted inside the window. `over_privilege`
    makes that distinction rather than this connector guessing it.
    """

    key = 'okta'
    vendor = 'Okta'
    product = 'Workforce Identity'
    category = 'idp'
    required_credentials = ('OKTA_DOMAIN', 'OKTA_API_TOKEN')
    api_reference = 'https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationUsers/'
    LOG_DAYS = 90

    def collect(self) -> dict:
        import urllib.parse
        from datetime import timedelta
        domain = self.setting('OKTA_DOMAIN').rstrip('/')
        headers = {'Authorization': 'SSWS %s' % self.setting('OKTA_API_TOKEN'),
                   'Accept': 'application/json'}
        users = self.follow('%s/api/v1/users?limit=200' % domain, headers=headers)
        apps = self.follow('%s/api/v1/apps?limit=200' % domain, headers=headers)
        assignments = {}
        for app in apps:
            app_id = str(app.get('id') or '')
            if app_id:
                assignments[app_id] = self.follow(
                    '%s/api/v1/apps/%s/users?limit=500' % (domain, urllib.parse.quote(app_id, safe='')),
                    headers=headers)
        since = (self.now() - timedelta(days=self.LOG_DAYS)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        events = self.follow('%s/api/v1/logs?%s' % (domain, urllib.parse.urlencode(
            {'filter': 'eventType eq "user.authentication.sso"', 'since': since, 'limit': 1000})),
            headers=headers)
        return {'users': users, 'apps': apps, 'assignments': assignments,
                'sso_events': events, 'log_since': since}

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        log_since = payload.get('log_since')

        labels: dict[str, str] = {}
        for app in payload.get('apps', []):
            app_id = str(app.get('id') or '')
            label = str(app.get('label') or app.get('name') or app_id)
            if not app_id:
                continue
            labels[app_id] = label
            crown = _looks_like_crown(label)
            delta.add_node('svc:%s' % label, NodeKind.SERVICE, label,
                           Zone.CROWN if crown else Zone.INTERNAL,
                           label=label, crown=crown, source='okta')

        logins: dict[str, str] = {}
        for user in payload.get('users', []):
            login = str((user.get('profile') or {}).get('login') or user.get('id') or '').strip()
            if not login:
                continue
            logins[str(user.get('id'))] = login
            status = str(user.get('status') or '').upper()
            delta.add_node('id:%s' % login, NodeKind.IDENTITY, login, Zone.INTERNAL,
                           label=login, source='okta',
                           suspended=status in ('SUSPENDED', 'DEPROVISIONED'))
            delta.stats['users'] = delta.stats.get('users', 0) + 1

        # Latest sign-on per (user, app), from the System Log.
        last_use: dict[tuple, str] = {}
        for event in payload.get('sso_events', []):
            actor = str((event.get('actor') or {}).get('id') or '')
            when = str(event.get('published') or '')
            for target in event.get('target') or []:
                if target.get('type') == 'AppInstance' and actor and when:
                    pair = (actor, str(target.get('id') or ''))
                    if when > last_use.get(pair, ''):
                        last_use[pair] = when

        for app_id, members in payload.get('assignments', {}).items():
            label = labels.get(app_id)
            if not label:
                continue
            for member in members:
                user_id = str(member.get('id') or '')
                login = logins.get(user_id) or str((member.get('credentials') or {}).get('userName') or '')
                if not login:
                    continue
                identity = 'id:%s' % login
                scope = str(member.get('scope') or 'USER').upper()
                used = last_use.get((user_id, app_id))
                # The entitlement, recorded whether or not it has been used.
                # A grant through a group is removed from the group, and a
                # remediation that names the wrong place does not happen.
                delta.add_edge(identity, 'svc:%s' % label, EdgeKind.ENTITLED,
                               str(member.get('created') or ''), scope=scope,
                               via='group' if scope == 'GROUP' else 'direct',
                               permission='Okta app assignment',
                               last_used=used, usage_since=log_since)
                delta.stats['entitlements'] = delta.stats.get('entitlements', 0) + 1
                if used:
                    delta.add_edge(identity, 'svc:%s' % label, EdgeKind.CALLED, used,
                                   last_seen=used, actions=['user.authentication.sso'])
                    delta.stats['exercised'] = delta.stats.get('exercised', 0) + 1
        return delta


class EntraIdConnector(Connector):
    """Microsoft Entra ID directory roles and their members, via Microsoft Graph.

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
    defaults = {'AZURE_LOGIN_URL': 'https://login.microsoftonline.com',
                'GRAPH_URL': 'https://graph.microsoft.com'}

    #: Roles that can reach anything in the tenant. Cost 1.0 because an
    #: attacker holding one does not need a second step.
    _HIGH_PRIVILEGE = frozenset({
        'Global Administrator', 'Privileged Role Administrator',
        'Application Administrator', 'Cloud Application Administrator',
    })

    def collect(self) -> dict:
        token = self.azure_token('https://graph.microsoft.com/.default')
        roles = self.follow('%s/v1.0/directoryRoles?$expand=members'
                            % self.setting('GRAPH_URL').rstrip('/'),
                            headers=self.bearer(token), items_key='value',
                            next_key='@odata.nextLink')
        return {'value': roles}

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
                # The role name is the permission. Graph's role listing does
                # not report whether a member ever uses the role, and the
                # edge says so explicitly; nor does an expanded member carry
                # when it was added, so first_seen is left for ingest to
                # stamp with the time it was observed.
                delta.add_edge(identity, role_node, EdgeKind.ENTITLED, '',
                               cost=1.0 if privileged else None,
                               permission=role_name, via='directory role',
                               usage_reported=False)
                delta.stats['role_members'] = delta.stats.get('role_members', 0) + 1
        return delta
