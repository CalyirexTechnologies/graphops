"""Who is acting, resolved once per request.

A `Principal` is produced by the authentication layer and is the only thing
the rest of the platform consults. It carries the organization, because in a
multi-tenant system "which tenant" is part of identity rather than a
parameter the caller supplies: a caller that could name its own tenant could
name someone else's.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .permissions import Permission, Role, permissions_for


class AccessDenied(Exception):
    """Raised when a principal lacks a permission.

    Carries the permission so the API layer can log precisely what was
    refused, while the response body stays generic.
    """

    def __init__(self, permission: Permission | str, detail: str = ''):
        self.permission = permission
        self.detail = detail
        super().__init__('missing permission %s%s'
                         % (getattr(permission, 'value', permission),
                            (': ' + detail) if detail else ''))


@dataclass(frozen=True)
class Principal:
    subject: str
    organization: str
    roles: tuple[str, ...] = ()
    #: 'user' or 'service'. A service principal is an API key, and some
    #: surfaces refuse one regardless of its roles.
    kind: str = 'user'
    session_id: str | None = None
    token_id: str | None = None
    #: Set when an administrator is acting as this user. Both identities are
    #: written to every audit entry; the acting admin is never dropped.
    impersonated_by: str | None = None
    client_ip: str | None = None
    attributes: dict = field(default_factory=dict)

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.roles)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission, detail: str = '') -> None:
        if not self.can(permission):
            raise AccessDenied(permission, detail)

    def has_role(self, role: Role | str) -> bool:
        wanted = getattr(role, 'value', str(role)).lower()
        return any(r.lower() == wanted for r in self.roles)

    @property
    def is_service(self) -> bool:
        return self.kind == 'service'

    def describe(self) -> str:
        """A short string for logs. Never includes the token."""
        who = '%s/%s' % (self.organization, self.subject)
        if self.impersonated_by:
            who += ' (as, by %s)' % self.impersonated_by
        return who


#: Used by the ingest pipeline and the demo runner, where there is no HTTP
#: request and no human. Explicit rather than a None check scattered around,
#: so an unauthenticated code path is visible at the call site.
def system_principal(organization: str) -> Principal:
    return Principal(subject='system', organization=organization,
                     roles=(Role.SERVICE.value,), kind='service')
