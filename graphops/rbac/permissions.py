"""Permissions and the roles that carry them.

The matrix below is the whole authorisation model. It is data, not code, so
the test suite can assert properties over it: that no role outside the
intended two can reveal crown-jewel detail, that VIEWER is a strict subset of
ANALYST, that SERVICE cannot read the audit log.

Two conventions worth stating because they drive the design.

**Deny by default.** `has(role, permission)` answers False for anything not
listed. There is no wildcard and no implicit inheritance; a role that should
do more gets the permission written into its row, where a reviewer sees it.

**Reading a crown jewel's identity is its own permission.** Everything else
in a security product is read-or-write, but `CROWN_REVEAL` splits reading a
path from reading what sits at the end of it. An auditor confirming that
paths are being reviewed does not need to know which database holds the card
data, and a viewer in a weekly report meeting needs it even less. Who may see
the target is the question an attacker inside the tool most wants answered.
"""
from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    # graph
    GRAPH_READ = 'graph:read'
    GRAPH_QUERY = 'graph:query'
    GRAPH_EXPORT = 'graph:export'
    CROWN_REVEAL = 'crown:reveal'
    # Saying which systems matter. Every answer in the product is a route to
    # a crown jewel, so this changes all of them for the tenant, and only a
    # role that can already see crown jewel names may hold it: one that
    # could not would mark a pseudonym and learn the real id from whether
    # the mark succeeded.
    CROWN_WRITE = 'crown:write'

    # findings
    FINDING_READ = 'finding:read'
    FINDING_WRITE = 'finding:write'
    FINDING_ASSIGN = 'finding:assign'

    # connectors
    CONNECTOR_READ = 'connector:read'
    CONNECTOR_RUN = 'connector:run'
    CONNECTOR_CONFIGURE = 'connector:configure'
    INGEST_WRITE = 'ingest:write'

    # tenancy and people
    USER_READ = 'user:read'
    USER_WRITE = 'user:write'
    ROLE_ASSIGN = 'role:assign'
    ORG_READ = 'org:read'
    ORG_WRITE = 'org:write'
    APIKEY_MANAGE = 'apikey:manage'
    WEBHOOK_MANAGE = 'webhook:manage'
    IMPERSONATE = 'user:impersonate'

    # oversight
    AUDIT_READ = 'audit:read'
    COMPLIANCE_READ = 'compliance:read'


class Role(str, Enum):
    OWNER = 'owner'
    ADMIN = 'admin'
    ANALYST = 'analyst'
    RESPONDER = 'responder'
    AUDITOR = 'auditor'
    VIEWER = 'viewer'
    SERVICE = 'service'


P = Permission

#: The authorisation model. Nothing is inherited; each row is complete.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset({
        P.GRAPH_READ, P.GRAPH_QUERY, P.GRAPH_EXPORT, P.CROWN_REVEAL, P.CROWN_WRITE,
        P.FINDING_READ, P.FINDING_WRITE, P.FINDING_ASSIGN,
        P.CONNECTOR_READ, P.CONNECTOR_RUN, P.CONNECTOR_CONFIGURE,
        P.USER_READ, P.USER_WRITE, P.ROLE_ASSIGN,
        P.ORG_READ, P.ORG_WRITE, P.APIKEY_MANAGE, P.WEBHOOK_MANAGE,
        P.AUDIT_READ, P.COMPLIANCE_READ, P.IMPERSONATE,
    }),
    Role.ADMIN: frozenset({
        P.GRAPH_READ, P.GRAPH_QUERY, P.GRAPH_EXPORT, P.CROWN_REVEAL, P.CROWN_WRITE,
        P.FINDING_READ, P.FINDING_WRITE, P.FINDING_ASSIGN,
        P.CONNECTOR_READ, P.CONNECTOR_RUN, P.CONNECTOR_CONFIGURE,
        P.USER_READ, P.USER_WRITE, P.ROLE_ASSIGN,
        P.ORG_READ, P.APIKEY_MANAGE, P.WEBHOOK_MANAGE,
        P.AUDIT_READ, P.COMPLIANCE_READ,
    }),
    # The working role. Sees everything about the estate and may say which
    # systems in it matter, which is analysis rather than administration.
    # Changes nothing about the tenant's people, keys or settings.
    Role.ANALYST: frozenset({
        P.GRAPH_READ, P.GRAPH_QUERY, P.GRAPH_EXPORT, P.CROWN_REVEAL, P.CROWN_WRITE,
        P.FINDING_READ, P.FINDING_WRITE,
        P.CONNECTOR_READ, P.COMPLIANCE_READ, P.ORG_READ,
    }),
    # Works the queue during an incident. Can act on findings, cannot export
    # the graph wholesale.
    Role.RESPONDER: frozenset({
        P.GRAPH_READ, P.GRAPH_QUERY, P.CROWN_REVEAL,
        P.FINDING_READ, P.FINDING_WRITE, P.FINDING_ASSIGN,
        P.CONNECTOR_READ, P.ORG_READ,
    }),
    # Reads the record, including the audit log, without seeing what sits at
    # the end of a path. Checking that the process runs does not require
    # knowing which system holds the card data.
    Role.AUDITOR: frozenset({
        # GRAPH_QUERY without CROWN_REVEAL is the entire point of this role,
        # and the pair is what makes CROWN_REVEAL load-bearing rather than
        # decorative. Without the query permission an auditor cannot run the
        # path search at all, so the redaction never applies to a route and
        # the separate permission buys nothing on /v1/graph. That was true
        # here until filming a demo of it showed the auditor getting a 403.
        P.GRAPH_READ, P.GRAPH_QUERY,
        P.FINDING_READ, P.AUDIT_READ,
        P.COMPLIANCE_READ, P.ORG_READ, P.USER_READ, P.CONNECTOR_READ,
    }),
    # Dashboard access. Counts and shapes, no identities.
    Role.VIEWER: frozenset({
        P.GRAPH_READ, P.FINDING_READ, P.ORG_READ,
    }),
    # Machine identity used by connectors. Writes telemetry, reads nothing.
    Role.SERVICE: frozenset({
        P.INGEST_WRITE, P.CONNECTOR_READ,
    }),
}

#: Roles that may be handed out through the API. SERVICE is excluded
#: deliberately: it is attached to an API key at creation, and letting it be
#: granted to a person would hand a human an identity that bypasses the
#: read-side checks entirely.
ASSIGNABLE_ROLES = frozenset(ROLE_PERMISSIONS) - {Role.SERVICE}


def parse_role(value: str) -> Role:
    try:
        return Role(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError('unknown role %r' % (value,)) from exc


def permissions_for(roles) -> frozenset[Permission]:
    """Union of the permissions carried by `roles`. Unknown roles contribute nothing."""
    granted: set[Permission] = set()
    for raw in roles or ():
        try:
            role = raw if isinstance(raw, Role) else parse_role(raw)
        except ValueError:
            # An unrecognised role grants nothing rather than raising. A role
            # removed from the matrix should lock a user out, not 500 them out.
            continue
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def has(roles, permission: Permission) -> bool:
    return permission in permissions_for(roles)
