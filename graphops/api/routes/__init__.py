"""Route registration.

Every route names the permission it requires in its own dependency list. The
grouping into routers is for the OpenAPI document's benefit; it carries no
authorisation meaning, so moving a route between routers cannot change who
may call it.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query

from ...audit.chain import Outcome
from ...identity.service import AuthError, MfaRequired, SessionReplayDetected
from ...rbac.permissions import ASSIGNABLE_ROLES, Permission, parse_role
from ...rbac.principal import Principal
from ..schemas import (
    BlastRadiusRequest,
    ConnectorRunRequest,
    CreateApiKeyRequest,
    CreateUserRequest,
    LoginRequest,
    MfaRequest,
    RefreshRequest,
)


def register_routes(app, *, identity, audit, current_principal, requires,
                    current_estate, respond, settings, db) -> None:
    from ..app import API_VERSION, ApiError

    # ================================================================= ops
    ops = APIRouter(tags=['ops'])

    @ops.get('/health', summary='Liveness')
    def health():
        return {'status': 'ok', 'version': API_VERSION,
                'uptime_seconds': int(time.time() - app.state.started_at)}

    @ops.get('/health/ready', summary='Readiness')
    def ready():
        # Readiness asks whether this process can serve a request, which
        # means the database answers and an estate is loaded. Returning ok
        # while the estate is absent would put an empty replica into a load
        # balancer and answer "no attack paths found".
        checks = {'database': False, 'estate': False}
        try:
            db.query_one('SELECT 1 AS ok')
            checks['database'] = True
        except Exception:  # noqa: BLE001, S110
            # Readiness reports the failure through `checks`; raising here
            # would turn a degraded probe into a 500 and tell a load
            # balancer nothing useful.
            pass
        try:
            checks['estate'] = app.state.estate_provider is not None
        except Exception:  # noqa: BLE001, S110
            # Same reasoning as above.
            pass
        healthy = all(checks.values())
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=200 if healthy else 503,
                            content={'status': 'ready' if healthy else 'not ready',
                                     'checks': checks})

    @ops.get('/metrics', summary='Prometheus metrics')
    def metrics():
        from fastapi.responses import PlainTextResponse

        from ...observability.metrics import render
        return PlainTextResponse(render(), media_type='text/plain; version=0.0.4')

    # ================================================================ auth
    auth = APIRouter(prefix='/v1/auth', tags=['auth'])

    @auth.post('/login', summary='Exchange a password for tokens')
    def login(body: LoginRequest):
        org = identity.organization_by_slug(body.organization)
        if org is None:
            # Same shape and cost as a bad password. A different answer here
            # tells an attacker which tenants exist.
            from ...identity import passwords
            passwords.dummy_verify()
            raise ApiError(401, 'invalid credentials')
        try:
            return identity.authenticate(organization_id=org['id'],
                                         email=body.email,
                                         password=body.password)
        except MfaRequired as exc:
            return {'mfa_required': True, 'challenge': exc.challenge}
        except AuthError as exc:
            raise ApiError(401, 'invalid credentials') from exc

    @auth.post('/mfa', summary='Complete an MFA challenge')
    def mfa(body: MfaRequest):
        try:
            return identity.complete_mfa(challenge=body.challenge, code=body.code)
        except AuthError as exc:
            raise ApiError(401, 'invalid code') from exc

    @auth.post('/refresh', summary='Rotate a refresh token')
    def refresh(body: RefreshRequest):
        try:
            return identity.refresh(body.refresh_token)
        except SessionReplayDetected as exc:
            # 409, not 401. The credential was valid; the problem is that it
            # was used twice, and the client deserves to know the difference.
            raise ApiError(409, 'refresh token reuse detected; '
                                'the session has been revoked') from exc
        except AuthError as exc:
            raise ApiError(401, 'invalid refresh token') from exc

    @auth.post('/logout', summary='Revoke the current session')
    def logout(principal: Principal = Depends(current_principal)):
        identity.revoke_session(principal.session_id, reason='user logout')
        if principal.token_id:
            identity.revoke_token(principal.token_id,
                                  int(time.time()) + settings.access_token_ttl_seconds,
                                  reason='logout')
        return {'revoked': True}

    @auth.get('/me', summary='Who the caller is')
    def me(principal: Principal = Depends(current_principal)):
        return {'subject': principal.subject,
                'organization': principal.organization,
                'roles': list(principal.roles),
                'kind': principal.kind,
                'impersonated_by': principal.impersonated_by,
                'permissions': sorted(p.value for p in principal.permissions)}

    # =============================================================== graph
    graph = APIRouter(prefix='/v1/graph', tags=['graph'])

    @graph.get('/exposure', summary='Routes from untrusted ground to a crown jewel')
    def exposure(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                 max_depth: int = Query(default=4, ge=1, le=6),
                 max_paths: int = Query(default=400, ge=1, le=2000)):
        from ... import analysis
        result = analysis.exposure(current_estate(), max_depth=max_depth,
                                   max_paths=max_paths)
        audit.record(action='graph.exposure', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject,
                     on_behalf_of=principal.impersonated_by,
                     detail={'paths': len(result.get('paths', []))})
        return respond(result, principal)

    @graph.get('/containment', summary='What one cut is measured to buy')
    def containment(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                    max_depth: int = Query(default=4, ge=1, le=6),
                    max_paths: int = Query(default=400, ge=1, le=2000),
                    candidates: int = Query(default=6, ge=1, le=12)):
        # `candidates` is capped low because every candidate re-runs the whole
        # path search. It is a cost ceiling on one request, not a preference.
        from ... import analysis
        result = analysis.containment(current_estate(), max_depth=max_depth,
                                      max_paths=max_paths, candidates=candidates)
        audit.record(action='graph.containment', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject,
                     on_behalf_of=principal.impersonated_by,
                     detail={'options': len(result.get('options', []))})
        return respond(result, principal)

    @graph.post('/blast-radius', summary='What one compromise reaches')
    def blast_radius(body: BlastRadiusRequest,
                     principal: Principal = Depends(requires(Permission.GRAPH_QUERY))):
        from ... import analysis
        try:
            result = analysis.blast_radius(current_estate(), body.node_id,
                                           max_hops=body.hops)
        except KeyError as exc:
            raise ApiError(404, 'no such node') from exc
        audit.record(action='graph.blast_radius', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject, resource=body.node_id)
        return respond(result, principal)

    @graph.get('/novel', summary='Routes that are new, however ordinary each step looks')
    def novel(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
              window_hours: int = Query(default=24, ge=1, le=720)):
        from ... import analysis
        return respond(analysis.novel_activity(current_estate(),
                                               window_hours=window_hours),
                       principal)

    @graph.get('/critical', summary='Where hardening removes the most routes')
    def critical(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                 limit: int = Query(default=8, ge=1, le=50)):
        from ... import analysis
        return respond({'nodes': analysis.critical_nodes(current_estate(),
                                                         limit=limit)},
                       principal)

    @graph.get('/segments', summary='Community detection over the estate')
    def segments(principal: Principal = Depends(requires(Permission.GRAPH_QUERY))):
        from ... import analysis
        return respond({'segments': analysis.segments(current_estate())},
                       principal)

    @graph.get('/over-privilege', summary='Access granted against access used')
    def over_privilege(principal: Principal = Depends(requires(Permission.GRAPH_QUERY))):
        from ... import analysis
        return respond(analysis.over_privilege(current_estate()), principal)

    @graph.get('/export', summary='The estate in a named interchange format')
    def export(principal: Principal = Depends(requires(Permission.GRAPH_EXPORT)),
               fmt: str = Query(default='stix', pattern='^(stix|sarif|oscal|csv)$')):
        from ...exporters import export_estate
        audit.record(action='graph.export', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject, detail={'format': fmt})
        return respond(export_estate(current_estate(), fmt=fmt), principal)

    # ========================================================== connectors
    connectors = APIRouter(prefix='/v1/connectors', tags=['connectors'])

    @connectors.get('', summary='Every integration the platform knows')
    def list_connectors(
            principal: Principal = Depends(requires(Permission.CONNECTOR_READ))):
        from ...connectors.registry import catalogue
        return {'connectors': catalogue()}

    @connectors.post('/run', summary='Run connectors and rebuild the estate')
    def run_connectors(
            body: ConnectorRunRequest,
            principal: Principal = Depends(requires(Permission.CONNECTOR_RUN))):
        from ...connectors import registry, resolve
        if body.mode == 'live' and settings.connector_mode != 'live':
            raise ApiError(400, 'this deployment is configured for replay mode')
        result = registry.ingest(body.connectors, mode=body.mode)
        resolved = resolve.resolve(result.estate)
        for run in result.runs:
            audit.record(action='connector.run',
                         outcome=(Outcome.SUCCESS if run.status == 'success'
                                  else Outcome.FAILURE),
                         organization_id=principal.organization,
                         actor_id=principal.subject, resource=run.connector,
                         detail=run.as_dict())
        summary = result.summary()
        summary['resolution'] = resolved.get('resolution', {})
        return summary

    # ============================================================ findings
    findings = APIRouter(prefix='/v1/findings', tags=['findings'])

    @findings.get('', summary='What the analysis produced')
    def list_findings(
            principal: Principal = Depends(requires(Permission.FINDING_READ)),
            severity: str | None = Query(default=None,
                                         pattern='^(critical|high|medium|low)$')):
        from ...findings import derive
        produced = derive(current_estate())
        if severity:
            produced = [f for f in produced if f['severity'] == severity]
        return respond({'findings': produced, 'count': len(produced)}, principal)

    # ========================================================== compliance
    compliance = APIRouter(prefix='/v1/compliance', tags=['compliance'])

    @compliance.get('/controls', summary='Control coverage from graph evidence')
    def controls(
            principal: Principal = Depends(requires(Permission.COMPLIANCE_READ)),
            framework: str = Query(default='soc2',
                                   pattern='^(soc2|iso27001|cis)$')):
        from ...compliance.assess import assess
        return respond(assess(current_estate(), framework=framework), principal)

    # =============================================================== admin
    admin = APIRouter(prefix='/v1/admin', tags=['admin'])

    @admin.get('/audit', summary='The audit log')
    def audit_log(principal: Principal = Depends(requires(Permission.AUDIT_READ)),
                  limit: int = Query(default=100, ge=1, le=1000),
                  offset: int = Query(default=0, ge=0)):
        # Scoped to the caller's own organization. Not a filter the caller
        # supplies: a tenant must not be able to ask for another's log.
        return {'entries': audit.entries(organization_id=principal.organization,
                                         limit=limit, offset=offset)}

    @admin.get('/audit/verify', summary='Recompute the audit hash chain')
    def audit_verify(principal: Principal = Depends(requires(Permission.AUDIT_READ))):
        return audit.verify_chain()

    @admin.post('/users', summary='Create a user')
    def create_user(body: CreateUserRequest,
                    principal: Principal = Depends(requires(Permission.USER_WRITE))):
        try:
            roles = [parse_role(r) for r in body.roles]
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        if any(r not in ASSIGNABLE_ROLES for r in roles):
            raise ApiError(400, 'that role cannot be assigned to a person')
        try:
            return identity.create_user(
                organization_id=principal.organization, email=body.email,
                password=body.password, roles=roles,
                display_name=body.display_name, created_by=principal.subject)
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc

    @admin.post('/api-keys', summary='Mint an API key')
    def create_api_key(body: CreateApiKeyRequest,
                       principal: Principal = Depends(requires(Permission.APIKEY_MANAGE))):
        return identity.create_api_key(organization_id=principal.organization,
                                       name=body.name, roles=body.roles,
                                       created_by=principal.subject)

    @admin.delete('/api-keys/{key_id}', summary='Revoke an API key')
    def revoke_api_key(key_id: str,
                       principal: Principal = Depends(requires(Permission.APIKEY_MANAGE))):
        row = db.query_one('SELECT organization_id FROM api_keys WHERE id = ?',
                           (key_id,))
        if row is None:
            raise ApiError(404, 'no such key')
        if row['organization_id'] != principal.organization:
            # 404 rather than 403. Answering "forbidden" would confirm the
            # key exists in some other tenant.
            raise ApiError(404, 'no such key')
        return {'revoked': identity.revoke_api_key(key_id,
                                                   actor_id=principal.subject)}

    for router in (ops, auth, graph, connectors, findings, compliance, admin):
        app.include_router(router)
