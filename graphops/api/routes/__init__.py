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
    CrownJewelRequest,
    ImpersonationRequest,
    LoginRequest,
    MfaRequest,
    RefreshRequest,
)


def register_routes(app, *, identity, audit, current_principal, requires,
                    current_estate, respond, settings, db, estates) -> None:
    from fastapi.responses import JSONResponse

    from ...identity.service import AccountLocked, InvalidCredentials
    from ...rbac.policy import pseudonym
    from ..app import API_VERSION, ApiError

    def as_seen_by(principal: Principal, rows: list) -> list:
        """Rows as this caller may see them, for searching before paging.

        A search over the unredacted text is an oracle: a caller without
        crown:reveal searching for "billing" would get a masked match back,
        and the match itself is the answer to "is there a crown jewel
        called billing". So the search runs over what the caller would be
        shown, never over what the server knows.
        """
        if principal.can(Permission.CROWN_REVEAL):
            return rows
        return respond({'rows': rows}, principal)['rows']

    def resolve_node(principal: Principal, estate, reference: str) -> str:
        """Turn the id a caller sent into a real node id, or refuse.

        A caller without crown:reveal only ever sees crown jewels as
        pseudonyms, so the console links them by pseudonym and that has to
        work. The same caller sending a crown jewel's real id gets the same
        404 as a node that does not exist: a masked 200 would still confirm
        the guess.
        """
        crown = {n['id'] for n in estate.nodes if n.get('crown')}
        if principal.can(Permission.CROWN_REVEAL):
            node_ids = {n['id'] for n in estate.nodes}
            if reference not in node_ids:
                raise ApiError(404, 'no such node')
            return reference
        if reference in crown:
            raise ApiError(404, 'no such node')
        for node_id in crown:
            if pseudonym(node_id, organization=principal.organization,
                         salt=app.state.redaction_salt) == reference:
                return node_id
        if reference not in {n['id'] for n in estate.nodes}:
            raise ApiError(404, 'no such node')
        return reference

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

    def _refused(exc: AuthError):
        """The two answers a failed sign-in can give, and nothing else.

        A locked account says it is locked and for how long, because the
        person locked out cannot otherwise tell why their password stopped
        working. A wrong password says how many tries are left. Both answers
        are given identically for an address with no account and a tenant
        that does not exist, which is what makes it safe to give them.
        """
        if isinstance(exc, AccountLocked):
            wait = max(1, int(exc.until - time.time()))
            return JSONResponse(status_code=423, headers={'Retry-After': str(wait)},
                                content={'error': 'account locked',
                                         'retry_after_seconds': wait})
        remaining = getattr(exc, 'attempts_remaining', None)
        return JSONResponse(status_code=401, content={
            'error': 'invalid credentials',
            'attempts_remaining': remaining if remaining is not None else 0})

    @auth.post('/login', summary='Exchange a password for tokens')
    def login(body: LoginRequest):
        org = identity.organization_by_slug(body.organization)
        try:
            if org is None:
                # Same shape, cost and count as a bad password. A different
                # answer here tells an attacker which tenants exist.
                identity.fail_unknown_organization(body.organization, body.email)
            return identity.authenticate(organization_id=org['id'],
                                         email=body.email,
                                         password=body.password)
        except MfaRequired as exc:
            return {'mfa_required': True, 'challenge': exc.challenge}
        except (InvalidCredentials, AccountLocked) as exc:
            return _refused(exc)
        except AuthError:
            return _refused(InvalidCredentials())

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

    def _person(user_id):
        if not user_id:
            return None
        row = db.query_one('SELECT id, email, display_name, mfa_enabled,'
                           ' last_login_at FROM users WHERE id = ?', (user_id,))
        if row is None:
            return None
        return {'id': row['id'], 'email': row['email'],
                'display_name': row['display_name'],
                'mfa_enabled': bool(row['mfa_enabled']),
                'last_login_at': row['last_login_at']}

    @auth.get('/me', summary='Who the caller is')
    def me(principal: Principal = Depends(current_principal)):
        person = _person(principal.subject) or {}
        org = db.query_one('SELECT id, slug, name, data_residency FROM organizations'
                           ' WHERE id = ?', (principal.organization,))
        session = (db.query_one('SELECT created_at FROM sessions WHERE id = ?',
                                (principal.session_id,))
                   if principal.session_id else None)
        return {'subject': principal.subject,
                'organization': principal.organization,
                'roles': list(principal.roles),
                'kind': principal.kind,
                'impersonated_by': principal.impersonated_by,
                'permissions': sorted(p.value for p in principal.permissions),
                'email': person.get('email'),
                'display_name': person.get('display_name'),
                'mfa_enabled': person.get('mfa_enabled'),
                'session_started_at': session['created_at'] if session else None,
                # Who is really at the keyboard while someone is viewed as.
                # Shown on every screen of the console for as long as it lasts.
                'impersonator': _person(principal.impersonated_by),
                'organization_detail': (
                    {'id': org['id'], 'slug': org['slug'], 'name': org['name'],
                     'data_residency': org['data_residency']} if org else None)}

    # =============================================================== graph
    graph = APIRouter(prefix='/v1/graph', tags=['graph'])

    @graph.get('/exposure', summary='Routes from untrusted ground to a crown jewel')
    def exposure(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                 max_depth: int = Query(default=4, ge=1, le=6),
                 max_paths: int = Query(default=400, ge=1, le=2000)):
        from ... import analysis
        result = analysis.exposure(current_estate(principal), max_depth=max_depth,
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
        result = analysis.containment(current_estate(principal), max_depth=max_depth,
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
        estate = current_estate(principal)
        real = resolve_node(principal, estate, body.node_id)
        try:
            result = analysis.blast_radius(estate, real, max_hops=body.hops)
        except KeyError as exc:
            raise ApiError(404, 'no such node') from exc
        if result is None:
            raise ApiError(404, 'no such node')
        audit.record(action='graph.blast_radius', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject, resource=body.node_id)
        return respond(result, principal)

    @graph.get('/novel', summary='Routes that are new, however ordinary each step looks')
    def novel(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
              window_hours: int = Query(default=24, ge=1, le=720)):
        from ... import analysis
        return respond(analysis.novel_activity(current_estate(principal),
                                               window_hours=window_hours),
                       principal)

    @graph.get('/critical', summary='Where hardening removes the most routes')
    def critical(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                 limit: int = Query(default=8, ge=1, le=50)):
        from ... import analysis
        return respond({'nodes': analysis.critical_nodes(current_estate(principal),
                                                         limit=limit)},
                       principal)

    @graph.get('/segments', summary='Community detection over the estate')
    def segments(principal: Principal = Depends(requires(Permission.GRAPH_QUERY))):
        from ... import analysis
        return respond({'segments': analysis.segments(current_estate(principal))},
                       principal)

    @graph.get('/over-privilege', summary='Access granted against access used')
    def over_privilege(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                       status: str | None = Query(
                           default=None, pattern='^(used|idle|never|unknown|dormant)$'),
                       regulated: bool | None = Query(default=None),
                       principal_type: str | None = Query(default=None, max_length=32),
                       q: str | None = Query(default=None, max_length=200),
                       idle_days: int = Query(default=90, ge=1, le=3650),
                       limit: int = Query(default=200, ge=1, le=1000),
                       offset: int = Query(default=0, ge=0)):
        # Filtered and paged here rather than in the browser. On a generated
        # 94,000-node estate the unpaged answer was 11.5 MB and 37,866 rows,
        # which no screen survives. The counts stay over the whole set, so a
        # filter can never make the totals look better than they are.
        from ... import analysis
        result = analysis.over_privilege(current_estate(principal), idle_days=idle_days)
        rows = result['grants']
        if status == 'dormant':
            rows = [r for r in rows if r['status'] in ('never', 'idle')]
        elif status:
            rows = [r for r in rows if r['status'] == status]
        if regulated is not None:
            rows = [r for r in rows if r['reaches_crown_jewel'] == regulated]
        if principal_type:
            rows = [r for r in rows
                    if (r['identity'].get('principal_type') or '') == principal_type]
        if q:
            needle = q.strip().lower()
            rows = [r for r in as_seen_by(principal, rows)
                    if needle in (r['identity']['key'] or '').lower()
                    or needle in (r['target']['key'] or '').lower()
                    or needle in (r.get('permission') or '').lower()]
        body = {key: value for key, value in result.items()
                if key not in ('grants', 'dormant')}
        body.update(total=len(rows), limit=limit, offset=offset,
                    grants=rows[offset:offset + limit])
        return respond(body, principal)

    @graph.get('/map', summary='Every system and relationship, ready to draw')
    def graph_map(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                  limit: int = Query(default=400, ge=1, le=2000),
                  window_hours: int = Query(default=24, ge=1, le=720)):
        # Through respond() like every graph answer, so a role without
        # crown:reveal gets the same pseudonyms here as in a route, and the
        # map lines up with anything drawn on it. Audited like exposure,
        # because the whole map is the most a single answer gives away.
        from ... import analysis
        result = analysis.estate_map(current_estate(principal), limit=limit,
                                     window_hours=window_hours)
        audit.record(action='graph.map', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject,
                     on_behalf_of=principal.impersonated_by,
                     detail={'nodes': result['shown_nodes'],
                             'truncated': result['truncated']})
        return respond(result, principal)

    @graph.get('/nodes', summary='Find entities by name')
    def search_nodes(principal: Principal = Depends(requires(Permission.GRAPH_QUERY)),
                     q: str | None = Query(default=None, max_length=200),
                     limit: int = Query(default=20, ge=1, le=200)):
        # Matched over what the caller is shown, as every search here is.
        # Matching the real names would let a caller without crown:reveal
        # learn that a crown jewel called "billing" exists from the fact
        # that a masked result came back at all.
        estate = current_estate(principal)
        loaded = estate.loaded()
        described = [loaded.describe(node_id) for node_id in loaded.meta]
        visible = as_seen_by(principal, described)
        if q:
            needle = q.strip().lower()
            visible = [d for d in visible if needle in (d['key'] or '').lower()
                       or needle in (d['label'] or '').lower()]
        # Crown jewels first, then by name, so the systems that matter are
        # the first thing a search offers.
        visible.sort(key=lambda d: (not d['is_crown_jewel'], d['key']))
        return respond({'nodes': visible[:limit], 'total': len(visible)}, principal)

    @graph.get('/nodes/{node_id:path}', summary='One entity, where it came from, and what it reaches')
    def node_detail(node_id: str,
                    principal: Principal = Depends(requires(Permission.GRAPH_QUERY))):
        from ... import analysis
        estate = current_estate(principal)
        real = resolve_node(principal, estate, node_id)
        detail = analysis.node_detail(estate, real)
        audit.record(action='graph.node', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject,
                     on_behalf_of=principal.impersonated_by, resource=node_id)
        return respond(detail, principal)

    @graph.post('/crown-jewels', summary='Say whether a system is a crown jewel')
    def mark_crown_jewel(body: CrownJewelRequest,
                         principal: Principal = Depends(requires(Permission.CROWN_WRITE))):
        estate = current_estate(principal)
        node = next((n for n in estate.nodes if n['id'] == body.node_id), None)
        if node is None:
            raise ApiError(404, 'no such node')
        from ...vocab import Zone
        if body.crown and node.get('zone') == Zone.UNTRUSTED:
            # Every route starts on the internet. Marking an internet address
            # as the thing worth protecting would make every route end where
            # it begins.
            raise ApiError(400, 'an address on the internet cannot be a crown jewel')
        estates.set_crown(principal.organization, body.node_id, body.crown,
                          body.reason, principal.subject)
        audit.record(action='crown_jewel.mark' if body.crown else 'crown_jewel.unmark',
                     outcome=Outcome.SUCCESS, organization_id=principal.organization,
                     actor_id=principal.subject,
                     on_behalf_of=principal.impersonated_by, resource=body.node_id,
                     detail={'reason': body.reason,
                             'source_said': bool(node.get('crown'))})
        return {'node_id': body.node_id, 'crown': body.crown}

    @graph.get('/export', summary='The estate in a named interchange format')
    def export(principal: Principal = Depends(requires(Permission.GRAPH_EXPORT)),
               fmt: str = Query(default='stix', pattern='^(stix|sarif|oscal|csv)$')):
        from ...exporters import export_estate
        audit.record(action='graph.export', outcome=Outcome.SUCCESS,
                     organization_id=principal.organization,
                     actor_id=principal.subject, detail={'format': fmt})
        return respond(export_estate(current_estate(principal), fmt=fmt), principal)

    # ============================================================ overview
    overview_router = APIRouter(tags=['graph'])

    @overview_router.get('/v1/overview', summary='The whole estate in one answer')
    def overview(principal: Principal = Depends(requires(Permission.GRAPH_READ))):
        """The landing screen, for every role that can read the graph.

        Each section is included only for a role holding its permission, and
        a withheld section is named along with the permission that would
        unlock it, so the screen can say why something is missing rather
        than looking broken. Counts are never withheld: "three routes reach
        a crown jewel" is the number a viewer is there to see.
        """
        from ... import analysis
        estate = current_estate(principal)
        summary = analysis.overview(estate)
        withheld: dict[str, str] = {}

        if not principal.can(Permission.GRAPH_QUERY):
            summary['exposure'].pop('cheapest', None)
            summary.pop('top_choke_point', None)
            for key in ('new_edges', 'new_reach', 'incidents'):
                summary['recent'].pop(key, None)
            withheld['exposure.cheapest'] = Permission.GRAPH_QUERY.value
            withheld['top_choke_point'] = Permission.GRAPH_QUERY.value
            withheld['recent.items'] = Permission.GRAPH_QUERY.value

        if principal.can(Permission.FINDING_READ):
            current = estates.findings(principal.organization)
            by_severity = {name: 0 for name in ('critical', 'high', 'medium', 'low')}
            for finding in current:
                by_severity[finding['severity']] = by_severity.get(finding['severity'], 0) + 1
            summary['findings'] = {
                'total': len(current), 'by_severity': by_severity,
                'worst': [{key: f.get(key) for key in
                           ('fingerprint', 'kind', 'severity', 'title', 'routes',
                            'first_seen')} for f in current[:5]]}
        else:
            withheld['findings'] = Permission.FINDING_READ.value

        if principal.can(Permission.CONNECTOR_READ):
            summary['last_ingest'] = estates.latest_ingest(principal.organization)
            summary['served_ingest'] = estates.served_ingest(principal.organization)
        else:
            withheld['last_ingest'] = Permission.CONNECTOR_READ.value
            withheld['served_ingest'] = Permission.CONNECTOR_READ.value

        summary['sections_withheld'] = withheld
        return respond(summary, principal)

    # ========================================================== connectors
    connectors = APIRouter(prefix='/v1/connectors', tags=['connectors'])

    @connectors.get('', summary='Every integration, and how each last ran')
    def list_connectors(
            principal: Principal = Depends(requires(Permission.CONNECTOR_READ))):
        from ...connectors.registry import catalogue
        latest = estates.latest_ingest(principal.organization)
        by_key = {run['connector']: run for run in (latest or {}).get('runs', [])}
        listing = []
        for entry in catalogue():
            run = by_key.get(entry['key'])
            listing.append(dict(entry, last_run=(
                {'status': run['status'], 'mode': run['mode'],
                 'nodes': run['nodes'], 'edges': run['edges'],
                 'duration_ms': run['duration_ms'], 'error': run['error'],
                 'stats': run.get('stats') or {}}
                if run else None)))
        return {'connectors': listing, 'last_ingest': latest,
                'mode': settings.connector_mode}

    @connectors.post('/run', summary='Run connectors and rebuild the estate')
    def run_connectors(
            body: ConnectorRunRequest,
            principal: Principal = Depends(requires(Permission.CONNECTOR_RUN))):
        from ...connectors import registry, resolve
        if body.mode == 'live' and settings.connector_mode != 'live':
            raise ApiError(400, 'this deployment is configured for replay mode')
        started = time.time()
        result = registry.ingest(body.connectors, mode=body.mode)
        resolved = resolve.resolve(result.estate)
        finished = time.time()
        for run in result.runs:
            audit.record(action='connector.run',
                         outcome=(Outcome.SUCCESS if run.status == 'success'
                                  else Outcome.FAILURE),
                         organization_id=principal.organization,
                         actor_id=principal.subject, resource=run.connector,
                         detail=run.as_dict())
        # The served estate changes only when something was ingested. A run
        # in which every connector failed is recorded and reported, and the
        # tenant keeps the estate it had, rather than being handed an empty
        # one that would answer "no routes found".
        if result.status != 'failed' and resolved.get('nodes'):
            estates.replace(principal.organization, resolved, result.ingest_id)
        record = estates.record_ingest(principal.organization, principal.subject,
                                       result, resolved, started, finished)
        audit.record(action='ingest.complete', outcome=(
            Outcome.SUCCESS if result.status == 'success' else Outcome.FAILURE),
            organization_id=principal.organization, actor_id=principal.subject,
            resource=result.ingest_id,
            detail={'status': result.status, 'connectors_run': len(result.runs),
                    'failed': [run.connector for run in result.failures]})
        summary = result.summary()
        summary['resolution'] = resolved.get('resolution', {})
        summary['ingest'] = record
        summary['served'] = result.status != 'failed'
        return summary

    # ============================================================ findings
    findings = APIRouter(prefix='/v1/findings', tags=['findings'])

    @findings.get('', summary='What the analysis produced, with its history')
    def list_findings(
            principal: Principal = Depends(requires(Permission.FINDING_READ)),
            severity: str | None = Query(default=None,
                                         pattern='^(critical|high|medium|low)$'),
            kind: str | None = Query(default=None, max_length=40),
            status: str = Query(default='open', pattern='^(open|resolved)$'),
            q: str | None = Query(default=None, max_length=200),
            limit: int = Query(default=200, ge=1, le=1000),
            offset: int = Query(default=0, ge=0)):
        # Filtered and paged here, with counts over the whole open set so the
        # filter chips always show totals. Unpaged, this was 18 MB on the
        # 94,000-node estate. Each finding carries when it was first seen,
        # kept by fingerprint across ingests, and one that stopped being
        # true is listed under status=resolved rather than disappearing.
        current_estate(principal)       # 503 when nothing is loaded
        everything = estates.findings(principal.organization)
        rows = (everything if status == 'open'
                else estates.resolved_findings(principal.organization))
        by_severity = {name: 0 for name in ('critical', 'high', 'medium', 'low')}
        by_kind: dict[str, int] = {}
        for finding in everything:
            by_severity[finding['severity']] = by_severity.get(finding['severity'], 0) + 1
            by_kind[finding['kind']] = by_kind.get(finding['kind'], 0) + 1
        if severity:
            rows = [f for f in rows if f['severity'] == severity]
        if kind:
            rows = [f for f in rows if f['kind'] == kind]
        if q:
            needle = q.strip().lower()
            rows = [f for f in as_seen_by(principal, rows)
                    if needle in f['title'].lower()
                    or needle in f['fingerprint'].lower()]
        return respond({'findings': rows[offset:offset + limit], 'total': len(rows),
                        'count': len(rows[offset:offset + limit]),
                        'by_severity': by_severity, 'by_kind': by_kind,
                        'open': len(everything), 'limit': limit, 'offset': offset},
                       principal)

    # ========================================================== compliance
    compliance = APIRouter(prefix='/v1/compliance', tags=['compliance'])

    @compliance.get('/controls', summary='Control coverage from graph evidence')
    def controls(
            principal: Principal = Depends(requires(Permission.COMPLIANCE_READ)),
            framework: str = Query(default='soc2',
                                   pattern='^(soc2|iso27001|cis)$')):
        from ...compliance.assess import assess
        return respond(assess(current_estate(principal), framework=framework), principal)

    # =============================================================== admin
    admin = APIRouter(prefix='/v1/admin', tags=['admin'])

    @admin.get('/audit', summary='The audit log')
    def audit_log(principal: Principal = Depends(requires(Permission.AUDIT_READ)),
                  limit: int = Query(default=100, ge=1, le=1000),
                  offset: int = Query(default=0, ge=0)):
        # Scoped to the caller's own organization. Not a filter the caller
        # supplies: a tenant must not be able to ask for another's log.
        #
        # Redacted on the way out, because an entry's `resource` is whatever
        # the analyst queried, and an analyst running blast radius on the
        # card database writes its id into the log an auditor then reads.
        # The stored rows are untouched, so the hash chain still verifies.
        return respond({'entries': audit.entries(
            organization_id=principal.organization,
            limit=limit, offset=offset)}, principal)

    @admin.get('/audit/verify', summary='Recompute the audit hash chain')
    def audit_verify(principal: Principal = Depends(requires(Permission.AUDIT_READ))):
        return audit.verify_chain()

    @admin.get('/users', summary='The people in this organization')
    def list_users(principal: Principal = Depends(requires(Permission.USER_READ))):
        # Columns named one by one. `SELECT *` would carry the password hash
        # and the TOTP secret into a response the day someone forgets to
        # strip them, and a listing is exactly where nobody looks for that.
        rows = db.query(
            'SELECT id, email, display_name, is_active, mfa_enabled, created_at,'
            ' last_login_at, locked_until FROM users WHERE organization_id = ?'
            ' ORDER BY created_at, email', (principal.organization,))
        roles: dict[str, list] = {}
        for row in db.query(
                'SELECT r.user_id, r.role FROM user_roles r JOIN users u'
                ' ON u.id = r.user_id WHERE u.organization_id = ?',
                (principal.organization,)):
            roles.setdefault(row['user_id'], []).append(row['role'])
        now = int(time.time())
        return {'users': [{
            'id': row['id'], 'email': row['email'],
            'display_name': row['display_name'],
            'roles': sorted(roles.get(row['id'], [])),
            'is_active': bool(row['is_active']),
            'mfa_enabled': bool(row['mfa_enabled']),
            'created_at': row['created_at'], 'last_login_at': row['last_login_at'],
            'locked': bool(row['locked_until'] and row['locked_until'] > now),
            'is_you': row['id'] == principal.subject,
        } for row in rows], 'assignable_roles': sorted(r.value for r in ASSIGNABLE_ROLES)}

    @admin.get('/api-keys', summary='API keys in this organization')
    def list_api_keys(principal: Principal = Depends(requires(Permission.APIKEY_MANAGE))):
        # The prefix identifies a key in logs; the hash is never returned and
        # the key itself was shown once, when it was minted.
        rows = db.query(
            'SELECT id, name, prefix, roles, created_by, created_at, expires_at,'
            ' last_used_at, revoked_at FROM api_keys WHERE organization_id = ?'
            ' ORDER BY created_at DESC', (principal.organization,))
        return {'api_keys': [dict(row, roles=[r for r in (row['roles'] or '').split(',') if r])
                             for row in rows]}

    @admin.post('/impersonation', summary='View the product as another user')
    def start_impersonation(
            body: ImpersonationRequest,
            principal: Principal = Depends(requires(Permission.IMPERSONATE))):
        # A session of its own, carrying both identities on every audit
        # entry. Ending it is logging that session out; the owner's own
        # session was never touched, so it simply resumes.
        if principal.impersonated_by:
            raise ApiError(400, 'end the current impersonation first')
        if body.user_id == principal.subject:
            raise ApiError(400, 'that is you')
        try:
            return identity.impersonate(admin=principal, target_user_id=body.user_id,
                                        client_ip=principal.client_ip)
        except AuthError as exc:
            # Another tenant's user and no user at all answer alike.
            raise ApiError(404, 'no such user') from exc

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

    for router in (ops, auth, overview_router, graph, connectors, findings,
                   compliance, admin):
        app.include_router(router)
