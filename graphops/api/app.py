"""The HTTP API.

Design notes worth reading before the routes.

**Authentication is a dependency, not middleware.** `current_principal`
resolves a bearer token or an API key into a `Principal`. A route without
that dependency is unauthenticated, which is visible in its signature rather
than hidden in a path-prefix rule somewhere else. `test_every_route_is_guarded`
walks the route table and fails if a non-public route lacks it, so the
guarantee survives the next person adding an endpoint.

**Authorisation is explicit per route.** Each route names the permission it
needs. There is no "admin endpoints live under /admin" convention, because
that convention is one careless `include_router` away from being false.

**Every response passes through the redactor.** Not a list of fields chosen
per endpoint: the whole payload is walked. A new endpoint returning node
records is redacted correctly before anyone remembers it should be.

**Errors never echo internals.** `ApiError` carries a status and a safe
message; anything else becomes a 500 with a correlation id, and the detail
goes to the log and the audit trail rather than to the caller.
"""
from __future__ import annotations

import time
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from ..audit.chain import AuditLog, Outcome
from ..config import Settings
from ..identity import tokens as token_module
from ..identity.service import AuthError, IdentityService
from ..rbac.permissions import Permission
from ..rbac.policy import redact
from ..rbac.principal import AccessDenied, Principal
from .ratelimit import RateLimiter

API_VERSION = '1.0.0'

#: Routes that legitimately take no principal. Checked by the test suite, so
#: adding one is a visible decision rather than an oversight.
PUBLIC_PATHS = frozenset({
    '/health', '/health/ready', '/openapi.json', '/docs', '/redoc',
    '/docs/oauth2-redirect', '/metrics',
    '/v1/auth/login', '/v1/auth/mfa', '/v1/auth/refresh',
})


class ApiError(HTTPException):
    """An error with a body safe to return to a caller."""

    def __init__(self, status_code: int, message: str, code: str = ''):
        super().__init__(status_code=status_code, detail=message)
        self.code = code or 'error'


def create_app(*, settings: Settings, db, estate_provider=None) -> FastAPI:
    """Build the application.

    `estate_provider` is a callable returning the current `Estate`. Injected
    rather than imported so tests and the demo can supply their own without
    a module-level global that the process can never change.
    """
    audit = AuditLog(db)
    identity = IdentityService(db, settings, audit)
    limiter = RateLimiter(per_minute=settings.rate_limit_per_minute)

    app = FastAPI(
        title='GraphOps API',
        version=API_VERSION,
        description=(
            'Security telemetry as a graph. Attack paths, blast radius, '
            'structural anomalies and standing access, over an estate '
            'assembled from SIEM, EDR, identity provider, cloud, '
            'vulnerability and CMDB connectors.'),
        openapi_tags=[
            {'name': 'auth', 'description': 'Sign-in, MFA and token lifecycle.'},
            {'name': 'graph', 'description': 'The four questions the engine answers.'},
            {'name': 'connectors', 'description': 'Integrations and ingest runs.'},
            {'name': 'findings', 'description': 'What the analysis produced.'},
            {'name': 'compliance', 'description': 'Control coverage from graph evidence.'},
            {'name': 'admin', 'description': 'Users, API keys and the audit log.'},
            {'name': 'ops', 'description': 'Health and metrics.'},
        ],
    )
    app.state.settings = settings
    app.state.db = db
    app.state.identity = identity
    app.state.audit = audit
    app.state.estate_provider = estate_provider
    app.state.started_at = time.time()
    #: Per-tenant pseudonymisation salt. Derived from the signing key so it
    #: needs no separate secret, and domain-separated so a leak of one
    #: pseudonym set says nothing about a token.
    app.state.redaction_salt = b'graphops-redaction|' + settings.signing_key

    # ------------------------------------------------------------ plumbing
    @app.middleware('http')
    async def correlate_and_limit(request: Request, call_next):
        request_id = request.headers.get('x-request-id') or str(uuid.uuid4())
        request.state.request_id = request_id

        # Keyed on the token or key when present, falling back to the peer
        # address. Keying on the address alone would let one tenant behind a
        # shared egress IP exhaust another tenant's budget.
        identifier = (request.headers.get('authorization')
                      or request.headers.get('x-api-key')
                      or (request.client.host if request.client else 'anonymous'))
        if not limiter.allow(identifier):
            return JSONResponse(
                status_code=429,
                content={'error': 'rate limit exceeded',
                         'retry_after_seconds': limiter.window_seconds,
                         'request_id': request_id},
                headers={'Retry-After': str(limiter.window_seconds),
                         'X-Request-Id': request_id})

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:                               # noqa: BLE001
            audit.record(action='api.error', outcome=Outcome.FAILURE,
                         resource=str(request.url.path),
                         detail={'request_id': request_id})
            # The exception text is not returned. It frequently contains a
            # query, a path or a driver message.
            return JSONResponse(
                status_code=500,
                content={'error': 'internal error', 'request_id': request_id},
                headers={'X-Request-Id': request_id})
        response.headers['X-Request-Id'] = request_id
        response.headers['X-Response-Time-Ms'] = '%.1f' % (
            (time.perf_counter() - started) * 1000)
        # Conservative defaults. The API serves JSON to programs, so it
        # should never be framed, sniffed or cached by an intermediary.
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.exception_handler(AccessDenied)
    async def _denied(request: Request, exc: AccessDenied):
        audit.record(action='api.denied', outcome=Outcome.DENIED,
                     resource=str(request.url.path),
                     detail={'permission': getattr(exc.permission, 'value',
                                                   str(exc.permission))})
        # The permission is named. Hiding which one was missing makes the API
        # unusable for a legitimate integrator and barely inconveniences an
        # attacker, who can enumerate by trying.
        return JSONResponse(status_code=403, content={
            'error': 'forbidden',
            'missing_permission': getattr(exc.permission, 'value',
                                          str(exc.permission))})

    @app.exception_handler(AuthError)
    async def _auth_failed(request: Request, exc: AuthError):
        return JSONResponse(status_code=401,
                            content={'error': 'authentication failed'})

    # --------------------------------------------------------- dependencies
    def current_principal(
            request: Request,
            authorization: str | None = Header(default=None),
            x_api_key: str | None = Header(default=None)) -> Principal:
        client_ip = request.client.host if request.client else None
        if x_api_key:
            try:
                return identity.principal_for_api_key(x_api_key, client_ip)
            except AuthError as exc:
                raise ApiError(401, 'invalid API key') from exc
        if authorization and authorization.lower().startswith('bearer '):
            try:
                return identity.principal_for_token(authorization[7:].strip(),
                                                    client_ip)
            except token_module.TokenExpired as exc:
                raise ApiError(401, 'token expired') from exc
            except (token_module.TokenError, AuthError) as exc:
                raise ApiError(401, 'invalid token') from exc
        raise ApiError(401, 'authentication required')

    def requires(permission: Permission):
        """Build a dependency enforcing one permission."""
        def guard(principal: Principal = Depends(current_principal)) -> Principal:
            principal.require(permission)
            return principal
        return guard

    def current_estate():
        provider = app.state.estate_provider
        if provider is None:
            raise ApiError(503, 'no estate is loaded')
        return provider()

    def respond(payload: dict, principal: Principal) -> dict:
        # The estate is passed so the redactor knows every name a crown jewel
        # goes by and can scrub it from text as well as from node records.
        # Without it, sentences such as finding titles carried the names to
        # roles that may not see them. When no estate is loaded there are no
        # crown jewels to name, so the response goes through node masking
        # alone rather than failing.
        provider = app.state.estate_provider
        estate = None
        if provider is not None and not principal.can(Permission.CROWN_REVEAL):
            estate = provider()
        return redact(payload, principal, salt=app.state.redaction_salt,
                      estate=estate)

    app.dependency_overrides_provider = None
    app.state.current_principal = current_principal
    app.state.requires = requires

    # ---------------------------------------------------------------- routes
    from .routes import register_routes
    register_routes(app, identity=identity, audit=audit,
                    current_principal=current_principal, requires=requires,
                    current_estate=current_estate, respond=respond,
                    settings=settings, db=db)
    return app
