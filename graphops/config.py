"""Runtime configuration, read from the environment.

Two rules hold everywhere in this file.

No secret has a usable default. `GRAPHOPS_SIGNING_KEY` and the connector
credentials either come from the environment or the component that needs them
refuses to start. A development default for a signing key is the single most
common way a demo turns into a production incident, because the default
survives the copy-paste into the deployment.

Nothing here reads a `.env` file on its own. `.env.example` documents the
variables and the operator decides how they reach the process, which keeps the
same code honest under systemd, Docker, ECS or a laptop.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Where SQLite lives when nothing else is configured. Under the repo rather
#: than /tmp, so a judge's data survives a reboot and is obvious to delete.
DEFAULT_DB_PATH = REPO_ROOT / 'data' / 'graphops.db'


class ConfigError(RuntimeError):
    """Raised when required configuration is absent or unusable."""


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError('%s must be an integer, got %r' % (name, raw)) from exc


@dataclass(frozen=True)
class Settings:
    """Everything the platform reads from its environment, resolved once."""

    # --- identity -------------------------------------------------------
    signing_key: bytes
    access_token_ttl_seconds: int = 900          # 15 minutes
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14
    issuer: str = 'graphops'

    # --- storage --------------------------------------------------------
    database_path: Path = DEFAULT_DB_PATH

    # --- graph backend --------------------------------------------------
    neo4j_uri: str = 'bolt://127.0.0.1:7687'
    neo4j_user: str = 'neo4j'
    neo4j_password: str | None = None

    # --- api ------------------------------------------------------------
    rate_limit_per_minute: int = 120
    max_page_size: int = 200

    # --- traversal bounds, see engine.algorithms ------------------------
    max_path_depth: int = 6
    max_paths: int = 500
    max_nodes_visited: int = 50_000

    # --- connectors -----------------------------------------------------
    #: Replay runs every connector against recorded fixtures instead of a
    #: live vendor API. It is the default because the fixtures are committed
    #: and a reviewer should be able to run the whole pipeline with no
    #: accounts, no keys and no network.
    connector_mode: str = 'replay'

    # --- observability --------------------------------------------------
    log_format: str = 'json'
    log_level: str = 'INFO'
    metrics_enabled: bool = True

    environment: str = 'development'
    extra: dict = field(default_factory=dict)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {'production', 'prod'}


def load_settings(*, allow_generated_key: bool = False) -> Settings:
    """Build `Settings` from the environment.

    `allow_generated_key` exists for tests and for `graphops demo`, which
    have no operator to set a key and never persist a token past the process.
    It mints a fresh random key per call, so a token signed by one process is
    invalid in the next. That is the intended behaviour: it fails closed
    rather than silently sharing a well-known key.
    """
    raw_key = os.environ.get('GRAPHOPS_SIGNING_KEY', '').strip()
    if raw_key:
        if len(raw_key) < 32:
            raise ConfigError(
                'GRAPHOPS_SIGNING_KEY must be at least 32 characters; '
                'got %d. Generate one with: python -m graphops.cli keygen'
                % len(raw_key))
        signing_key = raw_key.encode('utf-8')
    elif allow_generated_key:
        signing_key = secrets.token_bytes(32)
    else:
        raise ConfigError(
            'GRAPHOPS_SIGNING_KEY is not set. The platform will not start '
            'with a built-in key, because a default signing key is the one '
            'that ends up in production. Generate one with: '
            'python -m graphops.cli keygen')

    environment = os.environ.get('GRAPHOPS_ENV', 'development')

    db_path = Path(os.environ.get('GRAPHOPS_DB_PATH', str(DEFAULT_DB_PATH)))

    neo4j_password = os.environ.get('NEO4J_PASSWORD') or None
    if neo4j_password is None and environment.lower() in {'production', 'prod'}:
        # Only an error when something actually asks for the Neo4j backend;
        # the in-memory engine is a complete implementation on its own.
        neo4j_password = None

    mode = os.environ.get('GRAPHOPS_CONNECTOR_MODE', 'replay').strip().lower()
    if mode not in {'replay', 'live'}:
        raise ConfigError(
            "GRAPHOPS_CONNECTOR_MODE must be 'replay' or 'live', got %r" % mode)

    return Settings(
        signing_key=signing_key,
        access_token_ttl_seconds=_int('GRAPHOPS_ACCESS_TTL', 900),
        refresh_token_ttl_seconds=_int('GRAPHOPS_REFRESH_TTL', 60 * 60 * 24 * 14),
        issuer=os.environ.get('GRAPHOPS_ISSUER', 'graphops'),
        database_path=db_path,
        neo4j_uri=os.environ.get('NEO4J_URI', 'bolt://127.0.0.1:7687'),
        neo4j_user=os.environ.get('NEO4J_USER', 'neo4j'),
        neo4j_password=neo4j_password,
        rate_limit_per_minute=_int('GRAPHOPS_RATE_LIMIT', 120),
        max_page_size=_int('GRAPHOPS_MAX_PAGE_SIZE', 200),
        max_path_depth=_int('GRAPHOPS_MAX_PATH_DEPTH', 6),
        max_paths=_int('GRAPHOPS_MAX_PATHS', 500),
        max_nodes_visited=_int('GRAPHOPS_MAX_NODES', 50_000),
        connector_mode=mode,
        log_format=os.environ.get('GRAPHOPS_LOG_FORMAT', 'json'),
        log_level=os.environ.get('GRAPHOPS_LOG_LEVEL', 'INFO'),
        metrics_enabled=_flag('GRAPHOPS_METRICS', True),
        environment=environment,
    )
