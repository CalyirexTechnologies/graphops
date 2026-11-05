"""SQLite storage with forward-only, versioned migrations.

SQLite rather than Postgres so the platform starts with no server to install,
and behind a narrow enough surface that swapping it is a day's work: every
statement is ordinary SQL, there is no ORM, and nothing depends on a SQLite
extension. `PRAGMA journal_mode=WAL` and `foreign_keys=ON` are set on every
connection, the second because SQLite silently ignores foreign keys unless
you ask, which turns a schema full of REFERENCES clauses into decoration.

Migrations are a list of (version, sql) pairs applied in order inside one
transaction each, with the applied version recorded. They never run
backwards. A rollback is a restore, which is the honest position for a
system holding an append-only audit chain.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

#: Bumped whenever MIGRATIONS grows. Asserted in the test suite so a
#: migration added without a version bump fails CI rather than production.
SCHEMA_VERSION = 6

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
    CREATE TABLE organizations (
        id              TEXT PRIMARY KEY,
        slug            TEXT NOT NULL UNIQUE,
        name            TEXT NOT NULL,
        created_at      INTEGER NOT NULL,
        is_active       INTEGER NOT NULL DEFAULT 1,
        -- Where this tenant's data may be stored. Read by the connector
        -- layer before a cross-region call, not merely recorded.
        data_residency  TEXT NOT NULL DEFAULT 'global',
        retention_days  INTEGER NOT NULL DEFAULT 365
    );

    CREATE TABLE users (
        id                  TEXT PRIMARY KEY,
        organization_id     TEXT NOT NULL REFERENCES organizations(id),
        email               TEXT NOT NULL,
        password_hash       TEXT NOT NULL,
        display_name        TEXT NOT NULL DEFAULT '',
        is_active           INTEGER NOT NULL DEFAULT 1,
        mfa_secret          TEXT,
        mfa_enabled         INTEGER NOT NULL DEFAULT 0,
        mfa_last_counter    INTEGER,
        failed_attempts     INTEGER NOT NULL DEFAULT 0,
        locked_until        INTEGER,
        created_at          INTEGER NOT NULL,
        last_login_at       INTEGER,
        -- Email is unique per tenant, not globally. The same person may hold
        -- an account in two organizations, and a global unique constraint
        -- would leak that one exists when the other tries to register.
        UNIQUE (organization_id, email)
    );

    CREATE TABLE user_roles (
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role        TEXT NOT NULL,
        granted_at  INTEGER NOT NULL,
        granted_by  TEXT,
        PRIMARY KEY (user_id, role)
    );

    CREATE INDEX idx_users_org ON users(organization_id);
    """),

    (2, """
    CREATE TABLE api_keys (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations(id),
        name            TEXT NOT NULL,
        prefix          TEXT NOT NULL UNIQUE,
        key_hash        TEXT NOT NULL,
        roles           TEXT NOT NULL DEFAULT '',
        created_by      TEXT REFERENCES users(id),
        created_at      INTEGER NOT NULL,
        expires_at      INTEGER,
        last_used_at    INTEGER,
        revoked_at      INTEGER
    );

    CREATE TABLE sessions (
        id              TEXT PRIMARY KEY,
        user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        organization_id TEXT NOT NULL REFERENCES organizations(id),
        created_at      INTEGER NOT NULL,
        expires_at      INTEGER NOT NULL,
        revoked_at      INTEGER,
        client_ip       TEXT,
        user_agent      TEXT
    );

    -- Denylist, not an allowlist. Access tokens are short-lived and checked
    -- by signature; this table exists so logout and key revocation take
    -- effect before a token's own expiry.
    CREATE TABLE revoked_tokens (
        jti         TEXT PRIMARY KEY,
        expires_at  INTEGER NOT NULL,
        revoked_at  INTEGER NOT NULL,
        reason      TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX idx_sessions_user ON sessions(user_id);
    CREATE INDEX idx_revoked_expiry ON revoked_tokens(expires_at);
    """),

    (3, """
    -- Append-only. There is deliberately no UPDATE or DELETE path to this
    -- table anywhere in the codebase; see graphops/audit/chain.py for the
    -- hash chain that makes a silent edit detectable.
    CREATE TABLE audit_events (
        seq             INTEGER PRIMARY KEY AUTOINCREMENT,
        id              TEXT NOT NULL UNIQUE,
        organization_id TEXT,
        actor_id        TEXT,
        actor_kind      TEXT NOT NULL DEFAULT 'user',
        on_behalf_of    TEXT,
        action          TEXT NOT NULL,
        resource        TEXT NOT NULL DEFAULT '',
        outcome         TEXT NOT NULL,
        client_ip       TEXT,
        detail          TEXT NOT NULL DEFAULT '{}',
        occurred_at     INTEGER NOT NULL,
        previous_hash   TEXT NOT NULL,
        entry_hash      TEXT NOT NULL
    );

    CREATE INDEX idx_audit_org_time ON audit_events(organization_id, occurred_at);
    CREATE INDEX idx_audit_action ON audit_events(action);
    """),

    (4, """
    CREATE TABLE connector_runs (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations(id),
        connector       TEXT NOT NULL,
        mode            TEXT NOT NULL,
        started_at      INTEGER NOT NULL,
        finished_at     INTEGER,
        status          TEXT NOT NULL,
        nodes_ingested  INTEGER NOT NULL DEFAULT 0,
        edges_ingested  INTEGER NOT NULL DEFAULT 0,
        error           TEXT
    );

    CREATE TABLE findings (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations(id),
        kind            TEXT NOT NULL,
        severity        TEXT NOT NULL,
        title           TEXT NOT NULL,
        detail          TEXT NOT NULL DEFAULT '{}',
        status          TEXT NOT NULL DEFAULT 'open',
        assigned_to     TEXT REFERENCES users(id),
        first_seen      INTEGER NOT NULL,
        last_seen       INTEGER NOT NULL,
        -- Stable across runs so the same structural problem does not open a
        -- new finding every ingest. See findings.fingerprint().
        fingerprint     TEXT NOT NULL,
        UNIQUE (organization_id, fingerprint)
    );

    CREATE TABLE webhooks (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations(id),
        url             TEXT NOT NULL,
        secret          TEXT NOT NULL,
        events          TEXT NOT NULL DEFAULT '',
        is_active       INTEGER NOT NULL DEFAULT 1,
        created_at      INTEGER NOT NULL,
        last_status     INTEGER,
        last_attempt_at INTEGER
    );

    CREATE INDEX idx_runs_org ON connector_runs(organization_id, started_at);
    CREATE INDEX idx_findings_org ON findings(organization_id, status, severity);
    """),

    # Additive only: new tables and new nullable or defaulted columns, so the
    # previous release runs unchanged against a database migrated to this.
    (5, """
    -- One row per ingest. Before this, running ingest threw its own result
    -- away and the console had no "last ingest" to show. organization_id is
    -- nullable because the ingest a server runs at startup belongs to no
    -- tenant; it is what every tenant sees until it runs one of its own.
    CREATE TABLE ingests (
        id                  TEXT PRIMARY KEY,
        organization_id     TEXT REFERENCES organizations(id),
        actor_id            TEXT,
        mode                TEXT NOT NULL,
        status              TEXT NOT NULL,
        started_at          INTEGER NOT NULL,
        finished_at         INTEGER NOT NULL,
        as_of               TEXT,
        connectors_run      INTEGER NOT NULL DEFAULT 0,
        connectors_failed   INTEGER NOT NULL DEFAULT 0,
        merged              INTEGER NOT NULL DEFAULT 0,
        entities            INTEGER NOT NULL DEFAULT 0,
        relationships       INTEGER NOT NULL DEFAULT 0,
        -- Each connector's result for this ingest, as JSON. Kept on the row
        -- rather than in connector_runs, whose organization_id is NOT NULL
        -- and so cannot hold the startup ingest that belongs to no tenant.
        runs                TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX idx_ingests_org ON ingests(organization_id, finished_at);

    -- A tenant saying which systems matter, over what its sources said.
    -- One row per node, the latest decision, with who made it and why. The
    -- history is in the audit log.
    CREATE TABLE crown_overrides (
        organization_id     TEXT NOT NULL REFERENCES organizations(id),
        node_id             TEXT NOT NULL,
        crown               INTEGER NOT NULL,
        reason              TEXT NOT NULL DEFAULT '',
        set_by              TEXT,
        set_at              INTEGER NOT NULL,
        PRIMARY KEY (organization_id, node_id)
    );

    -- Failed sign-ins for addresses with no account. Counted exactly as a
    -- real account's are, so that a lockout cannot be used to learn which
    -- addresses have accounts: without this, five tries at a real address
    -- lock it and five at a made-up one never do.
    CREATE TABLE login_failures (
        organization_id     TEXT NOT NULL,
        email               TEXT NOT NULL,
        failed_attempts     INTEGER NOT NULL DEFAULT 0,
        locked_until        INTEGER,
        PRIMARY KEY (organization_id, email)
    );

    -- When a finding stopped being true. A fix that worked is a finding that
    -- resolves on the next ingest, and saying so closes the loop.
    ALTER TABLE findings ADD COLUMN resolved_at INTEGER;
    """),

    (6, """
    -- The estate each tenant is served, and the ingest it was built from.
    -- Held only in memory before this, so a restart handed every tenant the
    -- server's startup estate while the console still labelled it with the
    -- tenant's own last ingest: a live ingest could come back as replay data
    -- under the live run's name. One row per tenant, the estate currently
    -- served; the ingests table keeps the history.
    CREATE TABLE served_estates (
        organization_id     TEXT PRIMARY KEY REFERENCES organizations(id),
        ingest_id           TEXT NOT NULL,
        payload             TEXT NOT NULL,
        stored_at           INTEGER NOT NULL
    );
    """),
]


class Database:
    """A thread-safe handle to one SQLite file."""

    def __init__(self, path: str | Path = ':memory:'):
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ':memory:':
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False with an explicit RLock around every write:
        # the API serves concurrent requests and SQLite's own thread check
        # would reject them, while the lock keeps writes serialised.
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._configure()
        self.migrate()

    def _configure(self) -> None:
        cur = self._connection.cursor()
        # Without this SQLite accepts every REFERENCES clause and enforces none.
        cur.execute('PRAGMA foreign_keys = ON')
        if self.path != ':memory:':
            cur.execute('PRAGMA journal_mode = WAL')
        cur.execute('PRAGMA synchronous = NORMAL')
        cur.execute('PRAGMA busy_timeout = 5000')
        self._connection.commit()

    # ------------------------------------------------------------ migrations
    def _applied_version(self) -> int:
        cur = self._connection.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                           version    INTEGER PRIMARY KEY,
                           applied_at INTEGER NOT NULL)""")
        self._connection.commit()
        cur.execute('SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations')
        return int(cur.fetchone()['v'])

    def migrate(self) -> int:
        """Apply every migration newer than the recorded version."""
        import time as _time
        with self._lock:
            current = self._applied_version()
            for version, sql in MIGRATIONS:
                if version <= current:
                    continue
                cur = self._connection.cursor()
                try:
                    cur.executescript(sql)
                    cur.execute('INSERT INTO schema_migrations (version, applied_at)'
                                ' VALUES (?, ?)', (version, int(_time.time())))
                    self._connection.commit()
                except Exception:
                    self._connection.rollback()
                    raise
                current = version
            return current

    # ----------------------------------------------------------------- access
    @contextmanager
    def write(self):
        """A serialised write transaction. Commits on success, rolls back on error."""
        with self._lock:
            cur = self._connection.cursor()
            try:
                yield cur
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
            finally:
                cur.close()

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._connection.cursor()
            try:
                cur.execute(sql, params)
                return cur.fetchall()
            finally:
                cur.close()

    def query_one(self, sql: str, params: tuple = ()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._connection.close()
