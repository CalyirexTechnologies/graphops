# Contributing

```bash
make install     # venv with the API, Neo4j driver and test tooling
make test        # 383 tests
make lint        # ruff
```

## Things that will be asked in review

**A test named after what it prevents.** `test_alg_none_is_refused` says what
breaks if it fails. `test_token_validation` does not. For anything
security-relevant, write the test as the attack.

**A comment stating the rule, not the history.** Comments here explain why a
decision is what it is, especially where the obvious choice is wrong. They do
not record who made it or when.

**Nothing new imported into the core.** `graphops.analysis`,
`graphops.cli` and `graphops.connectors.*` run on the standard library, and
CI fails if that stops being true. The API and the Neo4j backend are optional
extras; keep third-party imports inside them, and import them lazily inside
functions where a core module needs one.

## Adding a connector

1. Subclass `Connector` (or `OutboundConnector`) in the right category module.
2. Declare `key`, `vendor`, `product`, `category`, `required_credentials` and
   `api_reference`. The API reference is checked by a test: a reviewer has to
   be able to compare your payload shape against the vendor's own docs.
3. Write `collect` with `self.request`, calling the vendor's documented
   endpoints in the documented order, with the documented authentication.
   Put any vendor host in `defaults` so regional and national clouds can
   override it. The same `collect` runs in replay and live mode; only the
   transport differs.
4. Write `transform` against the documented response shape, which you check
   against the vendor's documentation, not against your own recording.
5. Add a builder to `make_fixtures.py` that records the documented response
   to each call `collect` makes, and run `make fixtures`. Do not hand-write a
   fixture file: CI regenerates them and diffs, so a fixture nobody can
   regenerate fails the build.
6. Add the vendor's documented authentication to `SECRETS` in
   `tests/test_live_paths.py`, so the live path runs over real HTTP.
7. Register the class in `registry.CONNECTORS`.

Your fixture must fit the existing story rather than stand alone. The whole
point of the architecture is that the merged graph contains routes no single
source could show, and a fixture describing an unrelated company proves
nothing.

A recording that fits your parser proves only that the two agree with each
other. Until 5 November 2026 most of these connectors' recordings did, and
their live paths were wrong against the real APIs. Check the shape against
the vendor.

## Adding a route

Every route names the permission it needs in its own dependency list. There
is no "admin endpoints live under `/admin`" convention, because that
convention is one careless `include_router` away from being false.

`test_every_route_is_guarded` walks the route table and will fail on a route
with no principal dependency. If the route genuinely should be public, add it
to `PUBLIC_PATHS` in `api/app.py`, where the decision is visible.

## Adding a permission or a role

The matrix in `rbac/permissions.py` is data, and the tests assert properties
over all of it: that `viewer` stays a strict subset of `analyst`, that only
four roles may reveal crown jewels, that a service identity cannot read the
audit log. A change that breaks one of those should update the test
deliberately, in its own commit, with the reasoning in the message.

## Anything touching the audit log

The log is append-only. There is no `UPDATE` or `DELETE` path to
`audit_events` anywhere in the codebase and adding one will be rejected. If
you need to correct an entry, append a correcting entry.
