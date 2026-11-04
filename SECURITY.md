# Security

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public
issue. Please include the version, what you did, what happened, and what you
expected. A working proof of concept helps and is not required.

## Properties this codebase tries to hold

Each of these has a test that fails if it stops being true. The test name is
given so the claim is checkable rather than asserted.

| Property | Test |
|---|---|
| No route is reachable without authentication | `test_every_route_is_guarded`, kept honest by `test_the_route_walk_actually_reaches_the_application_routes` |
| `alg: none` cannot forge a token | `test_alg_none_is_refused` |
| A token without `exp` is refused | `test_a_token_with_no_expiry_is_refused` |
| A refresh token cannot be used as an access token | `test_a_refresh_token_cannot_be_used_as_an_access_token` |
| Refresh reuse revokes the session | `test_a_refresh_token_rotates_and_reuse_revokes_the_session` |
| A revoked role does not survive a refresh | `test_roles_are_reread_on_refresh_not_carried_over` |
| A missing account and a wrong password are indistinguishable | `test_an_unknown_user_and_a_wrong_password_are_indistinguishable` |
| A TOTP code works once | `test_a_current_code_is_accepted_once` |
| An API key is not recoverable after creation | `test_an_api_key_is_not_recoverable_after_creation` |
| Impersonation cannot cross tenants | `test_impersonation_cannot_cross_tenants` |
| A tenant cannot read another tenant's audit log | `test_a_tenant_cannot_read_another_tenants_audit_log` |
| Another tenant's object answers 404, not 403 | `test_revoking_another_tenants_api_key_answers_404` |
| Crown jewel identities are withheld without `crown:reveal` | `test_a_viewer_gets_a_pseudonym_and_a_notice` |
| No route names a crown jewel to a role without `crown:reveal`, in any field or sentence | `test_no_route_names_a_crown_jewel_to_a_role_without_reveal`, which walks the route table and searches each whole response for every name a crown jewel goes by |
| Redaction reaches response shapes nobody anticipated | `test_redaction_reaches_a_shape_nobody_anticipated` |

Two rows above were not true until 4 November 2026, and both failures were
the same kind: a test that passed because it checked less than its name
claimed. The route-table walk skipped every application route, because this
FastAPI version nests included routers behind entries with no `path`. And
redaction masked crown jewel records but left their names in plain text, so
finding titles, compliance evidence and containment sentences named them to
auditors and viewers. Both are fixed and both now have a test that fails if
the fix is reverted.
| Secrets never reach the audit log | `test_secrets_never_reach_the_log` |
| Editing or deleting an audit entry is detected | `test_editing_an_entry_is_detected`, `test_deleting_an_entry_is_detected` |
| A compliance control is never reported satisfied | `test_a_control_is_never_reported_satisfied` |
| A CSV cell cannot carry a spreadsheet formula | `test_csv_neutralises_a_formula` |

## Configuration that is not optional

`GRAPHOPS_SIGNING_KEY` has no default and the process refuses to start
without it. Generate one with `graphops keygen`. A built-in development key
is the one that reaches production.

Connector credentials are named per connector and read from the environment.
Live mode refuses to start when any are missing; it never falls back to the
committed fixtures.

## Known limitations

Stated rather than quietly accepted. See [THREAT-MODEL.md](THREAT-MODEL.md)
for the reasoning.

- An insider with database access can rewrite the audit chain wholesale.
  Detecting that needs the head hash anchored outside the system.
- Rate limiting is per process. With N replicas the effective limit is N
  times the configured one.
- The signing key lives in the process environment. An attacker with memory
  access to the process has it.
- If the customer's CMDB misclassifies a system, every answer about that
  system is wrong in the same direction. `crown_source` records which source
  made the claim.

## Cryptography

| Purpose | Primitive | Why |
|---|---|---|
| Password hashing | `hashlib.scrypt`, N=2^15, r=8, p=1 | Memory-hard, RFC 7914, stdlib, no native build step. Parameters stored per hash, so raising them does not invalidate existing passwords. |
| Token signing | HMAC-SHA256 via `hmac` | Vetted stdlib primitive. Only the JOSE envelope is local code. |
| TOTP | HMAC-SHA1 via `hmac`, RFC 6238 | SHA-1 is what the RFC and every authenticator app implement. |
| API key storage | SHA-256 of the full key | The key is high-entropy random, so a slow hash buys nothing here. |
| Pseudonymisation | HMAC-SHA256 under a per-tenant salt | A bare hash of a low-entropy identifier is reversible by enumeration. |

Argon2id would be the better password choice. scrypt was taken because it
ships in the standard library and keeps the whole platform installable with
no compiler, which is a deliberate trade and is recorded here rather than
left for a reader to infer.
