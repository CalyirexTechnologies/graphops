# Threat model

A tool that reads an organisation's security telemetry is a concentrated
target. It holds, in one place, the map an attacker would otherwise have to
build. This document says what that means and what the design does about it.

## What is being protected

| Asset | Why it matters |
|---|---|
| The estate graph | It is a complete map of how to reach the regulated data. More useful to an attacker than any single system it describes. |
| Crown jewel classification | Names which systems are worth taking. |
| Connector credentials | Read access to the SIEM, EDR, identity provider and cloud audit trail of the customer. |
| The audit log | The record of who looked at what. An attacker's first edit after a successful intrusion. |
| Signing key | Mints any token, for any user, in any tenant. |

## Who the adversaries are

**An outsider with no access.** Ordinary. Handled by authentication on every
route, which `test_every_route_is_guarded` enforces by walking the route
table rather than by listing endpoints.

**A legitimate low-privilege user.** The viewer who wants to know which
database holds the card data. This is the adversary the crown-jewel
redaction is for, and why `crown:reveal` is a separate permission from
`graph:read` rather than a property of seniority.

**A tenant trying to read another tenant.** Handled by scoping every query
to the principal's organization rather than to a parameter, and by answering
404 rather than 403 for another tenant's object, so the API does not confirm
it exists.

**An insider with database access.** Can rewrite the audit chain wholesale.
Nothing stored beside the data can prevent this, so `head()` is published for
anchoring elsewhere and `verify_chain(expected_head=...)` checks against it.
This is stated as a limitation rather than solved.

**A compromised connector.** A vendor API returning attacker-controlled
content. Every connector parses with the understanding that the payload is
hostile: a parse failure is caught per connector, the ingest continues
degraded, and node identifiers from a payload never become query fragments
because the engine holds an adjacency map rather than building Cypher by
string concatenation.

## Decisions and what they cost

**Deny by default in the RBAC matrix.** An unrecognised role grants nothing.
A role deleted from the matrix locks its holders out rather than failing
open. Cost: removing a role is a user-visible outage, which is correct.

**Separate `crown:reveal`.** Costs an extra permission to reason about. Buys
a viewer and an auditor role that are genuinely useful without being able to
name targets.

**Pseudonymisation rather than blanking.** A redacted crown jewel reads as
`crown-jewel-7f3a`, stable per tenant, HMAC-derived under a per-tenant salt.
Cost: a determined viewer can correlate a pseudonym with an out-of-band fact
and learn which node it is. Accepted, because blanking makes the viewer role
useless and the alternative is giving them the real name.

**Refresh-token reuse revokes the session.** A captured token is used twice:
once by the attacker and once by the real client. Detecting the second use
and revoking is the only point at which that theft is observable. Cost: a
client with a buggy retry logs its user out. Accepted.

**Rate limiting is in-process.** With N replicas the real limit is N times
the configured one. Stated in the module rather than hidden, because an
operator who believes otherwise will size it wrong. It protects the query
engine from a runaway script; abuse control belongs at the edge.

**No default signing key.** The process refuses to start without one. Cost:
one more step in every deployment. Buys the elimination of the single most
common path from demo to incident.

**Scrubbing before the audit write.** The audit log is the table most likely
to be shipped wholesale to a SIEM, so a secret reaching it has reached
everywhere. Known sensitive keys are replaced at any depth.

## What this design does not address

- **Denial of service.** Traversals are bounded by depth, node count and path
  count, and the bounds cannot be raised by a caller. That stops one query
  from being unbounded. It is not DoS protection.
- **Supply chain.** Dependencies are pinned and the core has none, but
  nothing here verifies what a vendor SDK does at runtime.
- **A compromised host.** The signing key is in the process's environment. An
  attacker with memory access to the process has it. Mitigating that needs an
  HSM or a KMS, which is a deployment decision rather than a code one.
- **Correctness of the customer's own classification.** If ServiceNow says a
  database is Public and it holds card data, every answer here is wrong in
  the same direction. `crown_source` records which source made the claim so
  that assumption is visible rather than buried.

## Reporting

See [SECURITY.md](SECURITY.md).
