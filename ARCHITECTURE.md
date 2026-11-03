# Architecture

Four layers. Each one knows only about the layer beneath it, which is what
lets a thirteenth connector be added without touching the engine, the API or
the viewer.

```
  connectors/        vendor payloads  ->  nodes and edges
       |             13 integrations, replay or live
       v
  resolve.py         the same entity under nine different names -> one node
       |
       v
  engine             vocab, algorithms, analysis
       |             bounded BFS, Dijkstra on effort, PageRank, Louvain
       v
  api/ + rbac/       authentication, authorisation, redaction, audit
```

## The engine

`vocab.py` fixes the vocabulary: seven node kinds, seven edge kinds, a zone
per node and a MITRE ATT&CK tactic per edge kind. It is deliberately small.
The idea is BloodHound 8.0's OpenGraph, that a fixed schema is what stops a
security graph growing, because the next data source always has an entity the
schema did not anticipate. There is no host-to-host logon edge, because
nothing in this telemetry would populate one.

`algorithms.py` is a graph library with no security knowledge: bounded BFS,
Dijkstra over edge cost, path enumeration, choke-point counting, PageRank,
Louvain local moving, connected components. Every traversal is bounded by
depth, visited-node count and path count, and a caller cannot raise the
bounds. An unbounded traversal over a graph built from attacker-influenced
telemetry is a denial of service with extra steps.

`analysis.py` asks the seven questions in security terms and returns answers
shaped for a consumer: routes with their tactics, a blast radius by hop,
structural novelty, standing access against observed use.

**Edges point the way an attacker travels, not the way the log reads.** A
cloud trail records that an identity acted from an address. An attacker
holding that address gains the use of the identity, so the edge runs address
to identity. Written as the log reads, every path search stops dead at the
first address. That was the first bug in this engine.

**Paths rank by attacker effort, not hop count.** Reusing a credential is
cheaper than landing an exploit. On the sample estate every route is two
hops, so hop count ranks them all equally and effort separates 2.0 from 5.0.

## Connectors

A connector is the only component that knows a vendor's payload shape. Two
directions, because they fail differently: **inbound** pulls telemetry and
returns a `GraphDelta`; **outbound** pushes a finding to a ticket, a channel
or a pager, idempotently on a caller-supplied key.

Two modes. **Replay** reads a committed fixture, which is the default and is
how the tests and the demo run: no vendor account, no key, no network.
**Live** issues the real call and refuses to start without its credentials
rather than falling back to the fixture, because a connector quietly serving
yesterday's data on an expired token is worse than one that fails.

One connector failing does not fail the ingest. The run is marked degraded
and the estate is built from whatever arrived.

| Category | Connectors |
|---|---|
| SIEM | Splunk Enterprise Security, Microsoft Sentinel |
| EDR | CrowdStrike Falcon |
| Identity provider | Okta, Microsoft Entra ID |
| Cloud audit | AWS CloudTrail |
| Vulnerability | Qualys VMDR, Tenable.io |
| CMDB | ServiceNow |
| Ticketing and chat | Jira, Slack, Microsoft Teams, PagerDuty |

## Entity resolution

The layer that decides whether a multi-source graph works at all.

Okta calls the bucket `s3://nightly-backups`, CloudTrail calls it
`arn:aws:s3:::nightly-backups`. ServiceNow calls the card store
`billing-database` and classifies it PCI; Okta calls the same thing
`billing-database` but files it as an application, so it lands under a
different node id. Left alone the graph holds two nodes for each, Okta's
entitlement points at one and ServiceNow's classification sits on the other,
and the query that should say "support-desk can reach regulated data and
never has" returns nothing. The product looks like it works and answers the
wrong question.

So keys are normalised, nodes that normalise alike **and belong to the same
class** are merged, and edges are rewritten onto the survivor. Resolution
within a class only: an identity called `backup` and a bucket called `backup`
are never joined. The survivor is chosen by evidence, and `resolved_from`
records every id that fed it.

## Identity and authorisation

Sign-in is password plus optional TOTP, with lockout, and the password branch
is written so a missing account and a wrong password cost comparable time.

Tokens are HS256 JWTs. The HMAC is `hmac`/`hashlib`; what this codebase adds
is the JOSE envelope, with `alg` checked against an allowlist of one before
anything else, `exp` required, and `typ` checked so a refresh token cannot be
replayed at an endpoint expecting an access token.

Refresh tokens rotate, and a token presented twice revokes the whole session.
Roles are re-read on refresh rather than carried from the old token, so a
revoked role takes effect at the next refresh.

RBAC is a data table, not code, which lets the test suite assert properties
over the whole matrix. Deny by default, no wildcards, no inheritance.

**`crown:reveal` is its own permission.** Everything else is read-or-write;
this one splits reading a path from reading what sits at the end of it. An
auditor confirming paths are reviewed does not need to know which database
holds the card data. A viewer gets `crown-jewel-7f3a` instead: stable per
tenant, HMAC-derived, with the response saying plainly that it was redacted
and which permission would lift it. Counts are never redacted.

The redactor walks the whole response rather than a list of known fields, so
a new endpoint returning node records is redacted before anyone remembers it
should be.

## Audit

Append-only, hash-chained. Each entry stores the hash of its predecessor and
its own hash covers both content and link, so editing or removing an entry
breaks every hash after it and `verify_chain` names the first damaged row.

The head is read and the row inserted inside one transaction. Computing the
hash outside it would let two concurrent writers chain off one predecessor
and fork the chain.

What it does not do: stop a writer with database access from rewriting the
chain from the edited point forward. Nothing stored beside the data can.
`head()` exists so a deployment can publish it somewhere append-only, and
`verify_chain(expected_head=...)` checks against that.

## Storage

SQLite behind a narrow enough surface to swap: plain SQL, no ORM, no SQLite
extension. Forward-only versioned migrations, applied in one transaction
each. `PRAGMA foreign_keys = ON` on every connection, because SQLite
otherwise ignores every REFERENCES clause and the schema becomes decoration.

## Graph backends

The engine was written against an adjacency map and never knew where its
nodes came from, so the same graph loads into Neo4j and the same questions
answer in plain Cypher. `demo_neo4j` runs both and compares them question by
question.

That check earned its place on its first run: Cypher reported thirteen routes
where the engine reported twelve, because two nodes can be joined by both an
entitlement and an observed use, and Neo4j walked each separately while the
engine collapsed them. One of the two was wrong, and a submission that only
ever ran one engine would not have known which.

No GDS and no APOC. Neither ships with Neo4j Community, and a reviewer on a
stock server would get nothing.
