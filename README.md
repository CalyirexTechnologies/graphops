# GraphOps

Security telemetry read as a graph, so a team can hunt before an incident
rather than reconstruct one afterwards.

Built for hackFront India, Cybersecurity theme, Neo4j Track.

It answers four questions. Which routes run from the internet to something
worth stealing, and where do they converge. What is in reach the moment a
system is taken. What is new, including routes where every single step looks
ordinary. And what access is held that nobody has ever used.

Around that sits the part that makes it a product rather than a script:
thirteen integrations, entity resolution across them, multi-tenant
authentication with role-based access control, a hash-chained audit log, a
REST API, and exports in four formats other tools already read.

---

## Run it

Nothing is installed and nothing is mocked. Every number below is printed by
the code.

```bash
python3 -m graphops.demo          # the engine, on the hand-authored estate
python3 -m graphops.cli ingest    # all 9 inbound connectors, then resolve
python3 -m graphops.cli analyse   # the findings those connectors produce
```

Those three need **no dependencies at all**. The engine and every connector
run on the standard library, which is enforced in CI by a job that imports
them on a clean interpreter and fails if anything outside the standard
library was pulled in.

The API and the Neo4j backend are optional extras:

```bash
make install                      # venv + fastapi + neo4j driver + pytest
export GRAPHOPS_SIGNING_KEY=$(python3 -m graphops.cli keygen)
.venv/bin/python -m graphops.cli bootstrap --slug acme --email you@acme.example
make serve                        # console at http://127.0.0.1:8000/
make test                         # 338 tests
```

`bootstrap` prints a generated owner password once. Sign in to the console
with `acme`, that email and that password. The console has ten screens
(overview, exposure, node detail, access, findings, connectors, compliance,
admin, profile and sign-in) and every number on them comes from the API:
nothing is sample data. It is plain scripts with no build step, served under
a content security policy that allows no inline script and no eval, and it
shows each role exactly what that role's permissions allow. An auditor sees
every route with the crown jewels pseudonymised. The API itself is at `/docs`.

Or the whole thing, API and Neo4j together:

```bash
export GRAPHOPS_SIGNING_KEY=$(python3 -m graphops.cli keygen)
export NEO4J_PASSWORD=<choose one>
docker compose up --build
```

There is no default signing key and the process refuses to start without
one. A built-in development key is the one that ends up in production.

---

## What it finds

Running the nine inbound connectors produces an estate of **35 entities and
47 relationships**, after **3 duplicate entities** are resolved across
sources. On it:

| Question | Answer |
|---|---|
| Routes from the internet to a crown jewel | 3 |
| Cheapest route | effort 2.0, a credential nobody watches, not a CVE |
| Busiest choke point | `support-desk`, on 2 of the 3 |
| Standing access granted, exercised, dormant | 9, 4, 5 |
| Dormant grants that reach regulated data | 4 |
| Findings produced | 8 |

The cheapest route is the one worth reading:

```
192.0.2.41  ->  svc-deploy  ->  s3://nightly-backups      effort 2.0
```

No single source could have found it. Splunk sees an address that has only
ever requested `/login` and that no rule fired on. CloudTrail sees that
address assume the `svc-deploy` role five hours ago. Okta says `svc-deploy`
was entitled to the backups all along and had never used it. Each record on
its own is unremarkable. Together they are a route from the internet to
every backup the company holds.

The second finding the multi-source graph produces and no single tool does:
`former-contractor`, **suspended in Okta**, is still entitled to the
PCI-classified billing database.

---

## Layers

```
  connectors/     13 integrations, replay or live   ->  nodes and edges
       |
  resolve.py      one entity under nine vendor names ->  one node
       |
  engine          vocab, algorithms, analysis
       |          bounded BFS, Dijkstra on effort, PageRank, Louvain
       |
  api/ + rbac/    auth, authorisation, redaction, audit
```

[ARCHITECTURE.md](ARCHITECTURE.md) has the reasoning for each layer.

---

## Integrations

Thirteen, in two directions. **Inbound** pulls telemetry and returns graph
deltas. **Outbound** pushes a finding to a ticket, a channel or a pager,
idempotently on a caller-supplied key.

| Category | Connector | Direction | What it contributes |
|---|---|---|---|
| SIEM | Splunk Enterprise Security | in | Perimeter requests and which rules fired |
| SIEM | Microsoft Sentinel | in | Incidents, and the address-to-account links in them |
| EDR | CrowdStrike Falcon | in | Alerts, and which account a host had in memory |
| Identity | Okta | in | Assignments, and **from the System Log, whether each was used** |
| Identity | Microsoft Entra ID | in | Directory roles and service principals |
| Cloud | AWS CloudTrail | in | Role assumption and resource reads |
| Vulnerability | Qualys VMDR | in | Host detections joined to the KnowledgeBase for CVEs and exploit intel |
| Vulnerability | Tenable Vulnerability Management | in | The same, from the vulnerability export API |
| CMDB | ServiceNow | in | **The only real source of a crown-jewel classification** |
| Ticketing | Jira | out | Opens an issue, deduplicated by label |
| Chat | Slack | out | Posts to a channel |
| Chat | Microsoft Teams | out | Posts an adaptive card |
| On-call | PagerDuty | out | Pages, but only for critical findings |

**Replay and live run the same code.** Every connector makes the same calls in
both modes, and only the transport differs. Live sends real HTTP. Replay
answers from a committed recording of the vendor's documented responses, so
the whole pipeline runs with **no vendor account, no API key and no network**,
and every replay exercises the live code. A request the recording does not hold
is an error rather than an empty answer, so the code and its recording cannot
drift apart quietly. Live mode refuses to start without its credentials rather
than falling back to the recording.

`tests/test_live_paths.py` runs every live path over real HTTP against a local
server that answers the recordings and checks each vendor's documented
authentication: SSWS for Okta, client-credential token exchanges for
CrowdStrike and Microsoft, Basic with `X-Requested-With` for Qualys, and
`X-ApiKeys` for Tenable. The live graph must equal the replay graph exactly.
CloudTrail is read from the log files a trail delivers to S3, after an
`aws s3 sync` of the bucket, so its live path keeps AWS signing in the AWS CLI.

**This was not true until 5 November 2026, and the gap was large.** Replay used
to hand each parser a fixture shaped to fit it, and the live code was separate
and had never run. Checked against each vendor's documentation, most of it was
wrong: CrowdStrike called the Detects API, which was decommissioned on 30
September 2025; Okta read a per-user `appAssignments[].lastSignOn` that no Okta
endpoint returns; Tenable's workbench has neither affected assets nor CVEs;
Sentinel's entities are a separate call; Splunk read a job list as results;
Qualys asked an XML API for JSON. Three connectors never exchanged their client
credentials for a token at all. All of it is rewritten against the documented
APIs, each cited on its connector as `api_reference`.

What this does not prove is that a real tenant answers exactly as documented.
The recordings are synthetic, checked against the documentation rather than
captured from anyone's tenant. Addresses come from the RFC 5737 documentation
ranges and route nowhere.

---

## Entity resolution

The layer that decides whether a multi-source graph works at all.

Okta calls the bucket `s3://nightly-backups`. CloudTrail calls it
`arn:aws:s3:::nightly-backups`. ServiceNow calls the card store
`billing-database` and classifies it PCI; Okta calls the same thing
`billing-database` but files it as an application, so it lands under a
different node id.

Left alone the graph holds two nodes for each. Okta's entitlement points at
one and ServiceNow's classification sits on the other, and the query that
should say *"support-desk can reach regulated data and has never used the
grant"* returns nothing. **The product looks like it works and quietly
answers the wrong question.** This was a real bug here, found by a test
asserting that an entitlement reaches a crown jewel.

So keys are normalised, nodes that normalise alike **and belong to the same
class** are merged, and edges are rewritten onto the survivor. Two guards
against over-merging, which is the worse failure: resolution happens only
within a class, so an identity called `backup` and a bucket called `backup`
are never joined; and the survivor is chosen by evidence, so a stated
classification beats a name heuristic. `resolved_from` records every id that
fed a node.

---

## The enterprise layer

| | |
|---|---|
| **Multi-tenancy** | Every query scoped to the principal's organization, never to a caller-supplied parameter. Another tenant's object answers 404, not 403. |
| **Authentication** | Password (scrypt) plus optional TOTP, account lockout, HS256 tokens, refresh rotation with reuse detection, API keys stored as hashes. |
| **Authorisation** | 7 roles, 21 permissions, a deny-by-default matrix held as data so the tests can assert properties over all of it. |
| **Graph-aware redaction** | `crown:reveal` is its own permission. Without it a crown jewel reads as `crown-jewel-7f3a`: stable per tenant, HMAC-derived, counts preserved. |
| **Audit** | Append-only and hash-chained. Editing or deleting an entry is detected and the first damaged row is named. Secrets scrubbed before the write. |
| **REST API** | 32 operations, OpenAPI at `/openapi.json`, Swagger at `/docs`. |
| **Exports** | STIX 2.1, SARIF 2.1.0, OSCAL assessment results, CSV. |
| **Compliance** | SOC 2, ISO 27001 and CIS controls assessed from graph evidence. |
| **Observability** | Prometheus metrics, structured logs, separate liveness and readiness. |
| **Deployment** | Multi-stage Dockerfile, non-root, read-only root filesystem, compose with Neo4j, six-job CI. |

### Two things in there worth singling out

**`crown:reveal` is a permission of its own.** Everything else in a security
product is read-or-write. This one splits reading a path from reading what
sits at the end of it. An auditor confirming that paths get reviewed does not
need to know which database holds the card data, and a viewer in a weekly
report meeting needs it even less. Who may see the target is the question an
attacker *inside the tool* most wants answered.

Redaction pseudonymises rather than blanks, so a viewer can still follow a
trend, and the response says plainly that it was redacted and which
permission would lift it. **Counts are never redacted** — "three routes reach
regulated data" is the number a viewer is there for.

The redactor walks the entire response rather than a list of known fields, so
a new endpoint returning node records is redacted before anyone remembers it
should be.

**A compliance control is never reported satisfied.** Only `not-satisfied`
or `not-assessed`. The graph can prove a control is contradicted; it cannot
prove one operates. A dashboard that goes green because it had no data is
worse than no dashboard, and `test_a_control_with_no_evidence_is_not_assessed`
fails if that ever changes.

---

## Neo4j

The engine was written against an adjacency map and never knew where its
nodes came from, so the same graph loads into Neo4j and the same questions
answer in plain Cypher.

```bash
make install
.venv/bin/python -m graphops.demo_neo4j     # runs both, compares them
```

Standalone queries are in [cypher/](cypher/) and run as they are in
`cypher-shell`. Plain Cypher, **no GDS and no APOC**, since neither ships
with Neo4j Community and a judge on a stock server would otherwise get
nothing.

That cross-check earned its place on its first run. Cypher reported thirteen
routes where the engine reported twelve, because two nodes can be joined by
both an entitlement and an observed use, and Neo4j walked each separately
while the engine collapsed them into one route. One of the two was wrong, and
a submission that only ever ran one engine would not have known which.

---

## Security properties, and the test for each

Every row has a test that fails if the property stops holding. The full table
is in [SECURITY.md](SECURITY.md); the reasoning and the limits are in
[THREAT-MODEL.md](THREAT-MODEL.md).

| Property | Test |
|---|---|
| No route is reachable without authentication | `test_every_route_is_guarded` |
| `alg: none` cannot forge a token | `test_alg_none_is_refused` |
| Refresh reuse revokes the whole session | `test_a_refresh_token_rotates_and_reuse_revokes_the_session` |
| A revoked role does not survive a refresh | `test_roles_are_reread_on_refresh_not_carried_over` |
| A missing account and a wrong password are indistinguishable | `test_an_unknown_user_and_a_wrong_password_are_indistinguishable` |
| Impersonation cannot cross tenants | `test_impersonation_cannot_cross_tenants` |
| Crown jewels are withheld without `crown:reveal` | `test_a_viewer_gets_a_pseudonym_and_a_notice` |
| Editing an audit entry is detected | `test_editing_an_entry_is_detected` |
| Secrets never reach the audit log | `test_secrets_never_reach_the_log` |
| A compliance control is never reported satisfied | `test_a_control_is_never_reported_satisfied` |

`test_every_route_is_guarded` walks the route table rather than listing
endpoints, so a route added next month is covered the day it is written.
Enumerating endpoints by hand is how an unauthenticated route reaches
production with a green suite.

**143 tests, 76% statement coverage.**

---

## The decisions worth defending

**Edges point the way an attacker travels, not the way the log reads.** A
cloud trail records that an identity acted from an address. An attacker
holding that address gains the use of the identity, so the edge is stored
address to identity. Stored as the log reads, every path search stops dead at
the first address. That is not hypothetical, it is what happened the first
time this was written.

**Paths are ranked by attacker effort, not hop count.** Reusing a credential
is cheaper than landing an exploit, and a shortest-path search that cannot
tell them apart routes the attacker through the hard step and calls that the
risk. On the sample estate every route is two hops, so hop count ranks them
all equally and effort separates 2.0 from 5.0. BloodHound CE paths on
unweighted hops, which is why tools like NoiseHound exist to put the weights
back.

**Vulnerability cost comes from exploit maturity, not CVSS.** A finding with
a known exploit in the wild is cheap; one with neither an exploit nor a proof
of concept is expensive, whatever its score. CVSS measures how bad it would
be, not how likely anyone is to do it, and a path search needs the second.

**Choke points are counted over enumerated paths, not as betweenness
centrality.** Betweenness scores a node against all shortest paths in the
graph, most of which start and end somewhere nobody cares about. The number a
defender can act on is "this is on two of the three ways in", and that is a
count. The idea is XM Cyber's and it is the best one in the field, that a
small fraction of exposures sit on choke points, which is the difference
between a remediation list a team can finish this week and one it never will.

**PageRank is read on the reversed graph, and external addresses are
dropped.** Importance flows along edges, and these edges point the way an
attacker travels, so running it forwards piles rank onto the crown jewels and
tells us what we already knew. Reversed, it accumulates on the nodes that
lead to valuable places. External addresses then score well because they
point at our surfaces, and ranking them is useless, because there is nothing
to harden about an address that is already hostile.

**Louvain here is the local-moving phase and is named that way.** Full
Louvain collapses each community into a node and repeats, which usually
changes the result on a large network. At the size one business's estate
reaches, the first phase already separates the clusters an analyst cares
about, and claiming the whole algorithm when half of it runs is a lie that is
easy to check.

**Every search is bounded.** Depth, node count and path count all have
ceilings a caller cannot raise. An unbounded traversal over a graph built from
attacker-influenced telemetry is a denial of service with extra steps, because
whoever can create nodes chooses how much CPU one analyst click costs.

**The vocabulary is small and every edge kind has a populating source.** The
idea comes from BloodHound 8.0's OpenGraph, that a fixed schema is what stops
a security graph growing, because the next data source always has an entity
the schema did not anticipate. There is deliberately no host-to-host logon
edge, because nothing in this telemetry would ever write one. A graph with
edges nobody populates is a demo rather than a tool.

**Each step carries its ATT&CK tactic.** "address to endpoint to asset" is
three hops. "Initial Access, Discovery, Lateral Movement" is an intrusion.
The mapping is per edge kind rather than per event, so it is a claim about
what that relationship means and not a guess about one event. A kind that
cannot be mapped honestly carries an empty technique rather than a
plausible-looking one.

**No dependency for the core, and the reason it stays true.** scrypt, HMAC
and the JOSE envelope are written against the standard library rather than
pulled from packages. The cryptographic primitives are stdlib and vetted;
only the envelope is local code, and the parts that are easy to get wrong
(`alg` allowlisting, required `exp`, constant-time comparison, token type
checking) are each covered by a test named after the attack it prevents.
Argon2id would be the better password choice; scrypt was taken because it
ships in the standard library. That trade is recorded in SECURITY.md rather
than left for a reader to infer.

---

## Layout

```
graphops/
  vocab.py            node and edge kinds, ATT&CK mapping, zones, costs
  algorithms.py       bounded BFS, Dijkstra, path enumeration, choke points,
                      PageRank, Louvain local moving, connected components
  analysis.py         the seven questions
  estate.py           the hand-authored synthetic business
  findings.py         answers -> findings, with stable fingerprints
  neo4j_store.py      the same graph in Neo4j, queried in Cypher
  cli.py              keygen, bootstrap, ingest, analyse, export, serve
  config.py           environment only, and no secret has a default
  connectors/         13 integrations, the registry, entity resolution,
                      and the fixture generator
  identity/           scrypt, JWT, TOTP, sign-in, API keys, impersonation
  rbac/               permissions, roles, principals, crown-jewel redaction
  audit/              the hash-chained append-only log
  api/                FastAPI app, routes, schemas, rate limiting
  exporters/          STIX, SARIF, OSCAL, CSV
  compliance/         SOC 2, ISO 27001, CIS controls and assessment
  observability/      Prometheus metrics
  store/              SQLite with forward-only migrations
cypher/               the five queries as standalone files
tests/                143 tests
viewer/index.html     the picture, no build step and no dependencies
```

52 Python files, about 7,100 lines, plus 1,270 lines of tests.

---

## The data is invented

`data/estate.json` and every connector fixture describe a business that does
not exist. Addresses come from the ranges RFC 5737 reserves for documentation
and route nowhere. The estate is hand-authored rather than randomly
generated, because the numbers in the write-up have to be the numbers you get
when you run it, and because a random graph does not reliably contain the
situations worth showing.

## What is not in this package

The engine, the connectors and the platform around them ship complete. What
is left out is the multi-tenant storage layer and the collectors from our own
product, which project live telemetry into nodes and edges in production.
`Estate.from_file`, the connector fixtures and `neo4j_store` stand in for
those. The engine never knew where its nodes came from, which is why swapping
the source changes nothing below it.

## Licence

MIT. See [LICENSE](LICENSE).
