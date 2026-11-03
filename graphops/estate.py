"""A synthetic estate for a mid-sized business, used to demonstrate the engine.

EVERYTHING HERE IS INVENTED. No customer, no real host and no real address
appears. The addresses are drawn from the ranges RFC 5737 reserves for
documentation, so none of them can route anywhere. The company does not
exist.

It is hand-authored rather than randomly generated, for two reasons. The
numbers in the write-up have to be the numbers a judge gets when they run
it, and a random graph does not reliably contain the three situations worth
showing. Those are:

  1. Many ways in that converge on a few nodes, so choke points mean
     something. Closing one endpoint here removes more routes than patching
     any single vulnerability.
  2. A crown jewel reachable by two unrelated route families, one through a
     web surface and one through a cloud credential, so the cheapest route
     is not the obvious one.
  3. A brand new route that no detection rule fired on, next to a noisy
     scanner that every rule caught. That contrast is the whole argument
     for structural detection.
"""
from datetime import datetime, timedelta, timezone

from .vocab import EdgeKind, NodeKind, Zone

# A fixed reference point, so a judge running this next month gets the same
# answers as the write-up. Everything is expressed relative to it.
GENERATED = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)

_OLD = GENERATED - timedelta(days=40)       # long-standing
_RECENT = GENERATED - timedelta(days=6)     # established, outside the window
_NEW = GENERATED - timedelta(hours=5)       # inside the 24h window


def _node(nid, kind, key, zone, label=None, crown=False):
    return {'id': nid, 'kind': kind, 'key': key, 'zone': zone,
            'label': label or key, 'crown': crown}


def build():
    """Return the estate payload, ready to serialise."""
    nodes = []
    edges = []

    def edge(src, dst, kind, first_seen, cost=None):
        from .vocab import DEFAULT_COST
        edges.append({'src': src, 'dst': dst, 'kind': kind,
                      'cost': float(cost if cost is not None
                                    else DEFAULT_COST.get(kind, 1.0)),
                      'first_seen': first_seen.isoformat()})

    # ---------------------------------------------------------- the internet
    # Six sources. Five are ordinary background noise and scanning. The sixth
    # is quiet, and is the one that matters.
    scanners = [
        ('ip-scan-1', '198.51.100.21'),
        ('ip-scan-2', '198.51.100.84'),
        ('ip-scan-3', '203.0.113.9'),
        ('ip-scan-4', '203.0.113.77'),
        ('ip-bruteforce', '192.0.2.133'),
    ]
    for nid, key in scanners:
        nodes.append(_node(nid, NodeKind.ADDRESS, key, Zone.UNTRUSTED))
    nodes.append(_node('ip-quiet', NodeKind.ADDRESS, '192.0.2.41',
                       Zone.UNTRUSTED, label='192.0.2.41 (no rule has fired)'))

    # ------------------------------------------------------ what faces them
    endpoints = [
        ('ep-login', '/login'),
        ('ep-orders', '/api/orders'),
        ('ep-upload', '/api/uploads'),
        ('ep-admin', '/admin'),
        ('ep-webhook', '/webhook/payments'),
    ]
    for nid, key in endpoints:
        nodes.append(_node(nid, NodeKind.ENDPOINT, key, Zone.PERIMETER))

    # --------------------------------------------------------- what is behind
    nodes += [
        _node('asset-web', NodeKind.ASSET, 'storefront-web', Zone.INTERNAL),
        _node('asset-orders', NodeKind.ASSET, 'order-service', Zone.INTERNAL),
        _node('asset-files', NodeKind.ASSET, 'file-store', Zone.INTERNAL),
        # The ones an attacker is actually after. Everything above is a way
        # of getting here, which is what makes these the path targets.
        _node('asset-billing', NodeKind.ASSET, 'billing-database',
              Zone.CROWN, label='billing-database (card data)', crown=True),
        _node('asset-hr', NodeKind.ASSET, 'hr-database',
              Zone.CROWN, label='hr-database (employee records)', crown=True),
    ]

    # Cloud services, reached with a credential rather than through a URL.
    nodes += [
        _node('svc-iam', NodeKind.SERVICE, 'iam', Zone.INTERNAL),
        _node('svc-backups', NodeKind.SERVICE, 's3://nightly-backups',
              Zone.CROWN, label='s3://nightly-backups (everything, nightly)',
              crown=True),
    ]

    # Identities. Two service accounts and two people.
    nodes += [
        _node('id-deploy', NodeKind.IDENTITY, 'svc-deploy', Zone.INTERNAL),
        _node('id-backup', NodeKind.IDENTITY, 'svc-backup', Zone.INTERNAL),
        _node('id-finance', NodeKind.IDENTITY, 'finance-admin', Zone.INTERNAL),
        _node('id-support', NodeKind.IDENTITY, 'support-desk', Zone.INTERNAL),
    ]

    # Known weaknesses. These are the list a scanner produces, and on their
    # own they are the list nobody can finish.
    vulns = [
        ('cve-upload', 'CVE-2026-1188 (file-store, unauthenticated upload)', 'asset-files'),
        ('cve-orders', 'CVE-2026-0442 (order-service, deserialisation)', 'asset-orders'),
        ('cve-web', 'CVE-2025-9910 (storefront-web, outdated TLS library)', 'asset-web'),
    ]
    for nid, key, _owner in vulns:
        nodes.append(_node(nid, NodeKind.VULNERABILITY, key, Zone.INTERNAL))

    # Detection rules that have fired.
    nodes += [
        _node('rule-bruteforce', NodeKind.RULE, 'repeated-auth-failure', Zone.INTERNAL),
        _node('rule-scan', NodeKind.RULE, 'path-enumeration', Zone.INTERNAL),
    ]

    # ------------------------------------------------------------- the edges
    # Scanners reach the public surfaces. This is the ordinary background.
    for nid, _ in scanners:
        edge(nid, 'ep-login', EdgeKind.REQUESTED, _OLD)
        edge(nid, 'ep-orders', EdgeKind.REQUESTED, _OLD)
    for nid in ('ip-scan-1', 'ip-scan-3', 'ip-bruteforce'):
        edge(nid, 'ep-admin', EdgeKind.REQUESTED, _OLD)
    for nid in ('ip-scan-2', 'ip-scan-4'):
        edge(nid, 'ep-upload', EdgeKind.REQUESTED, _RECENT)

    # The quiet address has only ever done something unremarkable.
    edge('ip-quiet', 'ep-login', EdgeKind.REQUESTED, _OLD)

    # Rules fired on the loud ones, and on nothing else.
    edge('ip-bruteforce', 'rule-bruteforce', EdgeKind.TRIPPED, _RECENT)
    edge('ip-scan-1', 'rule-scan', EdgeKind.TRIPPED, _RECENT)
    edge('ip-scan-3', 'rule-scan', EdgeKind.TRIPPED, _OLD)

    # Surfaces sit in front of systems. These are the convergence points.
    edge('ep-login', 'asset-web', EdgeKind.SERVES, _OLD)
    edge('ep-orders', 'asset-orders', EdgeKind.SERVES, _OLD)
    edge('ep-upload', 'asset-files', EdgeKind.SERVES, _OLD)
    edge('ep-admin', 'asset-billing', EdgeKind.SERVES, _OLD)
    edge('ep-webhook', 'asset-billing', EdgeKind.SERVES, _OLD)

    # The order service reads the billing database, which is why a bug in the
    # order tier is a card-data problem and not a web problem.
    edge('ep-orders', 'asset-billing', EdgeKind.SERVES, _RECENT)

    # Known weaknesses hang off the systems that carry them.
    for nid, _key, owner in vulns:
        edge(owner, nid, EdgeKind.EXPOSES, _OLD)

    # Credentials. An address that controls one gains the use of it.
    edge('ip-bruteforce', 'id-support', EdgeKind.YIELDS, _RECENT)
    edge('ip-scan-4', 'id-finance', EdgeKind.YIELDS, _RECENT)

    # What those identities can do.
    edge('id-support', 'svc-iam', EdgeKind.CALLED, _OLD)
    edge('id-finance', 'asset-hr', EdgeKind.SERVES, _OLD, cost=2.0)
    edge('id-deploy', 'svc-iam', EdgeKind.CALLED, _OLD)
    edge('id-backup', 'svc-backups', EdgeKind.CALLED, _OLD)

    # ------------------------------------------------- what policy ALLOWS
    # Entitlements, read from the identity provider rather than from logs.
    # Three of these are exercised above and three are not. The unexercised
    # ones are the over-privilege a zero-trust review is looking for, and
    # they are live attack steps whether or not anyone has ever used them.
    edge('id-support', 'svc-iam', EdgeKind.ENTITLED, _OLD)        # used
    edge('id-backup', 'svc-backups', EdgeKind.ENTITLED, _OLD)     # used
    edge('id-deploy', 'svc-iam', EdgeKind.ENTITLED, _OLD)         # used
    # Never exercised. The support desk can read the card database and the
    # HR database, and nobody has ever needed to.
    edge('id-support', 'asset-billing', EdgeKind.ENTITLED, _OLD)
    edge('id-support', 'asset-hr', EdgeKind.ENTITLED, _OLD)
    # The deployment account can reach the backups by policy. The route the
    # quiet address took below is exactly this entitlement being used for
    # the first time.
    edge('id-deploy', 'svc-backups', EdgeKind.ENTITLED, _OLD)

    # ------------------------------------------------------- the new finding
    # Five hours ago the quiet address began using a deployment credential.
    # Nothing about this step is individually alarming, and no rule covers
    # it. It is the whole reason to look at structure rather than events.
    edge('ip-quiet', 'id-deploy', EdgeKind.YIELDS, _NEW)
    # And the deployment identity can reach the backups, which it always could.
    edge('id-deploy', 'svc-backups', EdgeKind.CALLED, _NEW)

    return {
        'name': 'Northwind Components (synthetic, not a real business)',
        'generated': GENERATED.isoformat(),
        'note': ('Invented for demonstration. Addresses come from the RFC 5737 '
                 'documentation ranges and route nowhere.'),
        'nodes': nodes,
        'edges': edges,
    }


def write(path):
    import json
    payload = build()
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2)
    return payload


if __name__ == '__main__':
    import os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(here, 'data', 'estate.json')
    data = write(target)
    print('wrote %s, %d nodes and %d edges'
          % (target, len(data['nodes']), len(data['edges'])))
