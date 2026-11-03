"""The node and edge vocabulary, kept deliberately small.

BORROWED FROM BLOODHOUND 8.0's OpenGraph, which replaced a hardcoded Active
Directory schema with a generic one anything can be loaded into. A fixed
schema is the thing that stops a security graph growing: the next data
source always has an entity the schema did not anticipate.

WHAT THIS GRAPH IS NOT. BloodHound and most of the lateral-movement
literature are built on Active Directory authentication: host-to-host
logons, process launches, Kerberos tickets. THIS GRAPH HAS NONE OF
THAT. Its telemetry is web access logs, cloud audit trails, a software
inventory and detection rules. So the edges below are the ones that data
actually supports, and
there is deliberately no `logged_into` edge between two machines, because
nothing in this telemetry would ever populate it. A graph with edges nobody
writes is a demo, not a tool.
"""


class NodeKind:
    """What a node can be. Every one is something the telemetry already names."""

    IDENTITY = 'identity'            # a user, or a CloudTrail principal
    ADDRESS = 'address'              # an IP seen in a log or a detection
    ENDPOINT = 'endpoint'            # a URL path on a public surface
    ASSET = 'asset'                  # a package or service in the estate
    VULNERABILITY = 'vulnerability'  # a CVE affecting an asset
    SERVICE = 'service'              # a cloud service, e.g. s3, iam
    RULE = 'rule'                    # a detection rule that fired

    ALL = (IDENTITY, ADDRESS, ENDPOINT, ASSET, VULNERABILITY, SERVICE, RULE)


class EdgeKind:
    """How two nodes relate, and which ATT&CK tactic the step represents.

    THE ATT&CK TAG IS WHAT MAKES A PATH READABLE. MITRE's Attack Flow project
    exists because a raw graph path is not a story: an analyst reads
    "address -> endpoint -> asset" as three hops, and reads
    "Initial Access -> Exploitation -> Collection" as an intrusion. The
    mapping is per edge KIND, not per edge, so it is a claim about what that
    relationship means and not a guess about one event.
    """

    # EVERY EDGE POINTS THE WAY AN ATTACKER WOULD TRAVERSE IT, which is not
    # always the way the telemetry reads. CloudTrail records that an
    # identity acted FROM an address; an attacker who controls that address
    # gains the use of that identity, so the edge is stored address ->
    # identity. Storing it the way the log reads would make the graph
    # unsearchable: every path search would stop dead at the first address,
    # which is exactly what happened the first time this was written.
    YIELDS = 'yields'            # address  -> identity  (control it, use it)
    CALLED = 'called'            # identity -> service
    REQUESTED = 'requested'      # address  -> endpoint
    TRIPPED = 'tripped'          # address  -> rule      (an annotation)
    EXPOSES = 'exposes'          # asset    -> vulnerability
    SERVES = 'serves'            # endpoint -> asset

    # What a policy ALLOWS, as opposed to what the logs show was used.
    # Reading both from the same graph is the zero-trust question: the
    # access people exercise against the access they hold. An entitlement
    # is a real attacker step, because whoever takes the credential can use
    # the whole of it and not just the part its owner happened to need.
    ENTITLED = 'entitled'        # identity -> service or asset

    ALL = (YIELDS, CALLED, REQUESTED, TRIPPED, EXPOSES, SERVES, ENTITLED)

    # (tactic id, tactic name, technique) per edge kind. Only claims we can
    # defend from the edge's own meaning; an edge kind we cannot honestly map
    # carries an empty technique rather than a plausible-looking one.
    ATTACK = {
        YIELDS: ('TA0006', 'Credential Access', 'T1078'),       # Valid Accounts
        CALLED: ('TA0007', 'Discovery', 'T1580'),               # Cloud Infra Discovery
        REQUESTED: ('TA0007', 'Discovery', 'T1595'),            # Active Scanning
        TRIPPED: ('', '', ''),                                  # a detection, not a step
        EXPOSES: ('TA0001', 'Initial Access', 'T1190'),         # Exploit Public-Facing App
        SERVES: ('TA0008', 'Lateral Movement', 'T1210'),        # Exploit Remote Services
        ENTITLED: ('TA0004', 'Privilege Escalation', 'T1078.004'),  # Valid Cloud Accounts
    }


class Zone:
    """Trust zones, which is what makes "attack path" mean anything.

    A path is only interesting if it starts somewhere untrusted and ends
    somewhere that matters. Without zones every graph is a ball of string
    and every node looks equally important.
    """

    UNTRUSTED = 'untrusted'   # the public internet
    PERIMETER = 'perimeter'   # the surfaces that face it
    INTERNAL = 'internal'     # everything behind them
    CROWN = 'crown'           # what an attacker is actually after

    ALL = (UNTRUSTED, PERIMETER, INTERNAL, CROWN)
    ORDER = {UNTRUSTED: 0, PERIMETER: 1, INTERNAL: 2, CROWN: 3}


# How hard a step is for an attacker, used as the edge weight when pathing.
#
# BLOODHOUND CE PATHS ON UNWEIGHTED HOP COUNT, and the community tools that
# wrap it (NoiseHound, ADPathFinder) exist largely to fix that: the shortest
# path is not the likeliest one. An identity reusing a valid credential is
# cheaper for an attacker than exploiting a CVE, and a shortest-path search
# that cannot tell them apart will route the attacker through the hard step
# and call it the risk.
DEFAULT_COST = {
    EdgeKind.YIELDS: 1.0,       # already holds the credential
    EdgeKind.CALLED: 1.0,
    EdgeKind.REQUESTED: 2.0,    # has to find the surface
    EdgeKind.SERVES: 3.0,
    EdgeKind.EXPOSES: 5.0,      # has to land an exploit
    EdgeKind.TRIPPED: 10.0,     # loud: this step is one we already detect
    # Holding a credential, using what it is allowed to do is free. This is
    # why dormant entitlements are dangerous rather than merely untidy.
    EdgeKind.ENTITLED: 1.0,
}
