"""Cloud audit: AWS CloudTrail.

CloudTrail is the clearest example of why edge direction is a design decision
and not a transcription. A trail record reads:

    userIdentity: svc-deploy        sourceIPAddress: 192.0.2.41
    eventName:    AssumeRole        resources: [s3://nightly-backups]

Written the way the record reads, the edge runs identity -> address, and
every path search walks into an address and stops, because an address has no
outgoing edges. Written the way an attacker moves, the address yields the
identity and the identity reaches the resource, and the same three fields
become a two-hop route to the backups.

This was the first bug in the engine and it is why `vocab` documents a
direction for every edge kind.
"""
from __future__ import annotations

from ..vocab import EdgeKind, NodeKind, Zone
from .base import Connector, GraphDelta

#: Events that hand an attacker a credential or a new identity.
_CREDENTIAL_EVENTS = frozenset({
    'AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
    'GetSessionToken', 'GetFederationToken', 'CreateAccessKey',
})

#: Events that read data rather than moving laterally.
_DATA_EVENTS = frozenset({'GetObject', 'ListObjects', 'ListObjectsV2',
                          'GetSecretValue', 'Decrypt', 'SelectObjectContent'})

_CROWN_HINTS = ('backup', 'billing', 'card', 'payment', 'secret', 'payroll')

#: CloudTrail's userIdentity.type, mapped to the principal types the rest of
#: the product speaks. Only values AWS documents; anything else is left
#: unset rather than guessed.
_PRINCIPAL_TYPES = {'AssumedRole': 'role', 'Role': 'role', 'IAMUser': 'user',
                    'Root': 'root', 'AWSService': 'service',
                    'FederatedUser': 'user'}


def _iam_action(record: dict, event: str) -> str:
    """`s3.amazonaws.com` + `GetObject` -> `s3:GetObject`, IAM's own format.

    In that form the action can be compared with a policy statement rather
    than read as prose, which is what a revocation needs.
    """
    service = str(record.get('eventSource') or '').split('.', 1)[0]
    return '%s:%s' % (service, event) if service and event else event


class CloudTrailConnector(Connector):
    """AWS CloudTrail events, from LookupEvents or a delivered log file."""

    key = 'cloudtrail'
    vendor = 'Amazon Web Services'
    product = 'CloudTrail'
    category = 'cloud'
    required_credentials = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                            'AWS_REGION')
    api_reference = ('https://docs.aws.amazon.com/awscloudtrail/latest/'
                     'APIReference/API_LookupEvents.html')

    def fetch_live(self) -> dict:
        # LookupEvents is a SigV4-signed POST. Signing it correctly by hand
        # is more code than this file should carry, so the live path expects
        # the caller's own boto3 session to hand over the page it already
        # fetched. Refusing is better than a half-signed request that fails
        # in a way nobody can debug.
        raise NotImplementedError(
            'pass CloudTrail records in via transform(); SigV4 signing is the '
            "caller's boto3 session, not this connector's job")

    def transform(self, payload: dict) -> GraphDelta:
        delta = GraphDelta()
        for record in payload.get('Records', []):
            event = str(record.get('eventName') or '')
            when = str(record.get('eventTime') or '')
            source_ip = str(record.get('sourceIPAddress') or '').strip()
            identity_block = record.get('userIdentity', {})
            principal = str(identity_block.get('userName')
                            or identity_block.get('arn')
                            or identity_block.get('principalId') or '').strip()
            if not principal:
                delta.stats['skipped'] = delta.stats.get('skipped', 0) + 1
                continue
            # An ARN is unreadable on a diagram. Keep the last segment.
            short = principal.rsplit('/', 1)[-1]
            identity = 'id:%s' % short
            action = _iam_action(record, event)
            principal_type = _PRINCIPAL_TYPES.get(str(identity_block.get('type') or ''))
            delta.add_node(identity, NodeKind.IDENTITY, short, Zone.INTERNAL,
                           label=short, source='cloudtrail', arn=principal,
                           **({'principal_type': principal_type}
                              if principal_type else {}))

            # AWS writes the literal string for service-initiated calls.
            if source_ip and not source_ip.endswith('.amazonaws.com'):
                delta.add_node('addr:%s' % source_ip, NodeKind.ADDRESS,
                               source_ip, Zone.UNTRUSTED)
                if event in _CREDENTIAL_EVENTS:
                    # Direction reversed on purpose. See the module docstring.
                    delta.add_edge('addr:%s' % source_ip, identity,
                                   EdgeKind.YIELDS, when, event=event,
                                   actions=[action], last_seen=when)
                    delta.stats['credential_events'] = \
                        delta.stats.get('credential_events', 0) + 1

            for resource in record.get('resources', []) or []:
                arn = str(resource.get('ARN') or '').strip()
                if not arn:
                    continue
                name = arn.rsplit(':', 1)[-1].rsplit('/', 1)[-1] or arn
                crown = any(hint in name.lower() for hint in _CROWN_HINTS)
                node = 'svc:%s' % name
                delta.add_node(node, NodeKind.SERVICE, name,
                               Zone.CROWN if crown else Zone.INTERNAL,
                               label=name, crown=crown, source='cloudtrail',
                               arn=arn)
                delta.add_edge(identity, node, EdgeKind.CALLED, when,
                               event=event,
                               reads_data=event in _DATA_EVENTS,
                               actions=[action], last_seen=when)
                delta.stats['resource_touches'] = \
                    delta.stats.get('resource_touches', 0) + 1
            delta.stats['records'] = delta.stats.get('records', 0) + 1
        return delta
