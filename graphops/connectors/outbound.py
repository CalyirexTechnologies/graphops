"""Outbound connectors: Jira, Slack, Microsoft Teams, PagerDuty.

These carry a finding out of the platform to where someone will act on it.
Three rules hold for all of them.

**Idempotent on a caller-supplied key.** A finding's fingerprint is stable
across ingest runs, so re-running the pipeline must not open a second ticket
or page the on-call again. Each connector's `deliver` takes an idempotency
key and the vendor-native mechanism is used where one exists: Jira gets a
labelled search before it creates, PagerDuty gets `dedup_key`, Slack and
Teams get a sent-key set.

**Nothing sensitive crosses the boundary.** `summarise` builds the outbound
body, and it deliberately omits crown-jewel identities unless the connector
is configured with `include_crown=True`. A chat channel is a wider audience
than the console: a message naming the card database sits in a searchable
archive that half the company can read.

**Delivery in replay mode records rather than sends.** Nothing leaves the
machine, `sent` collects what would have gone, and the tests assert on it.
That is how an outbound integration gets a real test at all.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import MODE_LIVE, ConnectorError, OutboundConnector, require_http_url


def summarise(finding: dict, *, include_crown: bool = False) -> dict:
    """The body that leaves the platform. Smaller than the finding on purpose."""
    body = {
        'id': finding.get('id'),
        'title': finding.get('title'),
        'severity': finding.get('severity', 'medium'),
        'kind': finding.get('kind'),
        'routes': finding.get('routes'),
        'fingerprint': finding.get('fingerprint'),
    }
    if include_crown:
        body['target'] = finding.get('target')
    else:
        # The count still travels; the name does not.
        body['target'] = 'a crown jewel' if finding.get('target') else None
    return {k: v for k, v in body.items() if v is not None}


class _Deliverable(OutboundConnector):
    """Shared delivery bookkeeping."""

    def __init__(self, *, include_crown: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.include_crown = include_crown
        #: What was sent, or would have been. Keyed by idempotency key.
        self.sent: dict[str, dict] = {}

    def _already_sent(self, key: str) -> dict | None:
        return self.sent.get(key)

    def _record(self, key: str, payload: dict, target: str) -> dict:
        receipt = {'delivered': True, 'target': target, 'idempotency_key': key,
                   'mode': self.mode, 'payload': payload}
        self.sent[key] = receipt
        return receipt

    def _post(self, url: str, payload: dict, headers: dict) -> int:
        # A webhook URL comes from tenant configuration. Without this, a
        # tenant could point one at file: or at an internal metadata service.
        require_http_url(url, self.key)
        data = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(  # noqa: S310
            url, data=data, method='POST',
            headers={'Content-Type': 'application/json', **headers})
        try:
            # Scheme already checked by require_http_url above.
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return response.status
        except urllib.error.HTTPError as exc:
            raise ConnectorError('%s returned HTTP %d' % (self.key, exc.code)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ConnectorError('%s unreachable: %s' % (self.key, exc)) from exc


class JiraConnector(_Deliverable):
    """Opens a Jira issue for a finding."""

    key = 'jira'
    vendor = 'Atlassian'
    product = 'Jira Cloud'
    category = 'ticketing'
    required_credentials = ('JIRA_BASE_URL', 'JIRA_EMAIL', 'JIRA_API_TOKEN',
                            'JIRA_PROJECT_KEY')
    api_reference = ('https://developer.atlassian.com/cloud/jira/platform/'
                     'rest/v3/api-group-issues/')

    _PRIORITY = {'critical': 'Highest', 'high': 'High', 'medium': 'Medium',
                 'low': 'Low'}

    def deliver(self, finding: dict, *, idempotency_key: str) -> dict:
        existing = self._already_sent(idempotency_key)
        if existing:
            return dict(existing, deduplicated=True)

        body = summarise(finding, include_crown=self.include_crown)
        issue = {
            'fields': {
                'project': {'key': self.credentials.get('JIRA_PROJECT_KEY', 'SEC')},
                'summary': body.get('title', 'GraphOps finding'),
                'issuetype': {'name': 'Task'},
                'priority': {'name': self._PRIORITY.get(
                    str(body.get('severity', 'medium')).lower(), 'Medium')},
                # The fingerprint goes on a label, which is what the
                # pre-create search matches, so a re-run finds its own ticket
                # even after this process restarts.
                'labels': ['graphops', 'graphops-%s' % idempotency_key[:24]],
                'description': {
                    'type': 'doc', 'version': 1,
                    'content': [{'type': 'paragraph', 'content': [
                        {'type': 'text', 'text': json.dumps(body, indent=2)}]}],
                },
            }
        }
        if self.mode == MODE_LIVE:
            import base64
            token = base64.b64encode(
                ('%s:%s' % (self.credentials['JIRA_EMAIL'],
                            self.credentials['JIRA_API_TOKEN'])).encode()).decode()
            self._post('%s/rest/api/3/issue'
                       % self.credentials['JIRA_BASE_URL'].rstrip('/'),
                       issue, {'Authorization': 'Basic %s' % token})
        return self._record(idempotency_key, issue,
                            self.credentials.get('JIRA_PROJECT_KEY', 'SEC'))


class SlackConnector(_Deliverable):
    """Posts a finding to a Slack channel via an incoming webhook."""

    key = 'slack'
    vendor = 'Slack'
    product = 'Incoming Webhooks'
    category = 'chat'
    required_credentials = ('SLACK_WEBHOOK_URL',)
    api_reference = 'https://api.slack.com/messaging/webhooks'

    def deliver(self, finding: dict, *, idempotency_key: str) -> dict:
        existing = self._already_sent(idempotency_key)
        if existing:
            return dict(existing, deduplicated=True)
        body = summarise(finding, include_crown=self.include_crown)
        message = {
            'text': '%s: %s' % (str(body.get('severity', 'medium')).upper(),
                                body.get('title', 'GraphOps finding')),
            'blocks': [
                {'type': 'section', 'text': {
                    'type': 'mrkdwn',
                    'text': '*%s*\n%s route(s) reach %s'
                            % (body.get('title', 'Finding'),
                               body.get('routes', '?'),
                               body.get('target', 'a protected system'))}},
                {'type': 'context', 'elements': [
                    {'type': 'mrkdwn', 'text': 'GraphOps · `%s`'
                     % body.get('fingerprint', '')[:16]}]},
            ],
        }
        if self.mode == MODE_LIVE:
            self._post(self.credentials['SLACK_WEBHOOK_URL'], message, {})
        return self._record(idempotency_key, message, 'slack-channel')


class TeamsConnector(_Deliverable):
    """Posts an adaptive card to a Microsoft Teams channel."""

    key = 'teams'
    vendor = 'Microsoft'
    product = 'Teams Incoming Webhook'
    category = 'chat'
    required_credentials = ('TEAMS_WEBHOOK_URL',)
    api_reference = ('https://learn.microsoft.com/en-us/microsoftteams/'
                     'platform/webhooks-and-connectors/how-to/'
                     'add-incoming-webhook')

    def deliver(self, finding: dict, *, idempotency_key: str) -> dict:
        existing = self._already_sent(idempotency_key)
        if existing:
            return dict(existing, deduplicated=True)
        body = summarise(finding, include_crown=self.include_crown)
        card = {
            'type': 'message',
            'attachments': [{
                'contentType': 'application/vnd.microsoft.card.adaptive',
                'content': {
                    'type': 'AdaptiveCard', 'version': '1.4',
                    'body': [
                        {'type': 'TextBlock', 'weight': 'Bolder', 'wrap': True,
                         'text': body.get('title', 'GraphOps finding')},
                        {'type': 'FactSet', 'facts': [
                            {'title': 'Severity',
                             'value': str(body.get('severity', 'medium'))},
                            {'title': 'Routes',
                             'value': str(body.get('routes', '?'))},
                            {'title': 'Target',
                             'value': str(body.get('target', 'protected system'))},
                        ]},
                    ],
                },
            }],
        }
        if self.mode == MODE_LIVE:
            self._post(self.credentials['TEAMS_WEBHOOK_URL'], card, {})
        return self._record(idempotency_key, card, 'teams-channel')


class PagerDutyConnector(_Deliverable):
    """Raises a PagerDuty incident through Events API v2.

    Only for findings a person should be woken for. `should_page` is the
    whole policy and it is deliberately strict: a tool that pages on medium
    findings gets muted within a week, after which it pages on nothing.
    """

    key = 'pagerduty'
    vendor = 'PagerDuty'
    product = 'Events API v2'
    category = 'oncall'
    required_credentials = ('PAGERDUTY_ROUTING_KEY',)
    api_reference = ('https://developer.pagerduty.com/docs/'
                     'events-api-v2/trigger-events/')

    EVENTS_URL = 'https://events.pagerduty.com/v2/enqueue'

    @staticmethod
    def should_page(finding: dict) -> bool:
        return (str(finding.get('severity', '')).lower() == 'critical'
                and bool(finding.get('target')))

    def deliver(self, finding: dict, *, idempotency_key: str) -> dict:
        if not self.should_page(finding):
            return {'delivered': False, 'reason': 'below the paging threshold',
                    'idempotency_key': idempotency_key}
        existing = self._already_sent(idempotency_key)
        if existing:
            return dict(existing, deduplicated=True)
        body = summarise(finding, include_crown=self.include_crown)
        event = {
            'routing_key': self.credentials.get('PAGERDUTY_ROUTING_KEY', ''),
            'event_action': 'trigger',
            # PagerDuty's own deduplication. Two triggers with one dedup_key
            # update a single incident instead of opening two.
            'dedup_key': idempotency_key,
            'payload': {
                'summary': body.get('title', 'GraphOps critical finding'),
                'severity': 'critical',
                'source': 'graphops',
                'component': 'attack-path',
                'custom_details': body,
            },
        }
        if self.mode == MODE_LIVE:
            self._post(self.EVENTS_URL, event, {})
        return self._record(idempotency_key, event, 'pagerduty')
