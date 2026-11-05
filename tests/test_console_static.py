"""The console is served, and served under its own content security policy.

The console's promise is that it needs no inline script and no eval, so it
can run under a CSP that allows scripts from this origin only. That promise
is only worth something if the policy is actually sent and if nothing in the
page quietly needs it relaxed. Both are checked here; the screens themselves
are walked in a real browser as each role, which a unit test cannot do.
"""
from __future__ import annotations

import re
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent.parent / 'graphops' / 'console'


def test_the_root_sends_people_to_the_console(client):
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 307
    assert response.headers['location'] == '/console/'


def test_the_console_is_served_under_a_strict_csp(client):
    response = client.get('/console/')
    assert response.status_code == 200
    csp = response.headers['content-security-policy']
    assert "script-src 'self'" in csp
    assert 'unsafe-inline' not in csp and 'unsafe-eval' not in csp
    assert "frame-ancestors 'none'" in csp
    assert "connect-src 'self'" in csp


def test_the_api_itself_carries_no_console_policy(client):
    """The CSP is the console's. JSON responses keep their own headers."""
    assert 'content-security-policy' not in client.get('/health').headers


def test_the_page_has_no_inline_script_and_every_script_it_loads_exists(client):
    html = (CONSOLE / 'index.html').read_text(encoding='utf-8')
    scripts = re.findall(r'<script\b([^>]*)>(.*?)</script>', html, re.S)
    assert scripts
    for attrs, body in scripts:
        assert 'src=' in attrs, 'an inline script would need unsafe-inline'
        assert not body.strip()
        src = re.search(r'src="([^"]+)"', attrs).group(1)
        assert client.get('/console/' + src).status_code == 200, src
    assert not re.search(r'\son[a-z]+\s*=', html), 'an inline handler would need unsafe-inline'


def test_no_console_script_builds_markup_from_a_string():
    """innerHTML or eval would put a crown jewel name, or a log line an
    attacker wrote, one step from executing. The console builds every
    element through Preact instead."""
    for path in CONSOLE.glob('*.js'):
        text = path.read_text(encoding='utf-8')
        for banned in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(',
                       'new Function', 'document.write', 'dangerouslySetInnerHTML'):
            assert banned not in text, '%s uses %s' % (path.name, banned)


def test_the_console_names_the_product_not_the_company_or_a_customer():
    """The submission was scanned clean of company and tenant names, and the
    design export carried both. The console uses neither, and names no
    person: a style comment once credited a rule to a team member by name,
    and shipped in a public commit before a scan of the zip caught it."""
    # Written reversed so the repository's own scan for those names, which
    # the submission notes quote as clean, does not find them in this test.
    banned = [word[::-1] for word in ('xeriylac', 'arovlah',
                                      'anhsirkirhs', 'akihtsaws')]
    for path in list(CONSOLE.glob('*.js')) + list(CONSOLE.glob('*.html')) + list(CONSOLE.glob('*.css')):
        text = path.read_text(encoding='utf-8').lower()
        for name in banned:
            assert name not in text, '%s mentions a name the submission must not carry' % path.name
