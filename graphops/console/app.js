/* GraphOps console: shell, router and sign-in.
 *
 * Routing is by hash, and the hash never carries estate data. A node's id is
 * customer infrastructure, so the node page reads which node to show from
 * the session rather than the URL, where it would land in browser history.
 */
(function () {
  'use strict';
  var GX = window.GX, el = GX.el, icon = GX.icon;

  var SCREENS = [
    { id: 'overview', label: 'Overview', icon: 'overview', perm: 'graph:read' },
    { id: 'exposure', label: 'Exposure', icon: 'exposure', perm: 'graph:query' },
    { id: 'findings', label: 'Findings', icon: 'findings', perm: 'finding:read' },
    { id: 'access', label: 'Access', icon: 'access', perm: 'graph:query' },
    { id: 'compliance', label: 'Compliance', icon: 'compliance', perm: 'compliance:read' },
    { id: 'connectors', label: 'Connectors', icon: 'connectors', perm: 'connector:read' }
  ];
  var ADMIN_PERMS = ['user:read', 'apikey:manage', 'audit:read'];

  function route() {
    var h = (location.hash || '').replace(/^#\/?/, '');
    var parts = h.split('/');
    return { screen: parts[0] || '', tab: parts[1] || '' };
  }
  GX.go = function (screen, tab) {
    var next = '#/' + screen + (tab ? '/' + tab : '');
    if (location.hash === next) window.dispatchEvent(new Event('hashchange'));
    else location.hash = next;
  };
  GX.openNode = function (id) {
    if (!id) return;
    GX.session.set('gx.node', id);
    GX.go('node');
  };
  GX.toast = function (text, tone) { if (GX._app) GX._app.setState({ toast: { text: text, tone: tone, at: Date.now() } }); };

  /* --------------------------------------------------------------- sign in */
  var SignIn = GX.extend(GX.Component, {
    init: function () {
      this.state = { org: GX.local.get('gx.org') || '', email: '', password: '', show: false,
        step: 'password', challenge: null, code: '', error: null, busy: false };
    },
    submit: function (ev) {
      ev.preventDefault();
      var s = this.state, self = this;
      if (s.busy) return;
      self.setState({ busy: true, error: null });
      var done = function (body) {
        GX.setTokens(body);
        self.props.onSignedIn();
      };
      var failed = function (e) {
        var b = e.body || {};
        var msg;
        if (e.status === 423) {
          var mins = Math.max(1, Math.ceil((b.retry_after_seconds || 60) / 60));
          msg = { tone: 'lock', text: 'This account is locked for ' + mins + ' more minute' + (mins === 1 ? '' : 's') +
            ' after too many attempts. Wait, or ask your admin to unlock it.' };
        } else if (s.step === 'mfa') {
          msg = { text: 'That code did not work. Codes change every 30 seconds and each one works once.' };
        } else if (e.status === 401) {
          var left = b.attempts_remaining;
          msg = { text: 'That organisation, email and password do not match.' +
            (left > 0 ? ' ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left before a 15-minute lock.' : '') };
        } else if (e.status === 422) {
          msg = { text: 'Check the organisation name. It is the short name, such as acme, without spaces.' };
        } else {
          msg = { text: 'Sign-in is not responding. Try again in a moment.' };
        }
        self.setState({ busy: false, error: msg });
      };
      if (s.step === 'password') {
        GX.local.set('gx.org', s.org.trim().toLowerCase());
        GX.post('/v1/auth/login', { organization: s.org.trim().toLowerCase(), email: s.email.trim(), password: s.password })
          .then(function (body) {
            if (body.mfa_required) {
              self.setState({ busy: false, step: 'mfa', challenge: body.challenge, password: '' });
            } else { done(body); }
          }, failed);
      } else {
        GX.post('/v1/auth/mfa', { challenge: s.challenge, code: s.code.trim() }).then(done, failed);
      }
    },
    render: function (props, s) {
      var self = this;
      var field = function (id, label, input) {
        return el('div.field', null, el('label', { 'for': id }, label), input);
      };
      var form = s.step === 'password'
        ? [
          field('org', 'Organisation', el('input.input', { id: 'org', autocomplete: 'organization', value: s.org, required: true,
            onInput: function (e) { self.setState({ org: e.target.value }); } })),
          field('email', 'Work email', el('input.input', { id: 'email', type: 'email', autocomplete: 'username', value: s.email, required: true,
            onInput: function (e) { self.setState({ email: e.target.value }); } })),
          field('password', 'Password', el('div.input-wrap', null,
            el('input.input', { id: 'password', type: s.show ? 'text' : 'password', autocomplete: 'current-password', value: s.password,
              required: true, style: { paddingRight: '64px' }, onInput: function (e) { self.setState({ password: e.target.value }); } }),
            el('button', { type: 'button', 'aria-pressed': String(s.show), onClick: function () { self.setState({ show: !s.show }); },
              style: { position: 'absolute', right: '6px', top: '6px', height: '30px', padding: '0 10px', border: 0, borderRadius: '6px',
                background: 'transparent', color: 'var(--text-2)', fontWeight: 600 } }, s.show ? 'Hide' : 'Show')))
        ]
        : [
          el('p.dim', null, 'Enter the 6-digit code from your authenticator app.'),
          field('code', 'Verification code', el('input.input.code-input', { id: 'code', inputmode: 'numeric', autocomplete: 'one-time-code',
            pattern: '[0-9]{6}', maxlength: 6, value: s.code, required: true,
            onInput: function (e) { self.setState({ code: e.target.value.replace(/\D/g, '').slice(0, 6) }); } }))
        ];
      return el('div.signin', null,
        el('div.left', null,
          el('div.row', null, el('div.brand', null, el('span.brand-tile', { 'aria-hidden': 'true' }, 'G'), el('span.brand-name', null, 'GraphOps')),
            el('span.spacer'), GX.ThemeButton({ theme: props.theme, onToggle: props.onTheme })),
          el('form', { onSubmit: function (e) { self.submit(e); }, noValidate: false },
            el('div.steps', { 'aria-hidden': 'true' },
              el('div.' + (s.step === 'password' ? 'on' : 'done'), null, el('span.cap', null, '1 · Password')),
              el('div.' + (s.step === 'mfa' ? 'on' : 'x'), null, el('span.cap', null, '2 · Verification code'))),
            el('div.stack', null, el('h1', null, s.step === 'password' ? 'Sign in' : 'Verify it is you'),
              el('p.dim', null, s.step === 'password' ? 'Use the organisation and work email your admin set up for you.'
                : 'Your password was accepted. One more step.')),
            form,
            s.error ? el('div.callout.' + (s.error.tone === 'lock' ? 'warn' : 'bad'), { role: 'alert' },
              icon(s.error.tone === 'lock' ? 'lock' : 'warn', 18), el('div.body', null, s.error.text)) : null,
            el('button.btn.primary', { type: 'submit', disabled: s.busy, style: { height: '44px' } },
              s.busy ? 'Checking' : s.step === 'password' ? 'Continue' : 'Verify and sign in'),
            s.step === 'mfa' ? el('button.btn', { type: 'button', onClick: function () {
              self.setState({ step: 'password', code: '', challenge: null, error: null }); } }, 'Use a different account') : null),
          el('p.faint', null, 'Trouble signing in? Your organisation\'s admin can reset your password or MFA.')),
        el('div.right', { 'aria-hidden': 'true' }, ZoneIllustration(), el('p.tagline', null,
          'Every route from outside to what matters, and the one change that cuts the most of them.'),
          el('div.legend', null,
            el('span', null, el('i', { style: { width: '16px', height: '2px', background: 'var(--crit)', display: 'inline-block' } }), 'Route'),
            el('span', null, el('i', { style: { width: '10px', height: '10px', borderRadius: '50%', border: '1.5px dashed var(--warn)', display: 'inline-block' } }), 'Choke point'),
            el('span', { style: { color: 'var(--jewel)' } }, icon('diamond', 12), el('span.dim', null, 'Crown jewel')))));
    }
  });

  /* The sign-in page's picture. A drawing of the idea, not data: four trust
     zones, routes from the internet converging on a choke point and
     reaching crown jewels. The zone names are the product's own four. */
  function ZoneIllustration() {
    var h = GX.h;
    var zones = ['Internet', 'Perimeter', 'Internal', 'Crown'];
    var cols = [70, 230, 390, 550];
    var nodes = [[70, 190], [230, 100], [230, 190], [230, 280], [390, 70], [390, 160], [390, 230], [390, 310], [550, 110], [550, 200], [550, 290]];
    var edges = [[0, 1], [0, 2], [0, 3], [1, 4], [1, 5], [2, 5], [2, 6], [3, 6], [3, 7], [4, 8], [5, 8], [6, 9], [7, 10], [6, 10]];
    var route = [[0, 2], [2, 6], [6, 9]];
    var kids = [];
    zones.forEach(function (z, i) {
      kids.push(h('rect', { key: 'z' + i, x: cols[i] - 70, y: 20, width: 160, height: 330, fill: i === 3 ? 'color-mix(in srgb, var(--jewel) 9%, transparent)' : i % 2 ? 'var(--panel)' : 'transparent' }));
      kids.push(h('text', { key: 't' + i, x: cols[i] - 58, y: 42, fill: i === 3 ? 'var(--jewel)' : 'var(--text-3)', 'font-size': 10, 'letter-spacing': 1.2, 'font-weight': 600 }, z.toUpperCase()));
    });
    edges.forEach(function (e, i) {
      var a = nodes[e[0]], b = nodes[e[1]];
      kids.push(h('line', { key: 'e' + i, x1: a[0], y1: a[1], x2: b[0], y2: b[1], stroke: 'var(--line-2)', 'stroke-width': 1 }));
    });
    route.forEach(function (e, i) {
      var a = nodes[e[0]], b = nodes[e[1]];
      kids.push(h('line', { key: 'r' + i, x1: a[0], y1: a[1], x2: b[0], y2: b[1], stroke: 'var(--crit)', 'stroke-width': 2, 'stroke-dasharray': '5 4' }));
    });
    nodes.forEach(function (n, i) {
      if (i >= 8) {
        kids.push(h('path', { key: 'n' + i, d: 'M' + n[0] + ' ' + (n[1] - 10) + 'l10 10-10 10-10-10z', fill: i === 9 ? 'var(--jewel)' : 'color-mix(in srgb, var(--jewel) 30%, transparent)', stroke: 'var(--jewel)', 'stroke-width': 1.5 }));
      } else if (i === 0) {
        kids.push(h('circle', { key: 'n' + i, cx: n[0], cy: n[1], r: 10, fill: 'var(--bg)', stroke: 'var(--text-2)', 'stroke-width': 1.5 }));
      } else {
        var onRoute = i === 2 || i === 6;
        kids.push(h('circle', { key: 'n' + i, cx: n[0], cy: n[1], r: onRoute ? 7 : 5, fill: 'var(--bg)', stroke: onRoute ? 'var(--crit)' : 'var(--line-2)', 'stroke-width': onRoute ? 2 : 1.2 }));
        if (i === 6) kids.push(h('circle', { key: 'c', cx: n[0], cy: n[1], r: 13, fill: 'none', stroke: 'var(--warn)', 'stroke-width': 1.5, 'stroke-dasharray': '3 3' }));
      }
    });
    return h('svg', { 'class': 'zones-illus', viewBox: '0 0 640 370', role: 'img' }, kids);
  }

  GX.ThemeButton = function (props) {
    var dark = props.theme === 'dark';
    return el('button.icon-btn.hov', { type: 'button', onClick: props.onToggle,
      'aria-label': dark ? 'Switch to light theme' : 'Switch to dark theme' }, icon(dark ? 'sun' : 'moon', 16));
  };

  /* ----------------------------------------------------------- the search */
  var Search = GX.extend(GX.Component, {
    init: function () { this.state = { q: '', results: null, open: false }; this.timer = null; },
    change: function (q) {
      var self = this;
      self.setState({ q: q, open: true });
      clearTimeout(self.timer);
      if (q.trim().length < 2) { self.setState({ results: null }); return; }
      self.timer = setTimeout(function () {
        var me = self.props.me;
        var asks = [GX.can(me, 'graph:query') ? GX.get('/v1/graph/nodes' + GX.qs({ q: q, limit: 8 })) : Promise.resolve(null),
          GX.can(me, 'finding:read') ? GX.get('/v1/findings' + GX.qs({ q: q, limit: 5 })) : Promise.resolve(null)];
        Promise.all(asks.map(function (p) { return p.catch(function () { return null; }); })).then(function (r) {
          if (self.state.q !== q) return;
          self.setState({ results: { nodes: r[0] ? r[0].nodes : [], findings: r[1] ? r[1].findings : [] } });
        });
      }, 220);
    },
    render: function (props, s) {
      var self = this;
      var r = s.results;
      var items = [];
      if (r) {
        r.nodes.forEach(function (n) {
          items.push(el('a', { key: 'n' + n.id, href: '#/node', onClick: function (ev) { ev.preventDefault(); self.setState({ open: false, q: '' }); GX.openNode(n.id); } },
            icon(GX.kindIcon(n.kind, n.is_crown_jewel), 14), el('span.mono.ellipsis' + (n.is_crown_jewel ? '.jewel' : ''), null, n.key),
            el('span.faint', { style: { marginLeft: 'auto' } }, GX.KIND[n.kind] || n.kind)));
        });
        r.findings.forEach(function (f) {
          items.push(el('a', { key: 'f' + f.fingerprint, href: '#/findings', onClick: function (ev) { ev.preventDefault(); self.setState({ open: false, q: '' });
            GX.session.set('gx.finding', f.fingerprint); GX.go('findings'); } },
            GX.Sev({ level: f.severity }), el('span.ellipsis', null, f.title)));
        });
      }
      return el('div.search', { role: 'search' },
        el('label.sr', { 'for': 'gs' }, 'Search'),
        icon('search', 15),
        el('input', { id: 'gs', type: 'search', placeholder: 'Search entities and findings', value: s.q, autocomplete: 'off',
          onInput: function (e) { self.change(e.target.value); },
          onFocus: function () { self.setState({ open: true }); },
          onBlur: function () { setTimeout(function () { self.setState({ open: false }); }, 150); },
          onKeyDown: function (e) { if (e.key === 'Escape') self.setState({ open: false }); } }),
        s.open && r ? el('div.search-results', { role: 'listbox' },
          items.length ? items : el('div.faint', { style: { padding: '8px 10px' } }, 'Nothing matches "' + s.q + '"')) : null);
    }
  });

  /* ---------------------------------------------------------------- shell */
  function Shell(props) {
    var me = props.me, ov = props.overview, current = props.screen;
    var imp = me.impersonator;
    var ing = ov && ov.last_ingest;
    var exposureCount = ov && ov.exposure ? ov.exposure.path_count : null;
    var critical = ov && ov.findings ? ov.findings.by_severity.critical : null;
    var nav = SCREENS.filter(function (s) { return GX.can(me, s.perm); }).map(function (s) {
      var badge = null;
      if (s.id === 'exposure' && exposureCount !== null) badge = el('span.count.mono', null, GX.n(exposureCount));
      if (s.id === 'findings' && critical) badge = el('span.count.crit.mono', { title: critical + ' critical' }, GX.n(critical));
      if (s.id === 'connectors' && ing && ing.status !== 'success') badge = el('span.dot' + (ing.status === 'failed' ? '.bad' : ''), { title: 'Last ingest ' + ing.status });
      return el('a', { key: s.id, href: '#/' + s.id, 'aria-current': current === s.id || (current === 'node' && s.id === 'exposure') ? 'page' : undefined },
        icon(s.icon, 16), el('span', { style: { flex: '1 1 auto' } }, s.label), badge);
    });
    var adminOk = ADMIN_PERMS.some(function (p) { return GX.can(me, p); });
    var org = me.organization_detail || {};
    var who = imp ? (me.display_name || me.email) : (me.display_name || me.email);
    var pill = null;
    if (ing && GX.can(me, 'connector:read')) {
      var tone = ing.status === 'success' ? 'ok' : ing.status === 'degraded' ? 'warn' : 'crit';
      pill = el('a', { href: '#/connectors', style: {
        display: 'inline-flex', alignItems: 'center', gap: '8px', height: '36px', padding: '0 12px', borderRadius: '8px',
        color: 'var(--' + tone + ')', background: 'color-mix(in srgb, var(--' + tone + ') 12%, transparent)',
        border: '1px solid color-mix(in srgb, var(--' + tone + ') 35%, transparent)', fontWeight: 600, textDecoration: 'none' } },
        icon(ing.status === 'success' ? 'check' : 'warn', 15), 'Ingest ' + GX.time(ing.finished_at) + ' · ' + GX.cap1(ing.status));
    }
    return el('div.cx' + (imp ? '.imp-on' : ''), { 'data-theme': props.theme },
      imp ? el('div.imp-bar', { role: 'status' }, icon('eye', 16),
        el('span', null, el('strong', null, 'Acting as ' + (me.display_name || me.email) + ' (' + me.roles.join(', ') + ').'),
          ' Signed in as ' + (imp.display_name || imp.email) + '. Everything you do is written to the audit log under both names.'),
        el('button', { type: 'button', onClick: props.onEndImpersonation }, 'End impersonation')) : null,
      el('div.frame', null,
        el('aside.side', null,
          el('div.brand', null, el('span.brand-tile', { 'aria-hidden': 'true' }, 'G'), el('span.brand-name', null, 'GraphOps')),
          el('div.org-card', null, el('span.org-tile', { 'aria-hidden': 'true' }, GX.initials(org.name)),
            el('span', { style: { display: 'flex', flexDirection: 'column', lineHeight: '16px', minWidth: 0 } },
              el('span.ellipsis', { style: { fontWeight: 600 } }, org.name || 'Organisation'),
              el('span.mono.faint', { style: { fontSize: '11px' } }, 'org/' + (org.slug || '')))),
          el('nav.nav', { 'aria-label': 'Primary' }, nav),
          el('nav.nav.side-foot', { 'aria-label': 'Account' },
            adminOk ? el('a', { href: '#/admin', 'aria-current': current === 'admin' ? 'page' : undefined }, icon('admin', 16), 'Admin') : null,
            el('a', { href: '#/profile', 'aria-current': current === 'profile' ? 'page' : undefined }, icon('profile', 16), 'Profile'),
            el('button.nav-btn', { type: 'button', onClick: props.onSignOut }, icon('signout', 16), 'Sign out'))),
        el('div.content', null,
          el('header.topbar', null,
            el(Search, { me: me }),
            el('div.top-right', null, pill,
              GX.ThemeButton({ theme: props.theme, onToggle: props.onTheme }),
              el('a.avatar', { href: '#/profile', 'aria-label': 'Profile of ' + who, title: who }, GX.initials(me.display_name, me.email)))),
          el('main.main', { id: 'main' }, props.children))),
      props.toast ? el('div.toast' + (props.toast.tone === 'bad' ? '.bad' : ''), { role: 'status' }, props.toast.text) : null);
  }

  /* ------------------------------------------------------------------ app */
  var App = GX.extend(GX.Component, {
    init: function () {
      var saved = GX.local.get('gx.theme');
      var sys = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
      this.state = { me: null, overview: null, booting: true, theme: saved || sys, route: route(), toast: null };
      GX._app = this;
    },
    componentDidMount: function () {
      var self = this;
      window.addEventListener('hashchange', function () { self.setState({ route: route() }); window.scrollTo(0, 0); });
      GX.onSignedOut(function () { self.setState({ me: null, overview: null }); GX.go('signin'); });
      document.documentElement.setAttribute('data-theme', this.state.theme);
      this.boot();
    },
    componentDidUpdate: function () {
      var t = this.state.toast;
      var self = this;
      if (t && !this._toastTimer) {
        this._toastTimer = setTimeout(function () { self._toastTimer = null; self.setState({ toast: null }); }, 5200);
      }
      document.documentElement.setAttribute('data-theme', this.state.theme);
      document.body.style.background = this.state.theme === 'dark' ? '#0B0E12' : '#F3F4F6';
    },
    boot: function () {
      var self = this;
      if (!GX.tokens().access) { self.setState({ booting: false, me: null }); if (route().screen !== 'signin') GX.go('signin'); return; }
      GX.get('/v1/auth/me').then(function (me) {
        self.setState({ me: me, booting: false });
        var r = route();
        if (!r.screen || r.screen === 'signin') GX.go(GX.can(me, 'graph:read') ? 'overview' : 'profile');
        self.refreshOverview();
      }, function () {
        GX.setTokens(null);
        self.setState({ me: null, booting: false });
        GX.go('signin');
      });
    },
    refreshOverview: function () {
      var self = this;
      if (!GX.can(this.state.me, 'graph:read')) return Promise.resolve(null);
      return GX.get('/v1/overview').then(function (ov) { self.setState({ overview: ov }); return ov; },
        function () { self.setState({ overview: null }); return null; });
    },
    toggleTheme: function () {
      var t = this.state.theme === 'dark' ? 'light' : 'dark';
      GX.local.set('gx.theme', t);
      this.setState({ theme: t });
    },
    signOut: function () {
      var self = this;
      var end = function () {
        GX.setTokens(null);
        GX.session.set('gx.owner.access', null); GX.session.set('gx.owner.refresh', null);
        GX.session.set('gx.node', null); GX.session.set('gx.finding', null);
        self.setState({ me: null, overview: null });
        GX.go('signin');
      };
      GX.post('/v1/auth/logout').then(end, end);
    },
    startImpersonation: function (user) {
      var self = this;
      var current = GX.tokens();
      return GX.post('/v1/admin/impersonation', { user_id: user.id }).then(function (pair) {
        GX.session.set('gx.owner.access', current.access);
        GX.session.set('gx.owner.refresh', current.refresh);
        GX.setTokens(pair);
        return GX.get('/v1/auth/me');
      }).then(function (me) {
        self.setState({ me: me, overview: null });
        self.refreshOverview();
        GX.go('profile');
      });
    },
    endImpersonation: function () {
      var self = this;
      var restore = function () {
        GX.setTokens({ access_token: GX.session.get('gx.owner.access'), refresh_token: GX.session.get('gx.owner.refresh') });
        GX.session.set('gx.owner.access', null); GX.session.set('gx.owner.refresh', null);
        GX.get('/v1/auth/me').then(function (me) {
          self.setState({ me: me, overview: null });
          self.refreshOverview();
          GX.go('admin', 'users');
        }, function () { self.signOut(); });
      };
      // Ending it is signing the impersonated session out. The owner's own
      // session was never touched, so it simply resumes.
      GX.post('/v1/auth/logout').then(restore, restore);
    },
    render: function (props, s) {
      var self = this;
      if (s.booting) return el('div.cx', { 'data-theme': s.theme }, GX.Loading({ label: 'Starting' }));
      if (!s.me) {
        return el('div.cx', { 'data-theme': s.theme }, el(SignIn, { theme: s.theme, onTheme: function () { self.toggleTheme(); },
          onSignedIn: function () { self.setState({ booting: true }); self.boot(); } }));
      }
      var screen = s.route.screen;
      var view = GX.screens[screen];
      var allowed = SCREENS.filter(function (x) { return x.id === screen; })[0];
      var body;
      if (!view) {
        body = GX.Empty({ title: 'There is no such page' }, el('a', { href: '#/overview' }, 'Go to the overview'));
      } else if (allowed && !GX.can(s.me, allowed.perm)) {
        body = GX.Problem({ error: { status: 403, body: { missing_permission: allowed.perm } } });
      } else {
        body = el(view, { key: screen + '/' + (s.route.tab || '') + '/' + s.me.subject, me: s.me, overview: s.overview, tab: s.route.tab,
          refreshOverview: function () { return self.refreshOverview(); },
          startImpersonation: function (u) { return self.startImpersonation(u); },
          endImpersonation: function () { self.endImpersonation(); } });
      }
      return Shell({ me: s.me, overview: s.overview, theme: s.theme, screen: screen, toast: s.toast,
        onTheme: function () { self.toggleTheme(); }, onSignOut: function () { self.signOut(); },
        onEndImpersonation: function () { self.endImpersonation(); }, children: body });
    }
  });

  GX.screens = GX.screens || {};
  GX.start = function () { GX.render(el(App), document.getElementById('root')); };
})();
