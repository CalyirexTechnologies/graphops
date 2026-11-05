/* GraphOps console: the analysis screens. Overview, Exposure, Node, Access. */
(function () {
  'use strict';
  var GX = window.GX, el = GX.el, icon = GX.icon, n = GX.n;
  GX.screens = GX.screens || {};

  function head(title, sub, right) {
    return el('div.page-head', null, el('div.stack', null, el('h1', null, title), sub ? el('p', null, sub) : null), right || null);
  }
  GX.head = head;

  function asOf(ov) {
    // The ingest the estate came from, which a failed run or a restart can
    // make different from the last one run.
    var ing = ov && ov.served_ingest;
    var parts = [];
    if (ing) parts.push('built from ingest ' + GX.short(ing.id) + ' at ' + GX.time(ing.finished_at) + ' ' + GX.zone);
    if (ov && ov.mode === 'replay') parts.push('replay recorded ' + GX.day(ov.as_of) + ' ' + GX.time(ov.as_of));
    return parts.join(' · ');
  }
  GX.asOf = asOf;

  function ingestBanner(ing) {
    if (!ing || ing.status === 'success') return null;
    var failed = (ing.runs || []).filter(function (r) { return r.status !== 'success'; }).map(function (r) { return r.connector; });
    return el('div.callout.' + (ing.status === 'failed' ? 'bad' : 'warn'), { role: 'status' }, icon('warn', 20),
      el('div.body', null,
        el('strong', null, ing.status === 'failed' ? 'The last ingest failed, so these answers come from the estate before it'
          : 'The last ingest was degraded, so every answer here is built on incomplete data'),
        el('span.dim', null, failed.length ? failed.join(', ') + ' did not run cleanly. Routes that depend on what ' +
          (failed.length === 1 ? 'it reports' : 'they report') + ' may be missing until a clean run.' : '')),
      el('a.btn.small', { href: '#/connectors' }, 'Open connectors'));
  }
  GX.ingestBanner = ingestBanner;

  function redactionNote(body) {
    var r = body && body._redaction;
    if (!r) return null;
    return el('div.callout.jewel', { role: 'note' }, icon('lock', 18),
      el('div.body', null, el('strong', null, 'Crown jewel names are withheld for your role'),
        el('span.dim', null, n(r.nodes_redacted) + ' names on this page are pseudonyms such as crown-jewel-1a2b3c4d. Routes, counts and ' +
          'tactics are exact. Seeing the real names needs ' + r.unlocked_by + '.')));
  }
  GX.redactionNote = redactionNote;

  /* =============================================================== overview */
  GX.screens.overview = GX.extend(GX.Loader, {
    load: function () { return this.props.refreshOverview().then(function (ov) { if (!ov) throw new GX.ApiError(503, {}); return ov; }); },
    run: function () {
      var self = this;
      self.setState({ running: true });
      GX.post('/v1/connectors/run', { mode: 'replay' }).then(function (r) {
        GX.toast('Ingest ' + r.status + '. ' + r.connectors_run + ' connectors ran, ' + r.connectors_failed + ' failed.', r.status === 'success' ? '' : 'bad');
        self.setState({ running: false }); self.reload();
      }, function () { self.setState({ running: false }); GX.toast('The ingest did not start.', 'bad'); });
    },
    render: function (props, s) {
      var self = this, me = props.me;
      if (s.error) return el(GX.Fragment, null, head('Overview'), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      var ov = s.data;
      if (!ov) return el(GX.Fragment, null, head('Overview'), GX.Loading({}));
      var ex = ov.exposure || {}, ing = ov.last_ingest, org = me.organization_detail || {};
      var reach = (ex.targets || []).length;
      var cheapest = ex.cheapest;
      var top = ov.top_choke_point;
      var answer;
      if (!ex.crown_jewels_total) {
        answer = el('h2', { style: { fontSize: '32px', lineHeight: '40px', fontWeight: 650, fontStretch: '106%' } },
          el('span', { style: { color: 'var(--warn)' } }, 'Not yet. '), 'Nothing is marked as a crown jewel, so there is nothing to reach.');
      } else if (!ex.reachable) {
        answer = el('h2', { style: { fontSize: '32px', lineHeight: '40px', fontWeight: 650, fontStretch: '106%' } },
          el('span', { style: { color: 'var(--ok)' } }, 'No. '), 'No route reaches any of your ' + n(ex.crown_jewels_total) + ' crown jewels at depth ' + ex.max_depth + '.');
      } else {
        answer = el('h2', { style: { fontSize: '32px', lineHeight: '40px', fontWeight: 650, fontStretch: '106%' } },
          el('span', { style: { color: 'var(--crit)' } }, 'Yes. '),
          (ex.capped ? 'At least ' : '') + n(ex.path_count) + ' route' + (ex.path_count === 1 ? ' runs' : 's run') + ' from the internet to ' +
          n(reach) + ' of your ' + n(ex.crown_jewels_total) + ' crown jewels.');
      }
      var detail = null;
      if (cheapest && cheapest.steps.length) {
        var first = cheapest.steps[0].from, last = cheapest.steps[cheapest.steps.length - 1].to;
        detail = el('p.dim', { style: { fontSize: '14px', lineHeight: '22px' } }, 'The cheapest costs an attacker ',
          el('strong', { style: { color: 'var(--text)' } }, cheapest.cost + ' effort'), ', ' + cheapest.steps.length + ' step' + (cheapest.steps.length === 1 ? '' : 's') +
          ' from ' + first.key + ' to ' + last.key + '.' +
          (top ? ' ' + top.key + ' sits on ' + GX.pct(top.share) + ' of all routes.' : ''));
      }
      var tiles = el('div.panel.stats', { style: { boxShadow: 'none' } },
        el('div.stat', null, el('span.cap', null, 'Routes found'), el('span.v', null, n(ex.path_count)),
          el('span.s', null, 'depth ' + ex.max_depth + ' · ' + (ex.capped ? 'cap of ' + n(ex.max_paths) + ' reached' : 'limit ' + n(ex.max_paths)))),
        el('div.stat', null, el('span.cap', null, 'Cheapest route'), el('span.v', null, cheapest ? cheapest.cost : '-', el('small', null, 'effort')),
          el('span.s', null, cheapest ? cheapest.steps.length + ' steps' : props.me && !GX.can(props.me, 'graph:query') ? 'needs graph:query' : 'none')),
        el('div.stat', null, el('span.cap', null, 'Crown jewels in reach'), el('span.v.jewel', null, n(reach), el('small', null, 'of ' + n(ex.crown_jewels_total))),
          el('span.s', null, n(Math.max(0, ex.crown_jewels_total - reach)) + ' not reachable')),
        el('div.stat', null, el('span.cap', null, 'Top choke point'), el('span.v', null, top ? GX.pct(top.share) : '-'),
          el('span.s.mono.ellipsis', null, top ? top.key : props.me && !GX.can(props.me, 'graph:query') ? 'needs graph:query' : 'none')));

      var chainPanel = el('div', { style: { flex: '5 1 340px', minWidth: 0, borderLeft: '1px solid var(--line)', padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: '12px' } },
        el('div.row', null, el('span.cap', null, cheapest ? 'Cheapest route · ' + cheapest.steps.length + ' steps' : 'Cheapest route'),
          cheapest ? el('span.mono.faint', { style: { marginLeft: 'auto' } }, 'Σ effort ' + cheapest.cost) : null),
        cheapest ? VerticalChain({ steps: cheapest.steps, chokes: top ? [top.id] : [] })
          : el('p.dim', null, !GX.can(me, 'graph:query') ? 'Route details need the graph:query permission.' : ex.why || 'No route to show.'));

      var kinds = (ov.estate || {}).by_kind || {};
      var kindOrder = Object.keys(kinds).sort(function (a, b) { return kinds[b] - kinds[a]; });
      var palette = ['var(--accent)', 'color-mix(in srgb, var(--accent) 65%, var(--panel-3))', 'color-mix(in srgb, var(--accent) 40%, var(--panel-3))',
        'var(--jewel)', 'var(--low)', 'var(--line-2)', 'var(--text-3)'];
      var total = (ov.estate || {}).entities || 1;
      var estate = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '14px' } },
        el('div.row', null, el('span.cap', null, 'Estate'), el('span.faint', { style: { marginLeft: 'auto' } }, n(Object.keys((ov.estate || {}).by_zone || {}).length) + ' trust zones')),
        el('div.row', { style: { alignItems: 'baseline' } }, el('span', { style: { fontSize: '26px', fontWeight: 650 } }, n(ov.estate.entities)), el('span.dim', null, 'entities'),
          el('strong', null, n(ov.estate.relationships)), el('span.dim', null, 'relationships')),
        el('div.stack-bar', { role: 'img', 'aria-label': 'Entities by kind' }, kindOrder.map(function (k, i) {
          return el('i', { key: k, style: { width: (100 * kinds[k] / total) + '%', background: palette[i % palette.length] } });
        })),
        el('div.grid', { style: { gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '6px 16px' } }, kindOrder.map(function (k, i) {
          return el('div.row', { key: k, style: { flexWrap: 'nowrap' } }, el('i', { style: { width: '8px', height: '8px', borderRadius: '2px', background: palette[i % palette.length] } }),
            el('span.dim', { style: { flex: '1 1 auto' } }, GX.KIND[k] || k), el('span.mono', null, n(kinds[k])));
        }))));

      var crown = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '12px' } },
        el('div.row', null, el('span.cap', null, 'Crown jewels'), GX.can(me, 'graph:query') ? el('a', { href: '#/exposure', style: { marginLeft: 'auto', fontWeight: 600 } }, 'Routes to them') : null),
        el('div.row', { style: { alignItems: 'baseline' } }, el('span', { style: { fontSize: '26px', fontWeight: 650 } }, n(ex.crown_jewels_total)), el('span.dim', null, 'marked'),
          el('strong.jewel', null, n(reach)), el('span.dim', null, 'reachable from outside')),
        el('ul.stack', { style: { gap: '0' } }, (ex.targets || []).slice(0, 4).map(function (t) {
          return el('li.row', { key: t.id, style: { padding: '8px 0', borderTop: '1px solid var(--line)', flexWrap: 'nowrap' } },
            el('span', { style: { color: 'var(--jewel)' } }, icon('diamond', 14)),
            el('span', { style: { flex: '1 1 auto', minWidth: 0, display: 'flex', flexDirection: 'column' } },
              el('span.ellipsis', { style: { fontWeight: 600 } }, t.label), el('span.mono.faint.ellipsis', { style: { fontSize: '11.5px' } }, GX.NodeLink({ node: t }))),
            GX.Regimes({ regimes: t.regimes }),
            el('span', { style: { textAlign: 'right' } }, el('strong.mono', null, n(t.routes)), el('span.sub', null, 'routes')));
        })),
        ex.crown_jewels_total - reach > 0 ? el('p.faint', null, n(ex.crown_jewels_total - reach) + ' other' + (ex.crown_jewels_total - reach === 1 ? ' has' : 's have') +
          ' no route from outside at depth ' + ex.max_depth + '.') : null));

      var runs = ing ? ing.runs || [] : [];
      var ingest = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '12px' } },
        el('div.row', null, el('span.cap', null, 'Last ingest'), ing ? GX.Pill({ tone: ing.status === 'success' ? 'ok' : ing.status === 'degraded' ? 'warn' : 'bad', children: GX.cap1(ing.status) }) : null),
        !ing ? el('p.dim', null, GX.can(me, 'connector:read') ? 'No ingest has run yet.' : 'Ingest history needs connector:read.') : el(GX.Fragment, null,
          el('div.row', { style: { alignItems: 'baseline' } }, el('span', { style: { fontSize: '26px', fontWeight: 650 } }, GX.time(ing.finished_at)), el('span.dim', null, GX.zone),
            el('span.dim', null, GX.ago(ing.finished_at) + ' · ran ' + GX.duration(ing.duration_seconds))),
          el('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(' + Math.max(runs.length, 1) + ', 1fr)', gap: '4px' } }, runs.map(function (r) {
            return el('i', { key: r.connector, title: r.connector + ' ' + r.status, style: { height: '16px', borderRadius: '3px',
              background: r.status === 'success' ? 'color-mix(in srgb, var(--ok) 70%, transparent)' : 'var(--crit)' } });
          })),
          el('p.dim', null, (ing.succeeded) + ' of ' + ing.connectors_run + ' sources ran clean',
            runs.filter(function (r) { return r.status !== 'success'; }).map(function (r) { return el('span', { key: r.connector, style: { color: 'var(--crit)' } }, ' · ' + r.connector + ' failed'); })),
          el('div.row', { style: { borderTop: '1px solid var(--line)', paddingTop: '10px' } }, el('span.dim', null, 'Duplicate entities merged'), el('strong.mono', { style: { marginLeft: 'auto' } }, n(ing.merged)))),
        GX.can(me, 'connector:run') ? el('button.btn', { type: 'button', disabled: s.running, onClick: function () { self.run(); } }, s.running ? 'Running ingest' : 'Run ingest') : null));

      var f = ov.findings;
      var findings = f ? el('section.panel.clip', null,
        el('div.panel-head', null, el('div.row', null, el('h2', null, 'Findings'), el('span.faint', null, n(f.total) + ' open · severity comes from reachability to crown jewels, not CVSS')),
          el('a', { href: '#/findings', style: { fontWeight: 600 } }, 'All findings')),
        el('div.panel-body', null, el('div.grid.cols-4', { style: { gap: '12px' } }, GX.SEVERITIES.map(function (sv) {
          var says = { critical: 'reach a crown jewel cheaply from outside', high: 'reach regulated data or carry a choke point', medium: 'reach a crown jewel at more effort', low: 'reach nothing valuable' }[sv];
          return el('a.panel.hov', { key: sv, href: '#/findings', onClick: function () { GX.session.set('gx.findings.sev', sv); }, style: { padding: '12px 14px', color: 'var(--text)', boxShadow: 'none' } },
            GX.Sev({ level: sv }), el('div', { style: { fontSize: '24px', lineHeight: '30px', fontWeight: 650, margin: '6px 0 2px' } }, n(f.by_severity[sv])), el('span.sub', null, says));
        }))),
        el('div.tbl', null,
          el('div.th.cap', { style: { gridTemplateColumns: '100px minmax(0, 1fr) 140px 70px' } }, el('span', null, 'Severity'), el('span', null, 'Worst five'), el('span', null, 'Kind'), el('span.num', null, 'Routes')),
          f.worst.map(function (w) {
            return el('a.tr', { key: w.fingerprint, href: '#/findings', onClick: function () { GX.session.set('gx.finding', w.fingerprint); },
              style: { gridTemplateColumns: '100px minmax(0, 1fr) 140px 70px' } },
              GX.Pill({ tone: w.severity, children: GX.cap1(w.severity) }), el('span.ellipsis', null, w.title), el('span.dim', null, GX.FINDING_KIND[w.kind] || w.kind),
              el('span.num.mono', null, w.routes ? n(w.routes) : '-'));
          }))) : null;

      var rc = ov.recent || {};
      var recentCard = function (cap, big, items, empty) {
        return el('section.panel', null, el('div.panel-body.stack', { style: { gap: '10px' } }, el('span.cap', null, cap),
          el('div', { style: { fontSize: '20px', fontWeight: 650 } }, big),
          items && items.length ? el('ul.stack', { style: { gap: 0 } }, items) : el('p.dim', null, empty)));
      };
      var recent = el('div.stack', { style: { gap: '12px' } },
        el('div.row', null, el('h2', { style: { fontSize: '16px', fontWeight: 650 } }, 'Last ' + rc.window_hours + ' hours'),
          el('span.faint', null, 'up to ' + GX.day(ov.as_of) + ' ' + GX.time(ov.as_of) + ' ' + GX.zone)),
        el('div.grid.cols-3', null,
          recentCard('New relationships', n(rc.new_edge_count), (rc.new_edges || []).slice(0, 3).map(function (e, i) {
            return el('li', { key: i, style: { padding: '8px 0', borderTop: '1px solid var(--line)', display: 'grid', gridTemplateColumns: '48px minmax(0, 1fr)', gap: '10px' } },
              el('span.mono.faint', null, GX.time(e.first_seen)),
              el('span', null, el('span.mono', null, GX.NodeLink({ node: e.from })), ' ' + e.edge + ' ', el('span.mono', null, GX.NodeLink({ node: e.to }))));
          }), rc.new_edges ? 'Nothing new in the window.' : 'Details need graph:query.'),
          recentCard('Newly reachable systems', n(rc.new_reach_count) + ' system' + (rc.new_reach_count === 1 ? '' : 's'), (rc.new_reach || []).slice(0, 3).map(function (r, i) {
            return el('li', { key: i, style: { padding: '8px 0', borderTop: '1px solid var(--line)' } },
              el('span', null, el('span.mono', null, GX.NodeLink({ node: r.target })), ' is now reachable from ', el('span.mono', null, GX.NodeLink({ node: r.actor }))),
              el('span.sub', null, r.unflagged_by_rules ? 'No rule fired on any step of it' : 'A detection rule fired on this route'));
          }), rc.new_reach ? 'Nothing newly reachable.' : 'Details need graph:query.'),
          recentCard('Clustered incidents', n(rc.incident_count) + ' cluster' + (rc.incident_count === 1 ? '' : 's'), (rc.incidents || []).slice(0, 2).map(function (group, i) {
            return el('li', { key: i, style: { padding: '8px 0', borderTop: '1px solid var(--line)' } },
              el('span', null, group.length + ' connected entities'), el('span.sub.mono.ellipsis', null, group.slice(0, 4).map(function (g) { return g.key; }).join(' · ')));
          }), rc.incidents ? 'No connected anomalies.' : 'Details need graph:query.')));

      return el(GX.Fragment, null,
        head('Overview', (org.name || '') + (asOf(ov) ? ' · ' + asOf(ov) : '')),
        ingestBanner(ing), redactionNote(ov),
        el('section.panel', { style: { display: 'flex', flexWrap: 'wrap' } },
          el('div', { style: { flex: '7 1 480px', minWidth: 0, padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: '14px' } },
            el('span.cap', null, 'Can anyone get from outside to something valuable?'), answer, detail, tiles,
            GX.can(me, 'graph:query') && ex.reachable ? el('div.row', null,
              el('a.btn.primary', { href: '#/exposure' }, 'Open the cheapest route', icon('arrow', 15)),
              el('a.btn', { href: '#/exposure', onClick: function () { GX.session.set('gx.exposure.focus', 'fixes'); } }, 'See ranked fixes')) : null),
          chainPanel),
        el('div.grid.cols-3', null, estate, crown, ingest),
        findings,
        recent);
    }
  });

  /* A route top to bottom: tactic and technique on the edge, node below. */
  function VerticalChain(props) {
    var steps = props.steps, chokes = props.chokes || [];
    var rows = [];
    var dot = function (node) {
      var crown = node.is_crown_jewel, choke = chokes.indexOf(node.id) !== -1;
      return el('span', { style: { width: '22px', display: 'flex', justifyContent: 'center', color: crown ? 'var(--jewel)' : node.zone === 'untrusted' ? 'var(--text-2)' : 'var(--crit)' } },
        crown ? icon('diamond', 14) : node.zone === 'untrusted' ? icon('globe', 16)
          : el('i', { style: { width: '11px', height: '11px', borderRadius: '50%', border: '2px solid currentColor', display: 'block',
            boxShadow: choke ? '0 0 0 4px var(--panel), 0 0 0 6px color-mix(in srgb, var(--warn) 80%, transparent)' : 'none' } }));
    };
    var nodeRow = function (node, key) {
      return el('li', { key: key, style: { display: 'grid', gridTemplateColumns: '22px minmax(0, 1fr)', gap: '10px', alignItems: 'center' } }, dot(node),
        el('span.row', { style: { gap: '4px 10px' } }, el('span.mono', { style: { fontWeight: 600 } }, GX.NodeLink({ node: node })),
          node.label && node.label !== node.key ? el('span.dim', null, node.label) : null, el('span.faint', null, GX.ZONE[node.zone] || node.zone),
          chokes.indexOf(node.id) !== -1 ? GX.Pill({ tone: 'medium', children: 'choke point' }) : null));
    };
    rows.push(nodeRow(steps[0].from, 'start'));
    steps.forEach(function (s, i) {
      rows.push(el('li', { key: 'e' + i, style: { display: 'grid', gridTemplateColumns: '22px minmax(0, 1fr)', gap: '10px', alignItems: 'center' } },
        el('span', { style: { display: 'flex', justifyContent: 'center' } }, el('i', { style: { width: '2px', height: '22px', background: 'var(--crit)', display: 'block' } })),
        el('span.row', { style: { gap: '4px 8px' } }, el('span.cap', { style: { color: 'var(--text-2)' } }, s.tactic || s.edge),
          el('span.mono.faint', { style: { fontSize: '11.5px' } }, (s.technique || '') + ' · ' + s.cost))));
      rows.push(nodeRow(s.to, 'n' + i));
    });
    return el('ol.stack', { style: { gap: '4px' } }, rows);
  }
  GX.VerticalChain = VerticalChain;

  /* =============================================================== exposure */
  var DEPTHS = [1, 2, 3, 4, 5, 6];
  var LIMITS = [50, 100, 200, 400];

  GX.screens.exposure = GX.extend(GX.Loader, {
    init: function () {
      this.state.depth = 4; this.state.limit = 400; this.state.selected = 0; this.state.target = null;
    },
    load: function () {
      var q = GX.qs({ max_depth: this.state.depth, max_paths: this.state.limit });
      return Promise.all([GX.get('/v1/graph/exposure' + q), GX.get('/v1/graph/containment' + q), GX.get('/v1/graph/critical?limit=8')])
        .then(function (r) { return { exposure: r[0], containment: r[1], critical: r[2] }; });
    },
    componentDidUpdate: function () {
      if (this.state.data && GX.session.get('gx.exposure.focus') === 'fixes') {
        GX.session.set('gx.exposure.focus', null);
        var t = document.getElementById('fixes');
        if (t) t.scrollIntoView({ block: 'start' });
      }
    },
    pick: function (key, value) {
      var patch = {}; patch[key] = value; patch.selected = 0;
      var self = this;
      this.setState(patch, function () { self.reload(); });
    },
    render: function (props, s) {
      var self = this;
      var controls = el('div.row', { style: { alignItems: 'flex-end', gap: '16px' } },
        el('div.stack', { style: { gap: '6px' } }, el('span.cap#dl', null, 'Search depth'),
          el('div.seg', { role: 'group', 'aria-labelledby': 'dl' }, DEPTHS.map(function (d) {
            return el('button', { key: d, type: 'button', 'aria-pressed': String(s.depth === d), 'aria-label': 'Depth ' + d, onClick: function () { self.pick('depth', d); } }, d);
          }))),
        el('div.stack', { style: { gap: '6px' } }, el('span.cap#ll', null, 'Enumerate up to'),
          el('div.seg', { role: 'group', 'aria-labelledby': 'll' }, LIMITS.map(function (d) {
            return el('button', { key: d, type: 'button', 'aria-pressed': String(s.limit === d), onClick: function () { self.pick('limit', d); } }, d);
          }))));
      if (s.error) return el(GX.Fragment, null, head('Exposure', null, controls), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      if (!s.data) return el(GX.Fragment, null, head('Exposure', 'Routes from the internet to your crown jewels', controls), GX.Loading({ label: 'Enumerating routes' }));
      var ex = s.data.exposure, co = s.data.containment, crit = s.data.critical.nodes || [];
      var sub = 'Routes from the internet to your crown jewels' + (props.overview ? ' · ' + asOf(props.overview) : '');
      if (!ex.reachable) {
        var none = !ex.crown_jewels_total;
        return el(GX.Fragment, null, head('Exposure', sub, controls), redactionNote(ex),
          el('section.panel', null, el('div.empty', { style: { padding: '48px 24px' } },
            el('span', { style: { color: none ? 'var(--warn)' : 'var(--ok)' } }, icon(none ? 'warn' : 'check', 28)),
            el('strong', null, none ? 'Nothing is marked as a crown jewel yet' : 'No route reaches a crown jewel at depth ' + s.depth),
            el('p', { style: { maxWidth: '60ch' } }, none
              ? 'Exposure is measured as routes to the systems that matter, so until one is marked there is nothing to measure. ' +
                'Open any system from search and mark it as a crown jewel, or connect a CMDB that classifies data.'
              : 'Searched ' + n(ex.entry_points) + ' entry points against ' + n(ex.crown_jewels_total) + ' crown jewels. ' +
                (s.depth < 6 ? 'A deeper search may still find longer routes.' : 'This is the deepest search the engine runs.')),
            !none && s.depth < 6 ? el('button.btn', { type: 'button', onClick: function () { self.pick('depth', Math.min(6, s.depth + 2)); } }, 'Search to depth ' + Math.min(6, s.depth + 2)) : null)));
      }
      var paths = ex.paths || [];
      var shown = s.target ? paths.filter(function (p) { return p.steps[p.steps.length - 1].to.id === s.target; }) : paths;
      var sel = shown[s.selected] || shown[0] || paths[0];
      var chokeIds = (ex.choke_points || []).map(function (c) { return c.id; });
      var top = (ex.choke_points || [])[0];
      var tiles = el('div.grid.cols-4', null,
        el('div.panel.stat', null, el('span.cap', null, 'Routes found'), el('span.v', { style: { color: 'var(--crit)' } }, n(ex.path_count)),
          el('span.s', null, paths.length + ' shown · depth ' + ex.max_depth + ' · ' + (ex.capped ? 'cap reached, so this is a floor' : 'limit ' + n(ex.max_paths)))),
        el('div.panel.stat', null, el('span.cap', null, 'Cheapest route'), el('span.v', null, ex.cheapest.cost + ' effort'),
          el('span.s.ellipsis', null, ex.cheapest.steps.length + ' steps · ' + ex.cheapest.steps[0].from.key + ' to ' + ex.cheapest.steps[ex.cheapest.steps.length - 1].to.key)),
        el('div.panel.stat', null, el('span.cap', null, 'Crown jewels in reach'), el('span.v.jewel', null, n(ex.targets.length) + ' of ' + n(ex.crown_jewels_total)),
          el('span.s.ellipsis', null, ex.targets.map(function (t) { return t.key; }).join(', '))),
        el('div.panel.stat', null, el('span.cap', null, 'Top choke point'), el('span.v', null, top ? GX.pct(top.share) : '-'),
          el('span.s.ellipsis', null, top ? top.key + ' · ' + n(top.paths_through) + ' routes' : 'none')));

      var routeIndex = sel ? paths.indexOf(sel) : -1;
      var map = sel ? el('section.panel.clip', null,
        el('div.panel-head', null, el('div.row', null, el('h2', null, 'Route ' + (routeIndex + 1) + ' of ' + paths.length),
          el('span.dim', null, sel.cost + ' effort · ' + sel.steps.length + ' steps · ' + sel.steps[0].from.key + ' to ' + sel.steps[sel.steps.length - 1].to.key)),
          el('div.legend', null, el('span', null, el('i', { style: { width: '16px', borderTop: '2px dashed var(--crit)', display: 'inline-block' } }), 'Route'),
            el('span', null, el('i', { style: { width: '10px', height: '10px', borderRadius: '50%', border: '1.5px dashed var(--warn)', display: 'inline-block' } }), 'Choke point'))),
        el('div.route-map', null, RouteMap({ steps: sel.steps, chokes: ex.choke_points || [], total: ex.path_count }))) : null;

      var routes = el('section.panel.clip', { style: { flex: '7 1 520px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Routes'), el('span.faint', null, shown.length + ' of ' + n(ex.path_count) + ' shown · cheapest first')),
        el('div.row', { style: { padding: '12px 18px', borderBottom: '1px solid var(--line)', gap: '8px' } },
          el('button.chip', { type: 'button', 'aria-pressed': String(!s.target), onClick: function () { self.setState({ target: null, selected: 0 }); } }, 'All crown jewels', el('span.n.mono', null, n(ex.path_count))),
          ex.targets.map(function (t) {
            return el('button.chip', { key: t.id, type: 'button', 'aria-pressed': String(s.target === t.id), onClick: function () { self.setState({ target: t.id, selected: 0 }); } },
              t.key, el('span.n.mono', null, n(t.routes)));
          })),
        el('div.tbl', null,
          el('div.th.cap', { style: { gridTemplateColumns: '56px minmax(0, 1fr) 110px' } }, el('span', null, 'Effort'), el('span', null, 'Steps, with ATT&CK tactic'), el('span.num', null, 'Zones')),
          shown.length ? shown.map(function (p, i) {
            var last = p.steps[p.steps.length - 1].to;
            return el('div.tr' + (p === sel ? '.on' : ''), { key: i, role: 'button', tabIndex: 0, style: { gridTemplateColumns: '56px minmax(0, 1fr) 110px', alignItems: 'start', cursor: 'pointer' },
              onClick: function (ev) { if (ev.target.closest('a')) return; self.setState({ selected: i }); },
              onKeyDown: function (ev) { if (ev.key === 'Enter') self.setState({ selected: i }); } },
              el('span', null, el('strong', { style: { fontSize: '16px' } }, p.cost), el('span.sub.mono', null, '#' + (paths.indexOf(p) + 1))),
              GX.Chain({ steps: p.steps }),
              el('span.num.dim', null, (GX.ZONE[p.steps[0].from.zone] || '') + ' to ' + (GX.ZONE[last.zone] || ''), el('span.sub', null, p.steps.length + ' steps')));
          }) : GX.Empty({ title: 'No route to that crown jewel among the ' + paths.length + ' shown' }, 'It is reached only by routes beyond the first page. Raise the limit or pick another.')));

      var fixes = el('section.panel.clip#fixes', { style: { flex: '5 1 360px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Ranked fixes'), el('span.faint', null, 'each one measured by making the cut')),
        (co.options || []).length ? el('ol', null, co.options.map(function (o, i) {
          var out = o.crown_jewels_cut_off || [];
          return el('li.fix', { key: i },
            el('span.rank.mono', null, i + 1),
            el('div.stack', { style: { gap: '6px' } },
              el('span', null, GX.Pill({ tone: o.kind === 'node' ? 'high' : 'accent', children: o.kind === 'node' ? 'Take system down' : 'Revoke permission' }),
                o.fully_contained ? el('span', { style: { marginLeft: '6px' } }, GX.Pill({ tone: 'ok', children: 'Closes every route' })) : null),
              el('strong', { style: { fontWeight: 600 } }, GX.cap1(o.cut.action) + '.'),
              el('span.facts', null, el('span', null, el('strong.mono', { style: { color: 'var(--text)' } }, '-' + n(o.routes_removed)), ' routes (' + GX.pct(o.routes_removed / o.routes_before) + ')'),
                el('span', null, 'Cheapest effort ', el('strong.mono', { style: { color: 'var(--text)' } }, o.cheapest_before + ' → ' + (o.cheapest_after === null ? 'none' : o.cheapest_after)))),
              out.length ? el('span', { style: { color: 'var(--jewel)', fontWeight: 600 } }, 'Out of reach afterwards: ' + out.map(function (j) { return j.key; }).join(', '))
                : el('span.faint', null, o.effort_added ? 'Every crown jewel stays in reach, at ' + o.effort_added + ' more effort' : 'Every crown jewel stays in reach, and the attacker is no worse off')));
        })) : GX.Empty({ title: 'No single cut changes the picture' }, co.why || 'Every candidate was measured and none removes a route.'));

      var chokes = el('section.panel.clip', { style: { flex: '5 1 380px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Choke points'), el('span.faint', null, 'top ' + (ex.choke_points || []).length + ' · share of ' + n(ex.path_count) + ' routes')),
        el('div.tbl', null,
          el('div.th.cap', { style: { gridTemplateColumns: 'minmax(0, 1fr) 64px 140px' } }, el('span', null, 'Node'), el('span.num', null, 'Routes'), el('span', null, 'Share')),
          (ex.choke_points || []).map(function (c) {
            return el('a.tr', { key: c.id, href: '#/node', onClick: function (ev) { ev.preventDefault(); GX.openNode(c.id); }, style: { gridTemplateColumns: 'minmax(0, 1fr) 64px 140px' } },
              el('span', { style: { minWidth: 0 } }, el('span.mono.ellipsis', { style: { display: 'block' } }, c.key), el('span.sub', null, (GX.KIND[c.kind] || c.kind) + ' · ' + (GX.ZONE[c.zone] || c.zone))),
              el('span.num.mono', null, n(c.paths_through)),
              el('span.row', { style: { flexWrap: 'nowrap', gap: '8px' } }, el('span.bar', { style: { flex: '1 1 auto' } }, el('i', { style: { width: (c.share * 100) + '%' } })), el('span.mono.faint', null, GX.pct(c.share))));
          })));

      var maxThrough = Math.max.apply(null, crit.map(function (c) { return c.routes_through; }).concat([1]));
      var critical = el('section.panel.clip', { style: { flex: '7 1 520px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Critical systems'), el('span.faint', null, 'ranked by PageRank on the reversed graph, so the way in outranks the prize')),
        el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '560px' } },
          el('div.th.cap', { style: { gridTemplateColumns: '28px minmax(0, 1fr) 90px 80px 60px 150px' } }, el('span', null, '#'), el('span', null, 'System'), el('span', null, 'Zone'), el('span', null, 'Facing'),
            el('span.num', null, 'Jewels'), el('span', null, 'Routes through')),
          crit.map(function (c, i) {
            return el('a.tr', { key: c.id, href: '#/node', onClick: function (ev) { ev.preventDefault(); GX.openNode(c.id); }, style: { gridTemplateColumns: '28px minmax(0, 1fr) 90px 80px 60px 150px' } },
              el('span.faint', null, i + 1),
              el('span', { style: { minWidth: 0 } }, el('span.mono.ellipsis' + (c.is_crown_jewel ? '.jewel' : ''), { style: { display: 'block' } }, c.key), el('span.sub', null, GX.KIND[c.kind] || c.kind)),
              el('span.dim', null, GX.ZONE[c.zone] || c.zone),
              el('span', { style: { color: c.facing_internet ? 'var(--crit)' : 'var(--text-2)', fontWeight: c.facing_internet ? 600 : 400 } }, c.facing_internet ? 'Internet' : 'Internal'),
              el('span.num.mono.jewel', null, n(c.crown_jewels_reached)),
              el('span.row', { style: { flexWrap: 'nowrap', gap: '8px' } }, el('span.bar.accent', { style: { flex: '1 1 auto' } }, el('i', { style: { width: (100 * c.routes_through / maxThrough) + '%' } })),
                el('span.mono.faint', { style: { minWidth: '28px', textAlign: 'right' } }, n(c.routes_through))));
          }))));

      return el(GX.Fragment, null, head('Exposure', sub, controls), props.overview ? ingestBanner(props.overview.last_ingest) : null,
        redactionNote(ex), tiles, map, el('div.split', null, routes, fixes), el('div.split', null, chokes, critical));
    }
  });

  /* One route drawn across its zones. Every node, tactic and cost is the
     selected route's own; nothing is decorative. */
  function RouteMap(props) {
    var h = GX.h, steps = props.steps;
    var nodes = [steps[0].from].concat(steps.map(function (s) { return s.to; }));
    var colW = 230, pad = 80, W = Math.max(1080, pad * 2 + colW * (nodes.length - 1) + 60), H = 210, cy = 118;
    var x = function (i) { return pad + 30 + i * ((W - pad * 2 - 60) / Math.max(1, nodes.length - 1)); };
    var chokes = {};
    (props.chokes || []).forEach(function (c) { chokes[c.id] = c; });
    var kids = [];
    nodes.forEach(function (node, i) {
      var left = i === 0 ? 0 : (x(i - 1) + x(i)) / 2, right = i === nodes.length - 1 ? W : (x(i) + x(i + 1)) / 2;
      kids.push(h('rect', { key: 'z' + i, x: left, y: 0, width: right - left, height: H,
        fill: node.is_crown_jewel ? 'color-mix(in srgb, var(--jewel) 8%, transparent)' : i % 2 ? 'var(--panel-2)' : 'transparent' }));
      kids.push(h('text', { key: 'zl' + i, x: left + 14, y: 22, fill: node.is_crown_jewel ? 'var(--jewel)' : 'var(--text-3)', 'font-size': 10.5,
        'font-weight': 600, 'letter-spacing': 1.1 }, (GX.ZONE[node.zone] || node.zone || '').toUpperCase()));
    });
    steps.forEach(function (s, i) {
      var x1 = x(i) + 22, x2 = x(i + 1) - 24;
      kids.push(h('line', { key: 'l' + i, x1: x1, y1: cy, x2: x2, y2: cy, stroke: 'var(--crit)', 'stroke-width': 2, 'stroke-dasharray': '5 4' }));
      kids.push(h('path', { key: 'h' + i, d: 'M' + x2 + ' ' + (cy - 5) + 'l7 5-7 5z', fill: 'var(--crit)' }));
      kids.push(h('text', { key: 't' + i, x: (x1 + x2) / 2, y: cy + 22, 'text-anchor': 'middle', fill: 'var(--text-2)', 'font-size': 10, 'font-weight': 600, 'letter-spacing': 1 },
        (s.tactic || s.edge).toUpperCase()));
      kids.push(h('text', { key: 'q' + i, x: (x1 + x2) / 2, y: cy + 37, 'text-anchor': 'middle', fill: 'var(--text-3)', 'font-size': 11, 'font-family': 'JetBrains Mono, monospace' },
        (s.technique ? s.technique + ' · ' : '') + s.cost));
    });
    nodes.forEach(function (node, i) {
      var cx = x(i), crown = node.is_crown_jewel, choke = chokes[node.id];
      var stroke = crown ? 'var(--jewel)' : node.zone === 'untrusted' ? 'var(--text-2)' : 'var(--crit)';
      var group = [];
      if (choke) {
        group.push(h('circle', { key: 'cr', cx: cx, cy: cy, r: 28, fill: 'none', stroke: 'var(--warn)', 'stroke-width': 1.5, 'stroke-dasharray': '3 3' }));
        group.push(h('rect', { key: 'cb', x: cx - 44, y: 32, width: 88, height: 18, rx: 4, fill: 'color-mix(in srgb, var(--warn) 18%, var(--panel))', stroke: 'var(--warn)', 'stroke-width': 1 }));
        group.push(h('text', { key: 'ct', x: cx, y: 45, 'text-anchor': 'middle', fill: 'var(--warn)', 'font-size': 10, 'font-weight': 700, 'letter-spacing': .8 }, 'CHOKE · ' + GX.pct(choke.share)));
      }
      group.push(h('circle', { key: 'c', cx: cx, cy: cy, r: 21, fill: 'var(--panel)', stroke: stroke, 'stroke-width': 2 }));
      group.push(h('g', { key: 'i', transform: 'translate(' + (cx - 9) + ' ' + (cy - 9) + ')', style: { color: stroke } }, GX.icon(GX.kindIcon(node.kind, crown), 18)));
      group.push(h('text', { key: 'k', x: cx, y: cy - 46 + (choke ? 0 : 0), 'text-anchor': 'middle', fill: crown ? 'var(--jewel)' : 'var(--text)', 'font-size': 12,
        'font-weight': 600, 'font-family': 'JetBrains Mono, monospace' }, node.key.length > 26 ? node.key.slice(0, 25) + '…' : node.key));
      group.push(h('text', { key: 'd', x: cx, y: cy + 62, 'text-anchor': 'middle', fill: 'var(--text-3)', 'font-size': 11 },
        (GX.KIND[node.kind] || node.kind) + (node.regimes && node.regimes.length ? ' · ' + node.regimes.join(', ') : '')));
      kids.push(h('a', { key: 'n' + i, href: '#/node', onClick: function (ev) { ev.preventDefault(); GX.openNode(node.id); }, 'aria-label': 'Open ' + node.key }, group));
    });
    var note = null;
    var chokeOnRoute = nodes.filter(function (nd) { return chokes[nd.id]; })[0];
    if (chokeOnRoute) {
      var c = chokes[chokeOnRoute.id];
      note = h('text', { x: W - 16, y: H - 12, 'text-anchor': 'end', fill: 'var(--text-2)', 'font-size': 11.5 },
        n(c.paths_through) + ' of ' + n(props.total) + ' routes (' + GX.pct(c.share) + ') pass through ' + chokeOnRoute.key);
    }
    return h('svg', { viewBox: '0 0 ' + W + ' ' + H, width: W, height: H, role: 'img', 'aria-label': 'The selected route across its trust zones' }, kids, note);
  }

  /* ================================================================== node */
  GX.screens.node = GX.extend(GX.Loader, {
    init: function () { this.state.hops = 3; this.state.blast = null; this.state.dormantOnly = false; },
    load: function () {
      var id = GX.session.get('gx.node');
      if (!id) return Promise.reject(new GX.ApiError(404, {}));
      var self = this;
      return GX.get('/v1/graph/nodes/' + encodeURIComponent(id)).then(function (d) { self.loadBlast(d.node.id, self.state.hops); return d; });
    },
    loadBlast: function (id, hops) {
      var self = this;
      self.setState({ hops: hops, blastBusy: true });
      GX.post('/v1/graph/blast-radius', { node_id: id, hops: hops }).then(function (b) { self.setState({ blast: b, blastBusy: false }); },
        function () { self.setState({ blast: null, blastBusy: false }); });
    },
    mark: function (crown) {
      var self = this, node = self.state.data.node;
      GX.post('/v1/graph/crown-jewels', { node_id: node.id, crown: crown, reason: crown ? 'marked from the console' : 'unmarked from the console' }).then(function () {
        GX.toast(node.key + (crown ? ' is now a crown jewel. Every answer uses it from now on.' : ' is no longer a crown jewel.'));
        self.reload(); self.props.refreshOverview();
      }, function (e) { GX.toast(e.status === 400 ? 'An address on the internet cannot be a crown jewel.' : 'That change was not saved.', 'bad'); });
    },
    render: function (props, s) {
      var self = this, me = props.me;
      if (s.error) {
        return el(GX.Fragment, null, el('div.crumbs', null, el('a', { href: '#/exposure' }, 'Exposure'), ' / ', 'Node'),
          s.error.status === 404 ? GX.Empty({ title: 'That entity is not in this estate' }, 'It may have gone in the last ingest. Search for it from the top bar.')
            : GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      }
      if (!s.data) return GX.Loading({});
      var d = s.data, node = d.node;
      var crown = node.is_crown_jewel;
      var srcs = node.sources || [];
      var segment = d.segment;
      var actions = el('div.row', null,
        GX.can(me, 'crown:write') && node.zone !== 'untrusted' && !node.redacted ? el('button.btn', { type: 'button', onClick: function () { self.mark(!crown); } },
          crown ? 'Unmark as crown jewel' : 'Mark as crown jewel') : null,
        d.routes.count ? el('a.btn', { href: '#routes', onClick: function (ev) { ev.preventDefault(); var t = document.getElementById('routes'); if (t) t.scrollIntoView(); } }, 'Show its routes') : null);
      var facts = el('div.kv', null,
        el('div', null, el('span.cap', null, 'Kind'), el('b', null, (GX.KIND[node.kind] || node.kind) + (node.principal_type ? ' · ' + node.principal_type : ''))),
        el('div', null, el('span.cap', null, 'Trust zone'), el('b', null, GX.ZONE[node.zone] || node.zone)),
        el('div', null, el('span.cap', null, 'Crown jewel'), el('b', { 'class': crown ? 'jewel' : '' }, crown ? 'Yes' + (node.regimes && node.regimes.length ? ' · ' + node.regimes.join(', ') : '') : 'No'),
          node.crown_override ? el('span.sub', null, 'set in the console') : node.crown_source ? el('span.sub', null, 'from ' + node.crown_source.split('.')[0]) : null),
        el('div', null, el('span.cap', null, 'Segment'), el('b.ellipsis', null, segment ? segment.label : '-')),
        el('div', null, el('span.cap', null, 'Choke point'), d.choke ? el('b', { style: { color: 'var(--warn)' } }, n(d.choke.routes_through) + ' of ' + n(d.routes.total_in_estate) + ' routes · ' + GX.pct(d.choke.share))
          : el('b.dim', null, 'No')));

      var header = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '14px' } },
        el('div.row', { style: { alignItems: 'flex-start', gap: '16px' } },
          el('span', { style: { width: '52px', height: '52px', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '2px solid ' + (crown ? 'var(--jewel)' : 'var(--crit)'), color: crown ? 'var(--jewel)' : 'var(--text)' } }, icon(GX.kindIcon(node.kind, crown), 24)),
          el('div.stack', { style: { flex: '1 1 320px', minWidth: 0 } },
            el('h1', { style: { fontSize: '22px', lineHeight: '28px', fontWeight: 650 } }, node.label),
            el('div.row', { style: { gap: '8px' } }, el('span.mono.dim', null, node.key),
              navigator.clipboard ? el('button.btn.small', { type: 'button', onClick: function () { navigator.clipboard.writeText(node.key).then(function () { GX.toast('Copied ' + node.key); }); } }, 'Copy') : null,
              node.suspended ? GX.Pill({ tone: 'bad', children: 'Suspended in the identity provider' }) : null,
              d.is_entry_point ? GX.Pill({ tone: 'high', children: 'Entry point' }) : null),
            srcs.length ? el('p.dim', null, (srcs.length > 1 ? 'Merged from ' + srcs.length + ' sources, ' : 'Reported by ') + srcs.join(', ') +
              ((node.resolved_from || []).length ? '. Also known as ' + node.resolved_from.join(', ') : '') + (node.arn ? '. ' + node.arn : '') + '.') : null,
            node.owner || node.environment ? el('p.faint', null, [node.owner ? 'Owned by ' + node.owner : null, node.environment ? 'used for ' + node.environment : null].filter(Boolean).join(', ') + '.') : null),
          actions),
        facts));

      var b = s.blast;
      var rings = b ? Object.keys(b.hops).map(function (k) { return { hop: +k, members: b.hops[k] }; }) : [];
      var blast = el('section.panel', null,
        el('div.panel-head', { style: { alignItems: 'center' } }, el('div.stack', null, el('h2', null, 'Blast radius'),
          el('span.faint', null, 'What a compromise of this ' + (GX.KIND[node.kind] || 'entity').toLowerCase() + ' reaches. Each entity is counted once, at its nearest hop.')),
          el('div.stack', { style: { gap: '6px' } }, el('span.cap', null, 'Hops'), el('div.seg', { role: 'group', 'aria-label': 'Hops' }, DEPTHS.map(function (hh) {
            return el('button', { key: hh, type: 'button', 'aria-pressed': String(s.hops === hh), onClick: function () { self.loadBlast(node.id, hh); } }, hh);
          })))),
        !b ? GX.Loading({}) : el('div.panel-body', { style: { display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'flex-start' } },
          el('div.stack', { style: { flex: '1 1 260px', gap: '12px' } }, el('div.blast-rings', null, Rings({ rings: rings, crown: b.crown_jewels_reached.length })),
            el('div.kv', null, el('div', null, el('span.cap', null, 'Within ' + s.hops + ' hop' + (s.hops === 1 ? '' : 's')), el('b', { style: { fontSize: '20px' } }, n(b.total))),
              el('div', null, el('span.cap', null, 'Crown jewels'), el('b.jewel', { style: { fontSize: '20px' } }, n(b.crown_jewels_reached.length))))),
          el('div.grid', { style: { flex: '3 1 520px', gridTemplateColumns: 'repeat(auto-fit, minmax(min(240px, 100%), 1fr))', gap: '12px' } }, rings.map(function (r) {
            var list = r.members.slice().sort(function (a, c) { return (c.is_crown_jewel ? 1 : 0) - (a.is_crown_jewel ? 1 : 0); });
            return el('div.hop-col', { key: r.hop }, el('div.head', null, el('span.cap', null, 'Hop ' + r.hop), el('strong.mono', null, n(r.members.length))),
              el('ul', null, list.slice(0, 10).map(function (m) {
                return el('li', { key: m.id, style: { display: 'flex', gap: '6px', alignItems: 'flex-start' } }, m.is_crown_jewel ? el('span.jewel', null, icon('diamond', 12)) : null,
                  el('span', { style: { minWidth: 0 } }, el('span.mono', { style: { display: 'block' } }, GX.NodeLink({ node: m })), el('span.sub', null, GX.KIND[m.kind] || m.kind)));
              }), list.length > 10 ? el('li.faint', null, '+ ' + n(list.length - 10) + ' more') : null));
          }))));

      var routes = el('section.panel.clip#routes', { style: { flex: '7 1 520px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Routes through this ' + (GX.KIND[node.kind] || 'entity').toLowerCase())),
        el('div.notice', null, d.routes.count ? n(d.routes.count) + ' of ' + n(d.routes.total_in_estate) + ' routes pass through it. Cheapest ' + Math.min(5, d.routes.count) + ':'
          : 'No route from the internet to a crown jewel passes through it.'),
        d.routes.cheapest.map(function (r, i) {
          return el('div', { key: i, style: { display: 'grid', gridTemplateColumns: '40px minmax(0, 1fr)', gap: '10px', padding: '10px 18px', borderBottom: '1px solid var(--line)' } },
            el('strong', { style: { fontSize: '16px' } }, r.cost), GX.Chain({ steps: r.steps }));
        }));

      var seg = segment ? el('section.panel', { style: { flex: '5 1 340px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, 'Segment'), el('span.faint', null, n(segment.size) + ' entities')),
        el('div.panel-body.stack', { style: { gap: '12px' } },
          el('strong', { style: { fontSize: '16px' } }, GX.cap1(segment.label)),
          el('p.dim', null, segment.shared ? n(segment.shared.members) + ' of ' + n(segment.size) + ' members share the ' + segment.shared.field + ' ' + segment.shared.value + ' in their sources.'
            : 'Community detection groups entities that mostly connect to each other. Its members share no owner or environment, so it is described by what it holds.'),
          segment.exits.length ? el('div.stack', { style: { gap: '6px', borderTop: '1px solid var(--line)', paddingTop: '10px' } }, el('span.cap', null, 'Where it reaches out'),
            segment.exits.map(function (x, i) { return el('span', { key: i }, el('span.mono', null, GX.NodeLink({ node: x.from })), ' reaches ', el('span.mono', null, GX.NodeLink({ node: x.to }))); })) : null,
          el('div.stack', { style: { gap: '6px', borderTop: '1px solid var(--line)', paddingTop: '10px' } }, el('span.cap', null, 'Members'),
            el('div.row', { style: { gap: '6px' } }, segment.members.map(function (m) { return el('span.pill.outline.mono', { key: m.id }, GX.NodeLink({ node: m })); }))))) : null;

      var grants = d.grants.filter(function (g) { return !s.dormantOnly || g.status === 'never' || g.status === 'idle'; });
      var used = d.grants.filter(function (g) { return g.status === 'used'; }).length;
      var ent = d.grants.length ? el('section.panel.clip', null,
        el('div.panel-head', null, el('div.stack', null, el('h2', null, 'Entitled against used'),
          el('span.faint', null, 'Grants from the identity provider, against use seen in the logs. Idle means unused for ' + 90 + ' days.')),
          el('button.toggle', { type: 'button', 'aria-pressed': String(s.dormantOnly), onClick: function () { self.setState({ dormantOnly: !s.dormantOnly }); } }, el('span.track'), 'Dormant only')),
        el('div.panel-body', { style: { display: 'flex', flexWrap: 'wrap', gap: '16px' } },
          el('div.stack', { style: { flex: '1 1 320px', gap: '8px' } },
            el('div.row', { style: { flexWrap: 'nowrap' } }, el('span.dim', { style: { width: '70px' } }, 'Entitled'), el('span.bar', { style: { flex: '1 1 auto' } }, el('i', { style: { width: '100%', background: 'var(--line-2)' } })), el('strong.mono', null, n(d.grants.length))),
            el('div.row', { style: { flexWrap: 'nowrap' } }, el('span.dim', { style: { width: '70px' } }, 'Used'), el('span.bar.accent', { style: { flex: '1 1 auto' } }, el('i', { style: { width: (100 * used / d.grants.length) + '%' } })), el('strong.mono', null, n(used))))),
        el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '640px' } },
          el('div.th.cap', { style: { gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr) 110px 100px 90px 60px' } }, el('span', null, 'Resource'), el('span', null, 'Permission'), el('span', null, 'Via'), el('span', null, 'Last used'), el('span', null, 'Status'), el('span.num', null, 'Routes')),
          grants.map(function (g, i) { return GrantRow(g, i, 'target'); })))) : null;

      var grantees = d.grantees.length ? el('section.panel.clip', null,
        el('div.panel-head', null, el('h2', null, 'Who is granted access to this'), el('span.faint', null, n(d.grantees.length) + ' grants')),
        el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '640px' } },
          el('div.th.cap', { style: { gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr) 110px 100px 90px 60px' } }, el('span', null, 'Identity'), el('span', null, 'Permission'), el('span', null, 'Via'), el('span', null, 'Last used'), el('span', null, 'Status'), el('span.num', null, 'Routes')),
          d.grantees.map(function (g, i) { return GrantRow(g, i, 'identity'); })))) : null;

      return el(GX.Fragment, null,
        el('div.crumbs', null, el('a', { href: '#/exposure' }, 'Exposure'), ' / ', el('span.mono', null, node.key)),
        redactionNote(d), header, blast, el('div.split', null, routes, seg), ent, grantees);
    }
  });

  function lastUsed(g) {
    if (g.status === 'unknown') return el('span.faint', null, 'Not reported');
    if (!g.last_used) return el('span', { style: { color: 'var(--crit)', fontWeight: 600 } }, 'Never');
    return el('span', null, g.idle_days === 0 ? 'Today' : n(g.idle_days) + ' days', el('span.sub', null, GX.day(g.last_used)));
  }
  var STATUS = { used: ['ok', 'Used'], idle: ['warn', 'Idle'], never: ['bad', 'Never used'], unknown: ['outline', 'Unverified'] };
  function GrantRow(g, i, side) {
    var who = g[side];
    var st = STATUS[g.status] || ['outline', g.status];
    return el('div.tr', { key: i, style: { gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr) 110px 100px 90px 60px' } },
      el('span', { style: { minWidth: 0 } }, el('span.ellipsis', { style: { display: 'block' } }, GX.NodeLink({ node: who })),
        side === 'identity' && who.principal_type ? el('span.sub', null, who.principal_type) : el('span.sub', null, GX.KIND[who.kind] || who.kind)),
      el('span.mono.dim.ellipsis', null, g.permission || '-'),
      el('span.dim', null, g.via || '-'), lastUsed(g), GX.Pill({ tone: st[0], children: st[1] }),
      el('span.num.mono', null, g.routes_through ? n(g.routes_through) : '-'));
  }
  GX.GrantRow = GrantRow;

  function Rings(props) {
    var h = GX.h, rings = props.rings;
    var max = Math.max(rings.length, 1), size = 260, c = size / 2;
    var kids = [];
    for (var i = max; i >= 1; i--) {
      var r = 26 + (c - 30) * i / max;
      kids.push(h('circle', { key: 'r' + i, cx: c, cy: c, r: r, fill: 'color-mix(in srgb, var(--crit) ' + (4 + 6 * (max - i + 1) / max) + '%, var(--panel))', stroke: 'var(--line-2)', 'stroke-width': 1 }));
      var ring = rings[i - 1];
      kids.push(h('text', { key: 't' + i, x: c, y: c - r + 14, 'text-anchor': 'middle', fill: 'var(--text-2)', 'font-size': 10.5, 'font-family': 'JetBrains Mono, monospace' },
        ring ? ring.hop + ' · ' + n(ring.members.length) : ''));
    }
    var jewels = [];
    rings.forEach(function (ring, idx) {
      ring.members.filter(function (m) { return m.is_crown_jewel; }).forEach(function (m) { jewels.push({ idx: idx, m: m }); });
    });
    jewels.forEach(function (j, k) {
      var r = 26 + (c - 30) * (j.idx + 1) / max - 12;
      var a = (k * 2.4) + 0.6;
      var x = c + r * Math.cos(a), y = c + r * Math.sin(a);
      kids.push(h('path', { key: 'j' + k, d: 'M' + x + ' ' + (y - 8) + 'l8 8-8 8-8-8z', fill: 'var(--jewel)' }, h('title', null, j.m.key)));
    });
    kids.push(h('circle', { key: 'o', cx: c, cy: c, r: 18, fill: 'var(--panel)', stroke: 'var(--crit)', 'stroke-width': 2 }));
    return h('svg', { viewBox: '0 0 ' + size + ' ' + size, role: 'img', 'aria-label': 'Blast radius rings by hop' }, kids);
  }

  /* ================================================================= access */
  var PAGE = 50;
  GX.screens.access = GX.extend(GX.Loader, {
    init: function () { this.state.q = ''; this.state.regulated = true; this.state.status = 'dormant'; this.state.ptype = ''; this.state.limit = PAGE; },
    load: function () {
      var s = this.state;
      return GX.get('/v1/graph/over-privilege' + GX.qs({ q: s.q, regulated: s.regulated ? 'true' : '', status: s.status, principal_type: s.ptype, limit: s.limit }));
    },
    set: function (patch) {
      var self = this;
      patch.limit = patch.limit || PAGE;
      this.setState(patch, function () {
        clearTimeout(self._t);
        self._t = setTimeout(function () { self.reload(); }, patch.q !== undefined ? 250 : 0);
      });
    },
    render: function (props, s) {
      var self = this;
      if (s.error) return el(GX.Fragment, null, head('Access'), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      var d = s.data;
      var sub = 'Who can reach what, and whether they use it. A grant counts as used when it was exercised in the last ' + (d ? d.idle_after_days : 90) + ' days.';
      if (!d) return el(GX.Fragment, null, head('Access', sub), GX.Loading({}));
      var bs = d.by_status, dormant = bs.never + bs.idle;
      var total = Math.max(d.granted, 1);
      var summary = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '14px' } },
        el('div.grid.cols-4', { style: { gap: '12px' } },
          el('div.stack', null, el('span.cap', null, 'Granted'), el('span', { style: { fontSize: '28px', lineHeight: '34px', fontWeight: 650 } }, n(d.granted)), el('span.sub', null, 'grants across the estate')),
          el('div.stack', null, el('span.cap', null, 'Exercised'), el('span', { style: { fontSize: '28px', lineHeight: '34px', fontWeight: 650, color: 'var(--accent)' } }, n(d.exercised)), el('span.sub', null, GX.pct(d.exercised / total) + ' of granted')),
          el('div.stack', null, el('span.cap', null, 'Dormant'), el('span', { style: { fontSize: '28px', lineHeight: '34px', fontWeight: 650, color: 'var(--crit)' } }, n(dormant)),
            el('span.sub', null, GX.pct(dormant / total) + ' · ' + n(d.dormant_reaching_crown_jewels) + ' reach a crown jewel')),
          el('div.stack', null, el('span.cap', null, 'Unverified'), el('span', { style: { fontSize: '28px', lineHeight: '34px', fontWeight: 650 } }, n(d.unverified)), el('span.sub', null, 'held where no source reports use'))),
        el('div.stack-bar', { role: 'img', 'aria-label': 'Grants by status' },
          el('i', { style: { width: (100 * d.exercised / total) + '%', background: 'var(--accent)' } }),
          el('i', { style: { width: (100 * (dormant - d.dormant_reaching_crown_jewels) / total) + '%', background: 'color-mix(in srgb, var(--crit) 55%, var(--panel-3))' } }),
          el('i', { style: { width: (100 * d.dormant_reaching_crown_jewels / total) + '%', background: 'var(--crit)' } }),
          el('i', { style: { width: (100 * d.unverified / total) + '%', background: 'var(--line-2)' } })),
        el('div.legend', null, el('span', null, el('i', { style: { width: '8px', height: '8px', background: 'var(--accent)' } }), 'Exercised'),
          el('span', null, el('i', { style: { width: '8px', height: '8px', background: 'color-mix(in srgb, var(--crit) 55%, var(--panel-3))' } }), 'Dormant'),
          el('span', null, el('i', { style: { width: '8px', height: '8px', background: 'var(--crit)' } }), 'Dormant and reaching a crown jewel'),
          el('span', null, el('i', { style: { width: '8px', height: '8px', background: 'var(--line-2)' } }), 'Unverified'))));
      var statuses = [['', 'All'], ['dormant', 'Dormant'], ['never', 'Never used'], ['idle', 'Idle'], ['unknown', 'Unverified'], ['used', 'Used']];
      var types = [['', 'Anyone'], ['user', 'People'], ['role', 'Roles'], ['service', 'Service accounts']];
      var cols = 'minmax(0, 1.1fr) minmax(0, 1.3fr) 80px 110px minmax(0, 1fr) 64px';
      var list = el('section.panel.clip', null,
        el('div.panel-head', null, el('h2', null, s.status === 'dormant' ? 'Dormant grants' : 'Grants'),
          el('span.dim', null, 'Showing ', el('strong.mono', null, n(d.grants.length)), ' of ' + n(d.total) + (d.total !== d.granted ? ' matching' : ''))),
        el('div.row', { style: { padding: '12px 18px', borderBottom: '1px solid var(--line)' } },
          el('div.input-wrap', { style: { flex: '1 1 260px', maxWidth: '360px' } }, icon('search', 15), el('label.sr', { 'for': 'aq' }, 'Search grants'),
            el('input.input.small#aq', { type: 'search', placeholder: 'Identity, resource or permission', value: s.q, onInput: function (e) { self.set({ q: e.target.value }); } })),
          el('button.toggle', { type: 'button', 'aria-pressed': String(s.regulated), onClick: function () { self.set({ regulated: !s.regulated }); } }, el('span.track'), 'Reaches a crown jewel'),
          el('div.seg', { role: 'group', 'aria-label': 'Status' }, statuses.map(function (x) {
            return el('button', { key: x[0], type: 'button', 'aria-pressed': String(s.status === x[0]), onClick: function () { self.set({ status: x[0] }); } }, x[1]);
          })),
          el('div.seg', { role: 'group', 'aria-label': 'Identity type' }, types.map(function (x) {
            return el('button', { key: x[0], type: 'button', 'aria-pressed': String(s.ptype === x[0]), onClick: function () { self.set({ ptype: x[0] }); } }, x[1]);
          }))),
        el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '760px' } },
          el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'Identity'), el('span', null, 'Can reach'), el('span', null, 'Regulated'), el('span', null, 'Last used'), el('span', null, 'Granted via'), el('span.num', null, 'Routes')),
          d.grants.length ? d.grants.map(function (g, i) {
            var who = g.identity, what = g.target;
            return el('div.tr', { key: i, style: { gridTemplateColumns: cols } },
              el('span', { style: { minWidth: 0 } }, el('span.ellipsis', { style: { display: 'block' } }, GX.NodeLink({ node: who })),
                el('span.sub', null, (who.principal_type ? GX.cap1(who.principal_type) : 'Identity') + (who.suspended ? ' · suspended' : ''))),
              el('span', { style: { minWidth: 0 } }, el('span.row', { style: { gap: '6px', flexWrap: 'nowrap' } }, what.is_crown_jewel ? el('span.jewel', null, icon('diamond', 12)) : null, el('span.ellipsis', null, GX.NodeLink({ node: what, text: what.label }))),
                el('span.sub.mono.ellipsis', null, g.permission || '')),
              el('span', null, what.regimes && what.regimes.length ? GX.Regimes({ regimes: what.regimes }) : el('span.faint', null, what.is_crown_jewel ? 'crown' : '-')),
              lastUsed(g),
              el('span.mono.dim.ellipsis', null, (g.via || '-') + (g.sources && g.sources.length ? ' · ' + g.sources.join(', ') : '')),
              el('span.num.mono', null, g.routes_through ? n(g.routes_through) : '-'));
          }) : GX.Empty({ title: 'No grants match' }, s.regulated ? 'Turn off "Reaches a crown jewel" to see every grant.' : 'Clear the search or the filters.'))),
        el('div.panel-foot', null, el('span', null, n(d.grants.length) + ' loaded' + (d.grants.length < d.total ? ' · ' + n(d.total - d.grants.length) + ' more' : '')),
          d.grants.length < d.total ? el('button.btn.small', { type: 'button', onClick: function () { self.setState({ limit: s.limit + PAGE }, function () { self.reload(); }); } }, 'Load ' + Math.min(PAGE, d.total - d.grants.length) + ' more') : null,
          el('span', null, 'Sorted by reach, then routes, then never used first')));
      return el(GX.Fragment, null, head('Access', sub), redactionNote(d), summary, list);
    }
  });
})();
