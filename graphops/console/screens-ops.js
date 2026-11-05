/* GraphOps console: findings, operations and governance.
 * Findings, Connectors, Compliance, Admin, Profile. */
(function () {
  'use strict';
  var GX = window.GX, el = GX.el, icon = GX.icon, n = GX.n, head = GX.head;

  /* =============================================================== findings */
  var EXPORTS = [['stix', 'STIX 2.1', 'Threat intel platforms'], ['sarif', 'SARIF 2.1.0', 'Code scanning and CI'],
    ['oscal', 'OSCAL', 'Assessment results for compliance tools'], ['csv', 'CSV', 'Spreadsheets, formula-safe']];

  GX.screens.findings = GX.extend(GX.Loader, {
    init: function () {
      this.state.severity = GX.session.get('gx.findings.sev') || '';
      GX.session.set('gx.findings.sev', null);
      this.state.kind = ''; this.state.q = ''; this.state.status = 'open'; this.state.limit = 100;
      this.state.selected = GX.session.get('gx.finding'); this.state.menu = false;
    },
    load: function () {
      var s = this.state;
      return GX.get('/v1/findings' + GX.qs({ severity: s.severity, kind: s.kind, q: s.q, status: s.status, limit: s.limit }));
    },
    set: function (patch) {
      var self = this;
      this.setState(patch, function () { clearTimeout(self._t); self._t = setTimeout(function () { self.reload(); }, patch.q !== undefined ? 250 : 0); });
    },
    exportAs: function (fmt) {
      this.setState({ menu: false });
      GX.get('/v1/graph/export?fmt=' + fmt).then(function (body) {
        var stamp = new Date().toISOString().slice(0, 10);
        if (fmt === 'csv') GX.save('graphops-findings-' + stamp + '.csv', body.content, 'text/csv');
        else GX.save('graphops-' + fmt + '-' + stamp + '.json', JSON.stringify(body, null, 2), 'application/json');
        GX.toast('Exported as ' + fmt.toUpperCase() + '. The export is written to the audit log.');
      }, function () { GX.toast('The export did not complete.', 'bad'); });
    },
    render: function (props, s) {
      var self = this, me = props.me;
      var exportBtn = GX.can(me, 'graph:export') ? el('div.rel', null,
        el('button.btn', { type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': String(s.menu), onClick: function () { self.setState({ menu: !s.menu }); } }, icon('download', 15), 'Export'),
        s.menu ? el('div.menu', { role: 'menu' }, EXPORTS.map(function (x) {
          return el('button', { key: x[0], type: 'button', role: 'menuitem', onClick: function () { self.exportAs(x[0]); } }, el('strong', null, x[1]), el('span.sub', null, x[2]));
        })) : null) : null;
      if (s.error) return el(GX.Fragment, null, head('Findings', null, exportBtn), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      var d = s.data;
      if (!d) return el(GX.Fragment, null, head('Findings', 'Severity comes from reachability to crown jewels, not CVSS.', exportBtn), GX.Loading({}));
      var list = d.findings;
      var sel = list.filter(function (f) { return f.fingerprint === s.selected; })[0] || list[0];
      var filters = el('section.panel', null, el('div.panel-body.stack', { style: { gap: '10px' } },
        el('div.row', null, el('span.cap', { style: { width: '64px' } }, 'Severity'),
          GX.SEVERITIES.map(function (sv) {
            return el('button.chip.c-' + sv, { key: sv, type: 'button', 'aria-pressed': String(s.severity === sv), onClick: function () { self.set({ severity: s.severity === sv ? '' : sv }); } },
              GX.Sev({ level: sv }), el('span.n.mono', null, n(d.by_severity[sv] || 0)));
          }),
          el('div.input-wrap', { style: { marginLeft: 'auto', flex: '1 1 240px', maxWidth: '320px' } }, icon('search', 15), el('label.sr', { 'for': 'fq' }, 'Search findings'),
            el('input.input.small#fq', { type: 'search', placeholder: 'Title or fingerprint', value: s.q, onInput: function (e) { self.set({ q: e.target.value }); } }))),
        el('div.row', null, el('span.cap', { style: { width: '64px' } }, 'Kind'),
          Object.keys(GX.FINDING_KIND).filter(function (k) { return d.by_kind[k]; }).map(function (k) {
            return el('button.chip', { key: k, type: 'button', 'aria-pressed': String(s.kind === k), onClick: function () { self.set({ kind: s.kind === k ? '' : k }); } },
              GX.FINDING_KIND[k], el('span.n.mono', null, n(d.by_kind[k])));
          }),
          el('div.seg', { style: { marginLeft: 'auto' }, role: 'group', 'aria-label': 'Open or resolved' },
            el('button', { type: 'button', 'aria-pressed': String(s.status === 'open'), onClick: function () { self.set({ status: 'open' }); } }, 'Open', el('span.n', null, n(d.open))),
            el('button', { type: 'button', 'aria-pressed': String(s.status === 'resolved'), onClick: function () { self.set({ status: 'resolved' }); } }, 'Resolved')))));
      var cols = '96px 120px minmax(0, 1fr) 64px 92px';
      var table = el('section.panel.clip', { style: { flex: '7 1 520px', minWidth: 0 } },
        el('div.panel-head', null, el('h2', null, n(d.total) + ' finding' + (d.total === 1 ? '' : 's')),
          el('span.faint', null, 'worst first · ' + n(list.length) + ' loaded')),
        el('div.tbl', null,
          el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'Severity'), el('span', null, 'Kind'), el('span', null, 'Title'),
            el('span.num', null, 'Routes'), el('span', null, s.status === 'open' ? 'Open since' : 'Resolved')),
          list.length ? list.map(function (f) {
            return el('button.tr' + (f === sel ? '.on' : ''), { key: f.fingerprint, type: 'button', style: { gridTemplateColumns: cols },
              onClick: function () { GX.session.set('gx.finding', f.fingerprint); self.setState({ selected: f.fingerprint }); } },
              GX.Sev({ level: f.severity }), el('span.dim', null, GX.FINDING_KIND[f.kind] || f.kind), el('span.ellipsis', null, f.title),
              el('span.num.mono', null, f.routes ? n(f.routes) : '-'), el('span.dim', null, GX.day(s.status === 'open' ? f.first_seen : f.resolved_at)));
          }) : GX.Empty({ title: s.status === 'resolved' ? 'Nothing has been resolved yet' : 'No findings match' },
            s.status === 'resolved' ? 'A finding resolves on its own when an ingest shows it is no longer true.' : 'Clear the filters to see every finding.')),
        d.total > list.length ? el('div.panel-foot', null, el('span', null, n(d.total - list.length) + ' more'),
          el('button.btn.small', { type: 'button', onClick: function () { self.set({ limit: s.limit + 100 }); } }, 'Load more')) : null);
      return el(GX.Fragment, null,
        head('Findings', n(d.open) + ' open. Severity comes from reachability to crown jewels, not CVSS.', exportBtn),
        GX.redactionNote(d), filters, el('div.split', null, table, sel ? FindingDetail({ f: sel, status: s.status }) : null));
    }
  });

  function FindingDetail(props) {
    var f = props.f;
    var opened = GX.toDate(f.first_seen);
    var days = opened ? Math.max(0, Math.floor((Date.now() - opened.getTime()) / 86400000)) : null;
    var parts = [];
    if (f.path && f.path.steps) {
      parts.push(el('div.stack', { key: 'p', style: { gap: '8px' } }, el('span.cap', null, 'Route involved'), GX.Chain({ steps: f.path.steps }),
        el('span.faint', null, 'Attacker effort ' + f.path.cost + ' · ' + f.path.steps.length + ' steps')));
    }
    if (f.node) {
      parts.push(el('div.stack', { key: 'n', style: { gap: '6px' } }, el('span.cap', null, f.kind === 'containment' ? 'Cut' : 'Node'),
        el('span', null, GX.NodeLink({ node: f.node })), f.protects_if_cut && f.protects_if_cut.length
          ? el('span.jewel', null, 'Cutting it puts ' + f.protects_if_cut.join(', ') + ' out of reach') : null));
    }
    if (f.grant) {
      var g = f.grant;
      parts.push(el('div.stack', { key: 'g', style: { gap: '6px' } }, el('span.cap', null, 'Grant'),
        el('span', null, f.identity ? GX.NodeLink({ node: f.identity }) : null, f.target ? ' may reach ' + f.target : ''),
        el('span.faint', null, [g.permission, g.via ? 'via ' + g.via : null, g.status === 'never' ? 'never used' : g.status === 'idle' ? 'unused for ' + g.idle_days + ' days'
          : g.status === 'unknown' ? 'use not reported by its source' : null].filter(Boolean).join(' · '))));
    }
    return el('section.panel', { style: { flex: '5 1 360px', minWidth: 0, position: 'sticky', top: '76px' } },
      el('div.panel-body.stack', { style: { gap: '14px' } },
        el('div.row', null, GX.Pill({ tone: f.severity, children: GX.cap1(f.severity) }), GX.Pill({ tone: 'outline', children: GX.FINDING_KIND[f.kind] || f.kind }),
          props.status === 'resolved' ? GX.Pill({ tone: 'ok', children: 'Resolved' }) : null),
        el('h2', { style: { fontSize: '18px', lineHeight: '25px', fontWeight: 650 } }, f.title),
        el('div.panel', { style: { padding: '12px 14px', boxShadow: 'none', background: 'var(--panel-2)' } },
          el('div.row', null, el('span.cap', null, 'Fingerprint'), el('span.mono', { style: { marginLeft: 'auto', fontWeight: 600 } }, 'fp_' + f.fingerprint.slice(0, 8))),
          el('p.dim', { style: { marginTop: '6px' } }, props.status === 'resolved'
            ? 'Open from ' + GX.day(f.first_seen) + ' until ' + GX.day(f.resolved_at) + ', when an ingest showed it was no longer true.'
            : 'Open since ' + GX.day(f.first_seen) + (days !== null ? ' (' + (days === 0 ? 'today' : days + ' day' + (days === 1 ? '' : 's')) + ')' : '') +
              '. Same fingerprint in every ingest since, so it keeps its history.')),
        f.remediation ? el('div.stack', { style: { gap: '6px', borderTop: '1px solid var(--line)', paddingTop: '12px' } }, el('span.cap', null, 'Remediation'),
          el('p', { style: { fontSize: '14px', lineHeight: '22px' } }, f.remediation)) : null,
        parts.length ? el('div.stack', { style: { gap: '14px', borderTop: '1px solid var(--line)', paddingTop: '12px' } }, parts) : null));
  }

  /* ============================================================= connectors */
  var CATEGORY = { siem: 'SIEM', edr: 'Endpoint', idp: 'Identity', cloud: 'Cloud', vulnerability: 'Vulnerability',
    itsm: 'Asset inventory', ticketing: 'Ticketing', chat: 'Chat', oncall: 'On-call' };
  // Two letters per product, as the design badges them. Vendor initials
  // collide: Entra and Sentinel are both Microsoft.
  var TAGS = { cloudtrail: 'CT', crowdstrike: 'CS', entra: 'EN', okta: 'OK', qualys: 'QL', sentinel: 'SE',
    servicenow: 'SN', splunk: 'SP', tenable: 'TN', jira: 'JI', pagerduty: 'PD', slack: 'SL', teams: 'MT' };
  function tag(c) { return TAGS[c.key] || String(c.key || '?').slice(0, 2).toUpperCase(); }

  GX.screens.connectors = GX.extend(GX.Loader, {
    load: function () { return GX.get('/v1/connectors'); },
    run: function () {
      var self = this;
      self.setState({ running: true });
      GX.post('/v1/connectors/run', { mode: 'replay' }).then(function (r) {
        self.setState({ running: false });
        GX.toast('Ingest ' + r.status + '. ' + (r.connectors_run - r.connectors_failed) + ' of ' + r.connectors_run + ' connectors ran clean' +
          (r.served ? ', and every screen now answers from it.' : '. The estate was kept as it was.'), r.status === 'success' ? '' : 'bad');
        self.reload(); self.props.refreshOverview();
      }, function (e) {
        self.setState({ running: false });
        GX.toast(e.status === 403 ? 'Running an ingest needs connector:run.' : 'The ingest did not start.', 'bad');
      });
    },
    render: function (props, s) {
      var self = this, me = props.me;
      var runBtn = GX.can(me, 'connector:run') ? el('button.btn.primary', { type: 'button', disabled: s.running, onClick: function () { self.run(); } },
        icon('play', 14), s.running ? 'Running ingest' : 'Run ingest') : null;
      if (s.error) return el(GX.Fragment, null, head('Connectors', null, runBtn), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      var d = s.data;
      if (!d) return el(GX.Fragment, null, head('Connectors', null, runBtn), GX.Loading({}));
      var inbound = d.connectors.filter(function (c) { return c.direction === 'inbound'; });
      var outbound = d.connectors.filter(function (c) { return c.direction !== 'inbound'; });
      var cats = {};
      d.connectors.forEach(function (c) { cats[c.category] = 1; });
      var ing = d.last_ingest;
      var failures = ing ? (ing.runs || []).filter(function (r) { return r.status !== 'success'; }) : [];
      var last = el('section.panel.clip', null,
        el('div.panel-head', { style: { alignItems: 'center' } }, el('div.row', null,
          ing ? GX.Pill({ tone: ing.status === 'success' ? 'ok' : ing.status === 'degraded' ? 'warn' : 'bad', children: GX.cap1(ing.status) }) : GX.Pill({ tone: 'outline', children: 'No ingest yet' }),
          el('strong', { style: { fontSize: '16px' } }, ing ? 'Last ingest ' + GX.short(ing.id) + ' · finished ' + GX.time(ing.finished_at) + ' ' + GX.zone : 'Nothing has been ingested'),
          ing ? el('span.faint', null, 'took ' + GX.duration(ing.duration_seconds) + ' · ' + GX.ago(ing.finished_at) + (ing.actor_id ? '' : ' · at server start')) : null)),
        ing ? el('div.stats', null,
          el('div.stat', null, el('span.cap', null, 'Connectors run'), el('span.v', null, n(ing.connectors_run))),
          el('div.stat', null, el('span.cap', null, 'Succeeded'), el('span.v', { style: { color: 'var(--ok)' } }, n(ing.succeeded))),
          el('div.stat', null, el('span.cap', null, 'Failed'), el('span.v', { style: { color: ing.connectors_failed ? 'var(--crit)' : 'var(--text)' } }, n(ing.connectors_failed))),
          el('div.stat', null, el('span.cap', null, 'Duplicates merged'), el('span.v', null, n(ing.merged))),
          el('div.stat', null, el('span.cap', null, 'Entities after merge'), el('span.v', null, n(ing.entities)))) : null,
        failures.length ? el('div', { style: { display: 'flex', flexWrap: 'wrap', gap: '16px', padding: '16px 18px', borderTop: '1px solid var(--line)' } },
          el('div.row', { style: { flex: '1 1 380px', alignItems: 'flex-start', flexWrap: 'nowrap' } }, el('span', { style: { color: 'var(--warn)' } }, icon('warn', 20)),
            el('div.stack', null, el('strong', null, failures.length === 1 ? 'One source failed, so this run is degraded rather than failed' : failures.length + ' sources failed'),
              el('span.dim', null, 'The others landed and the graph was rebuilt from them. Every screen answers from incomplete data until a clean run.'))),
          el('div.stack', { style: { flex: '1 1 380px', gap: '8px' } }, failures.map(function (r) {
            return el('div.callout.bad', { key: r.connector, style: { padding: '10px 12px' } }, el('div.body', null,
              el('strong', null, r.connector + ' · ' + r.status), el('span.dim', null, r.error || 'No error was recorded.')));
          }))) : null);
      var cols = 'minmax(0, 1.4fr) 120px 90px 90px minmax(0, 1.2fr)';
      var row = function (c, inboundSide) {
        var r = c.last_run;
        var result;
        if (!inboundSide) result = el('span.faint', null, 'Delivers findings when one is sent. No delivery recorded yet.');
        else if (!r) result = el('span.faint', null, 'Not run in the last ingest');
        else if (r.status === 'success') result = el('span.row', { style: { gap: '6px', flexWrap: 'nowrap' } }, el('i', { style: { width: '7px', height: '7px', borderRadius: '50%', background: 'var(--ok)' } }),
          n(r.nodes) + ' entities, ' + n(r.edges) + ' relationships');
        else result = el('span.row', { style: { gap: '6px', flexWrap: 'nowrap', color: 'var(--crit)', fontWeight: 600 } }, el('i', { style: { width: '7px', height: '7px', borderRadius: '50%', background: 'var(--crit)' } }), el('span.ellipsis', null, r.error || r.status));
        var mode = r ? r.mode : d.mode;
        return el('div.tr', { key: c.key, style: { gridTemplateColumns: cols } },
          el('span.row', { style: { flexWrap: 'nowrap', minWidth: 0 } }, el('span.mono', { style: { width: '30px', height: '30px', borderRadius: '7px', border: '1px solid var(--line-2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', color: 'var(--text-2)', flex: '0 0 auto' } }, tag(c)),
            el('span', { style: { minWidth: 0 } }, el('strong.ellipsis', { style: { display: 'block', fontWeight: 600 } }, c.vendor + ' ' + c.product),
              el('a.sub', { href: c.api_reference, target: '_blank', rel: 'noopener noreferrer' }, 'API reference'))),
          el('span.dim', null, CATEGORY[c.category] || c.category),
          GX.Pill({ tone: mode === 'live' ? 'ok' : 'outline', children: GX.cap1(mode || 'replay') }),
          el('span.mono.dim', null, r && ing ? GX.time(ing.finished_at) : '-'), result);
      };
      var tableFor = function (title, subtitle, note, items, inboundSide) {
        return el('section.panel.clip', null,
          el('div.panel-head', null, el('div.row', null, el('h2', null, title), el('span.faint', null, subtitle)), el('span.faint', null, note)),
          el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '720px' } },
            el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'Connector'), el('span', null, 'Category'), el('span', null, 'Mode'),
              el('span', null, inboundSide ? 'Last ran' : 'Last sent'), el('span', null, 'Result')),
            items.map(function (c) { return row(c, inboundSide); }))));
      };
      var inCats = {}, outCats = {};
      inbound.forEach(function (c) { inCats[c.category] = 1; });
      outbound.forEach(function (c) { outCats[c.category] = 1; });
      return el(GX.Fragment, null,
        head('Connectors', d.connectors.length + ' integrations across ' + Object.keys(cats).length + ' categories · ' + inbound.length + ' bring data in · ' + outbound.length + ' send alerts out', runBtn),
        s.running ? el('div.callout.info', { role: 'status' }, icon('info', 18), el('div.body', null, el('strong', null, 'Running ' + inbound.length + ' connectors'),
          el('span.dim', null, d.mode === 'replay' ? 'Each replays its recorded response, then entities are resolved across sources and the graph is rebuilt.' : 'Each calls its vendor API, or for CloudTrail reads the delivered log files, then entities are resolved and the graph rebuilt.'))) : null,
        last,
        tableFor('Pulling data in', inbound.length + ' connectors · ' + Object.keys(inCats).length + ' categories', 'Live calls each vendor API, or reads CloudTrail log files. Replay re-reads a recording.', inbound, true),
        tableFor('Pushing alerts out', outbound.length + ' connectors · ' + Object.keys(outCats).length + ' categories', 'In replay an outbound connector builds its message and sends nothing.', outbound, false));
    }
  });

  /* ============================================================= compliance */
  var FRAMEWORKS = [['soc2', 'SOC 2'], ['iso27001', 'ISO 27001'], ['cis', 'CIS Controls']];
  var FW_TITLE = { soc2: 'SOC 2 · Trust Services Criteria', iso27001: 'ISO/IEC 27001:2022 · Annex A', cis: 'CIS Critical Security Controls v8' };

  GX.screens.compliance = GX.extend(GX.Loader, {
    init: function () { this.state.fw = 'soc2'; },
    load: function () { return GX.get('/v1/compliance/controls?framework=' + this.state.fw); },
    render: function (props, s) {
      var self = this;
      var tabs = el('div.seg', { role: 'group', 'aria-label': 'Framework' }, FRAMEWORKS.map(function (f) {
        return el('button', { key: f[0], type: 'button', 'aria-pressed': String(s.fw === f[0]), onClick: function () { self.setState({ fw: f[0], data: null }, function () { self.reload(); }); } }, f[1]);
      }));
      var sub = 'Evidence from the graph, mapped to controls' + (props.overview ? ' · ' + GX.asOf(props.overview) : '') + '.';
      if (s.error) return el(GX.Fragment, null, head('Compliance', sub, tabs), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      var d = s.data;
      var legend = el('section.panel', { style: { display: 'flex', flexWrap: 'wrap' } },
        el('div.row', { style: { flex: '1 1 300px', padding: '14px 16px', alignItems: 'flex-start', flexWrap: 'nowrap' } }, GX.Pill({ tone: 'high', children: [icon('ban', 12), 'Not satisfied'] }),
          el('span.dim', null, 'The graph holds evidence against the control.')),
        el('div.row', { style: { flex: '1 1 300px', padding: '14px 16px', alignItems: 'flex-start', flexWrap: 'nowrap', borderLeft: '1px solid var(--line)' } }, GX.Pill({ tone: 'dashed', children: [icon('circle', 12), 'Not assessed'] }),
          el('span.dim', null, 'The graph cannot decide. Evidence is missing, or the control needs input it does not have.')),
        el('div.row', { style: { flex: '1 1 300px', padding: '14px 16px', alignItems: 'flex-start', flexWrap: 'nowrap', borderLeft: '1px solid var(--line)' } }, el('span.dim', null, icon('lock', 16)),
          el('span.dim', null, el('strong', { style: { color: 'var(--text)' } }, 'There is no pass. '), 'Finding nothing wrong in the graph is not proof a control works, so a clean control reads Not assessed, never passed.')));
      if (!d) return el(GX.Fragment, null, head('Compliance', sub, tabs), legend, GX.Loading({}));
      var notSat = d.controls.filter(function (c) { return c.status === 'not-satisfied'; }).length;
      var cols = '170px minmax(0, 1fr) minmax(0, 1.4fr) 150px';
      return el(GX.Fragment, null, head('Compliance', sub, tabs), GX.redactionNote(d), legend,
        el('section.panel.clip', null,
          el('div.panel-head', null, el('h2', null, FW_TITLE[s.fw]),
            el('span.dim', null, el('strong', { style: { color: 'var(--high)' } }, n(notSat) + ' not satisfied'), ' · ' + n(d.controls.length - notSat) + ' not assessed')),
          el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '760px' } },
            el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'Control'), el('span', null, 'What it asks'), el('span', null, 'Evidence from the graph'), el('span', null, 'Status')),
            d.controls.map(function (c) {
              var bad = c.status === 'not-satisfied';
              return el('div.tr', { key: c.id, style: { gridTemplateColumns: cols, alignItems: 'start', padding: '16px 18px' } },
                el('div.stack', null, el('strong.mono', { style: { fontSize: '15px' } }, c.id), el('span', { style: { fontWeight: 600 } }, c.title)),
                el('span.dim', null, c.question),
                (c.evidence || []).length ? el('ul.stack', { style: { gap: '8px' } }, c.evidence.map(function (e) {
                  return el('li', { key: e.fingerprint, style: { display: 'grid', gridTemplateColumns: '12px minmax(0, 1fr)', gap: '8px' } },
                    el('i', { style: { width: '6px', height: '6px', marginTop: '7px', borderRadius: '50%', background: 'var(--' + (e.severity === 'critical' ? 'crit' : e.severity === 'high' ? 'high' : 'med') + ')' } }),
                    el('span', null, e.title + ' ', el('a', { href: '#/findings', onClick: function () { GX.session.set('gx.finding', e.fingerprint); } }, 'Finding')));
                })) : el('span.faint', null, 'No contradicting evidence in the graph.'),
                bad ? GX.Pill({ tone: 'high', children: [icon('ban', 12), 'Not satisfied'] }) : GX.Pill({ tone: 'dashed', children: [icon('circle', 12), 'Not assessed'] }));
            }))),
          el('div.panel-foot', null, el('span', null, d.disclaimer))));
    }
  });

  /* ================================================================== admin */
  var ROLE_TONE = { owner: 'imp', admin: 'accent', analyst: 'ok', responder: 'high', auditor: 'jewel', viewer: 'outline', service: 'outline' };
  function rolePills(roles) { return el('span.row', { style: { gap: '4px' } }, (roles || []).map(function (r) { return GX.Pill({ key: r, tone: ROLE_TONE[r], children: GX.cap1(r) }); })); }
  function genPassword() {
    var bytes = new Uint8Array(15);
    window.crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) { return 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.charAt(b % 55); }).join('').replace(/(.{5})(?!$)/g, '$1-');
  }

  GX.screens.admin = GX.extend(GX.Component, {
    init: function (props) {
      var me = props.me;
      var tabs = [];
      if (GX.can(me, 'user:read')) tabs.push('users');
      if (GX.can(me, 'apikey:manage')) tabs.push('keys');
      if (GX.can(me, 'audit:read')) tabs.push('audit');
      this.state = { tabs: tabs, tab: tabs.indexOf(props.tab) !== -1 ? props.tab : tabs[0], counts: {} };
    },
    count: function (k, v) { var c = Object.assign({}, this.state.counts); c[k] = v; this.setState({ counts: c }); },
    render: function (props, s) {
      var self = this;
      if (!s.tabs.length) return el(GX.Fragment, null, head('Admin'), GX.Problem({ error: { status: 403, body: { missing_permission: 'user:read' } } }));
      var labels = { users: 'Users', keys: 'API keys', audit: 'Audit log' };
      var body = s.tab === 'users' ? el(Users, { me: props.me, onCount: function (v) { self.count('users', v); }, startImpersonation: props.startImpersonation })
        : s.tab === 'keys' ? el(Keys, { me: props.me, onCount: function (v) { self.count('keys', v); } })
          : el(Audit, { me: props.me });
      return el(GX.Fragment, null,
        head('Admin', 'Owners and admins manage users and API keys. Auditors read and verify the audit log.'),
        el('div.tabs', { role: 'tablist' }, s.tabs.map(function (t) {
          return el('button', { key: t, type: 'button', role: 'tab', 'aria-selected': String(s.tab === t), onClick: function () { self.setState({ tab: t }); history.replaceState(null, '', '#/admin/' + t); } },
            labels[t], s.counts[t] !== undefined ? el('span.n.mono', null, n(s.counts[t])) : null);
        })), body);
    }
  });

  var Users = GX.extend(GX.Loader, {
    init: function () { this.state.q = ''; this.state.adding = false; this.state.form = { email: '', name: '', role: 'analyst' }; this.state.made = null; },
    load: function () { var self = this; return GX.get('/v1/admin/users').then(function (d) { self.props.onCount(d.users.length); return d; }); },
    add: function (ev) {
      ev.preventDefault();
      var self = this, f = this.state.form, password = genPassword();
      GX.post('/v1/admin/users', { email: f.email.trim(), display_name: f.name.trim(), roles: [f.role], password: password }).then(function () {
        self.setState({ adding: false, made: { email: f.email.trim(), password: password }, form: { email: '', name: '', role: 'analyst' } });
        self.reload();
      }, function (e) { GX.toast(e.status === 400 ? GX.cap1(e.message) + '.' : 'That user was not created.', 'bad'); });
    },
    render: function (props, s) {
      var self = this, me = props.me;
      if (s.error) return GX.Problem({ error: s.error, retry: function () { self.reload(); } });
      if (!s.data) return GX.Loading({});
      var q = s.q.trim().toLowerCase();
      var users = s.data.users.filter(function (u) { return !q || (u.email + ' ' + u.display_name).toLowerCase().indexOf(q) !== -1; });
      var canView = GX.can(me, 'user:impersonate') && !me.impersonator;
      var cols = 'minmax(0, 1.4fr) minmax(0, 1fr) 70px 130px 90px 110px';
      return el(GX.Fragment, null,
        s.made ? el('div.callout.info', { role: 'status' }, icon('info', 18), el('div.body', null, el('strong', null, s.made.email + ' can sign in now'),
          el('span.dim', null, 'Their first password is ', el('span.mono', { style: { color: 'var(--text)' } }, s.made.password), '. It is shown once. Send it to them by a channel you trust.')),
          el('button.btn.small', { type: 'button', onClick: function () { self.setState({ made: null }); } }, 'Done')) : null,
        el('section.panel.clip', null,
          el('div.row', { style: { padding: '14px 18px', borderBottom: '1px solid var(--line)' } },
            el('div.input-wrap', { style: { flex: '1 1 260px', maxWidth: '320px' } }, icon('search', 15), el('label.sr', { 'for': 'uq' }, 'Search users'),
              el('input.input.small#uq', { type: 'search', placeholder: 'Name or email', value: s.q, onInput: function (e) { self.setState({ q: e.target.value }); } })),
            GX.can(me, 'user:write') ? el('button.btn.primary', { type: 'button', style: { marginLeft: 'auto' }, onClick: function () { self.setState({ adding: !s.adding }); } }, icon('plus', 15), 'Add user') : null),
          s.adding ? el('form', { onSubmit: function (e) { self.add(e); }, style: { display: 'flex', flexWrap: 'wrap', gap: '12px', padding: '14px 18px', borderBottom: '1px solid var(--line)', background: 'var(--panel-2)', alignItems: 'flex-end' } },
            el('div.field', { style: { flex: '1 1 200px' } }, el('label', { 'for': 'nu-name' }, 'Name'), el('input.input.small#nu-name', { value: s.form.name, onInput: function (e) { self.setState({ form: Object.assign({}, s.form, { name: e.target.value }) }); } })),
            el('div.field', { style: { flex: '1 1 240px' } }, el('label', { 'for': 'nu-email' }, 'Work email'), el('input.input.small#nu-email', { type: 'email', required: true, value: s.form.email, onInput: function (e) { self.setState({ form: Object.assign({}, s.form, { email: e.target.value }) }); } })),
            el('div.field', { style: { flex: '0 1 160px' } }, el('label', { 'for': 'nu-role' }, 'Role'),
              el('select.input.small#nu-role', { value: s.form.role, onChange: function (e) { self.setState({ form: Object.assign({}, s.form, { role: e.target.value }) }); } },
                s.data.assignable_roles.map(function (r) { return el('option', { key: r, value: r }, GX.cap1(r)); }))),
            el('button.btn.primary', { type: 'submit' }, 'Create'), el('span.faint', { style: { flex: '1 1 100%' } }, 'A first password is generated in this browser and shown to you once.')) : null,
          el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '760px' } },
            el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'User'), el('span', null, 'Roles'), el('span', null, 'MFA'), el('span', null, 'Last sign-in'), el('span', null, 'Status'), el('span')),
            users.map(function (u) {
              return el('div.tr', { key: u.id, style: { gridTemplateColumns: cols } },
                el('span.row', { style: { flexWrap: 'nowrap', minWidth: 0 } }, el('span.avatar', { style: { width: '30px', height: '30px', fontSize: '11px', flex: '0 0 auto' } }, GX.initials(u.display_name, u.email)),
                  el('span', { style: { minWidth: 0 } }, el('strong.ellipsis', { style: { display: 'block', fontWeight: 600 } }, u.display_name || u.email.split('@')[0]), el('span.sub.mono.ellipsis', null, u.email))),
                rolePills(u.roles),
                el('span', { style: { color: u.mfa_enabled ? 'var(--text)' : 'var(--warn)' } }, u.mfa_enabled ? 'On' : 'Off'),
                el('span.dim', null, u.last_login_at ? GX.when(u.last_login_at) : 'Never'),
                GX.Pill({ tone: !u.is_active ? 'outline' : u.locked ? 'bad' : 'ok', children: !u.is_active ? 'Inactive' : u.locked ? 'Locked' : 'Active' }),
                el('span', { style: { textAlign: 'right' } }, u.is_you ? el('span.faint', null, 'You') : canView && u.is_active
                  ? el('button.btn.small', { type: 'button', onClick: function () { props.startImpersonation(u).catch(function () { GX.toast('Viewing as that user did not start.', 'bad'); }); } }, icon('eye', 14), 'View as') : null));
            }))),
          el('div.panel-foot', null, el('span', null, n(s.data.assignable_roles.length) + ' assignable roles. Only owners can view as another user, and every action while doing so is logged under both names.'))));
    }
  });

  var Keys = GX.extend(GX.Loader, {
    init: function () { this.state.adding = false; this.state.name = ''; this.state.minted = null; },
    load: function () { var self = this; return GX.get('/v1/admin/api-keys').then(function (d) { self.props.onCount(d.api_keys.filter(function (k) { return !k.revoked_at; }).length); return d; }); },
    mint: function (ev) {
      ev.preventDefault();
      var self = this;
      GX.post('/v1/admin/api-keys', { name: this.state.name.trim(), roles: ['service'] }).then(function (k) {
        self.setState({ adding: false, name: '', minted: k }); self.reload();
      }, function () { GX.toast('That key was not created.', 'bad'); });
    },
    revoke: function (k) {
      var self = this;
      if (self.state.confirm !== k.id) { self.setState({ confirm: k.id }); return; }
      GX.del('/v1/admin/api-keys/' + encodeURIComponent(k.id)).then(function () { self.setState({ confirm: null }); GX.toast(k.name + ' is revoked. Requests using it now fail.'); self.reload(); },
        function () { GX.toast('That key was not revoked.', 'bad'); });
    },
    render: function (props, s) {
      var self = this;
      if (s.error) return GX.Problem({ error: s.error, retry: function () { self.reload(); } });
      if (!s.data) return GX.Loading({});
      var cols = 'minmax(0, 1.2fr) 130px 100px 130px 130px 140px';
      return el(GX.Fragment, null,
        s.minted ? el('div.callout.info', { role: 'status' }, icon('lock', 18), el('div.body', null, el('strong', null, 'Copy this key now. It is not shown again.'),
          el('span.mono', { style: { wordBreak: 'break-all', color: 'var(--text)' } }, s.minted.api_key)),
          navigator.clipboard ? el('button.btn.small', { type: 'button', onClick: function () { navigator.clipboard.writeText(s.minted.api_key).then(function () { GX.toast('Copied.'); }); } }, 'Copy') : null,
          el('button.btn.small', { type: 'button', onClick: function () { self.setState({ minted: null }); } }, 'Done')) : null,
        el('section.panel.clip', null,
          el('div.row', { style: { padding: '14px 18px', borderBottom: '1px solid var(--line)' } }, el('span.dim', null, 'Keys let a connector or a SIEM forwarder call the API. They hold the service role only.'),
            el('button.btn.primary', { type: 'button', style: { marginLeft: 'auto' }, onClick: function () { self.setState({ adding: !s.adding }); } }, icon('plus', 15), 'Create key')),
          s.adding ? el('form', { onSubmit: function (e) { self.mint(e); }, style: { display: 'flex', gap: '12px', padding: '14px 18px', borderBottom: '1px solid var(--line)', background: 'var(--panel-2)', alignItems: 'flex-end', flexWrap: 'wrap' } },
            el('div.field', { style: { flex: '1 1 280px' } }, el('label', { 'for': 'kn' }, 'What uses it'), el('input.input.small#kn', { required: true, maxlength: 120, placeholder: 'e.g. splunk forwarder', value: s.name, onInput: function (e) { self.setState({ name: e.target.value }); } })),
            el('button.btn.primary', { type: 'submit' }, 'Create')) : null,
          el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '760px' } },
            el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, 'Name'), el('span', null, 'Prefix'), el('span', null, 'Roles'), el('span', null, 'Created'), el('span', null, 'Last used'), el('span')),
            s.data.api_keys.length ? s.data.api_keys.map(function (k) {
              return el('div.tr', { key: k.id, style: { gridTemplateColumns: cols, opacity: k.revoked_at ? 0.6 : 1 } },
                el('strong.ellipsis', { style: { fontWeight: 600 } }, k.name), el('span.mono.dim', null, k.prefix + '…'), rolePills(k.roles),
                el('span.dim', null, GX.when(k.created_at)), el('span.dim', null, k.last_used_at ? GX.when(k.last_used_at) : 'Never'),
                el('span', { style: { textAlign: 'right' } }, k.revoked_at ? GX.Pill({ tone: 'outline', children: 'Revoked ' + GX.day(k.revoked_at) })
                  : el('button.btn.small.danger', { type: 'button', onClick: function () { self.revoke(k); } }, s.confirm === k.id ? 'Confirm revoke' : 'Revoke')));
            }) : GX.Empty({ title: 'No API keys yet' }, 'Create one for each integration, so revoking one never breaks another.')))));
    }
  });

  var Audit = GX.extend(GX.Loader, {
    init: function () { this.state.limit = 50; this.state.verify = null; this.state.people = {}; },
    load: function () {
      var self = this;
      if (GX.can(self.props.me, 'user:read') && !self._peopleAsked) {
        self._peopleAsked = true;
        GX.get('/v1/admin/users').then(function (d) {
          var map = {}; d.users.forEach(function (u) { map[u.id] = u.email.split('@')[0]; }); self.setState({ people: map });
        }, function () { /* names stay as ids */ });
      }
      return GX.get('/v1/admin/audit?limit=' + this.state.limit);
    },
    check: function () {
      var self = this;
      self.setState({ verifying: true });
      GX.get('/v1/admin/audit/verify').then(function (v) { self.setState({ verify: v, verifying: false }); }, function () { self.setState({ verifying: false }); GX.toast('The chain check did not run.', 'bad'); });
    },
    render: function (props, s) {
      var self = this;
      if (s.error) return GX.Problem({ error: s.error, retry: function () { self.reload(); } });
      if (!s.data) return GX.Loading({});
      var who = function (id, kind) { return !id ? (kind === 'system' ? 'system' : 'anonymous') : s.people[id] || GX.short(id); };
      var v = s.verify;
      var cols = '58px 110px minmax(0, .8fr) minmax(0, .9fr) minmax(0, 1.2fr) 170px';
      return el(GX.Fragment, null,
        v ? el('div.callout.' + (v.valid ? 'info' : 'bad'), { role: 'status' }, icon(v.valid ? 'check' : 'warn', 18), el('div.body', null,
          el('strong', null, v.valid ? 'The chain is intact' : 'The chain is broken'),
          el('span.dim', null, v.valid ? 'Every one of ' + n(v.entries) + ' entries carries the hash of the one before it, ending at ' + String(v.head).slice(0, 12) + '. No entry has been edited or removed.'
            : 'An entry does not match the hash the next one recorded' + (v.broken_at ? ', at entry ' + v.broken_at : '') + '. An edit or a deletion happened after it was written.'))) : null,
        el('section.panel.clip', null,
          el('div.row', { style: { padding: '14px 18px', borderBottom: '1px solid var(--line)' } },
            el('span.dim', null, 'Newest first. Each entry carries the hash of the one before it, so an edit anywhere breaks every hash after it.'),
            el('button.btn', { type: 'button', style: { marginLeft: 'auto' }, disabled: s.verifying, onClick: function () { self.check(); } }, icon('link', 15), s.verifying ? 'Checking' : 'Verify chain')),
          el('div.tbl-scroll', null, el('div.tbl', { style: { minWidth: '860px' } },
            el('div.th.cap', { style: { gridTemplateColumns: cols } }, el('span', null, '#'), el('span', null, 'Time (' + GX.zone + ')'), el('span', null, 'Actor'), el('span', null, 'Action'), el('span', null, 'Target'), el('span', null, 'Hash, previous to this')),
            s.data.entries.map(function (e) {
              return el('div.tr', { key: e.id, style: { gridTemplateColumns: cols } },
                el('span.mono.faint', null, n(e.seq)), el('span.mono.dim', null, GX.when(e.occurred_at)),
                el('span.mono.ellipsis', null, who(e.actor_id, e.actor_kind), e.on_behalf_of ? el('span.sub', null, 'as ' + who(e.on_behalf_of)) : null),
                el('span.mono.ellipsis', { style: { color: e.outcome === 'success' ? 'var(--accent)' : 'var(--crit)' } }, e.action),
                el('span.ellipsis.dim', null, e.resource || (e.detail && e.detail.reason) || '-'),
                el('span.mono.faint', null, String(e.previous_hash).slice(0, 6) + '… → ' + String(e.entry_hash).slice(0, 6) + '…'));
            }))),
          el('div.panel-foot', null, el('span', null, n(s.data.entries.length) + ' shown'),
            s.data.entries.length >= s.limit ? el('button.btn.small', { type: 'button', onClick: function () { self.setState({ limit: s.limit + 50 }, function () { self.reload(); }); } }, 'Load older') : null)));
    }
  });

  /* ================================================================ profile */
  var PERMS = [
    ['Graph and exposure', [['graph:read', 'See the overview and its counts'], ['graph:query', 'See routes, nodes, blast radius and choke points'],
      ['crown:reveal', 'See crown jewel names instead of pseudonyms'], ['crown:write', 'Mark and unmark crown jewels'], ['graph:export', 'Export as STIX, SARIF, OSCAL or CSV']]],
    ['Findings', [['finding:read', 'See findings and their fingerprints'], ['finding:write', 'Change a finding'], ['finding:assign', 'Assign findings to people']]],
    ['Connectors', [['connector:read', 'See connectors and ingest results'], ['connector:run', 'Start an ingest'], ['connector:configure', 'Add, edit and switch replay or live'],
      ['ingest:write', 'Push telemetry in through the API']]],
    ['Oversight', [['compliance:read', 'See controls and their evidence'], ['audit:read', 'Read and verify the hash-chained audit log']]],
    ['Administration', [['user:read', 'See the people in this organisation'], ['user:write', 'Create users'], ['role:assign', 'Assign roles'],
      ['apikey:manage', 'Create and revoke API keys'], ['webhook:manage', 'Manage outbound webhooks'], ['user:impersonate', 'View the product as another user'],
      ['org:read', 'See organisation settings'], ['org:write', 'Change organisation settings']]]
  ];

  GX.screens.profile = GX.extend(GX.Loader, {
    load: function () {
      var me = this.props.me;
      return GX.can(me, 'user:read') ? GX.get('/v1/admin/users').then(function (d) { return { members: d.users.length }; }, function () { return {}; }) : Promise.resolve({});
    },
    render: function (props) {
      var me = props.me, imp = me.impersonator, org = me.organization_detail || {};
      var held = me.permissions || [];
      var person = function (who, roles, mfa, since) {
        return el('div.stack', { style: { gap: '14px' } },
          el('div.row', { style: { flexWrap: 'nowrap' } }, el('span.avatar', { style: { width: '48px', height: '48px', fontSize: '16px' } }, GX.initials(who.display_name, who.email)),
            el('div.stack', null, el('strong', { style: { fontSize: '17px' } }, who.display_name || who.email.split('@')[0]), el('span.mono.dim', null, who.email))),
          el('div.grid', { style: { gridTemplateColumns: '1fr 1fr', gap: '12px' } },
            el('div.stack', null, el('span.cap', null, roles.length > 1 ? 'Roles' : 'Role'), rolePills(roles)),
            el('div.stack', null, el('span.cap', null, 'MFA'), el('span', { style: { fontWeight: 600, color: mfa ? 'var(--text)' : 'var(--warn)' } }, mfa ? 'Authenticator app' : 'Not set up')),
            since ? el('div.stack', null, el('span.cap', null, 'Signed in'), el('span', { style: { fontWeight: 600 } }, GX.when(since))) : null));
      };
      var signedIn = el('section.panel', { style: { flex: '1 1 320px', minWidth: 0 } }, el('div.panel-body.stack', { style: { gap: '14px' } },
        el('span.cap', null, 'Signed in as'),
        imp ? person(imp, ['owner'], imp.mfa_enabled, imp.last_login_at) : person(me, me.roles, me.mfa_enabled, me.session_started_at),
        imp ? el('p.dim', { style: { borderTop: '1px solid var(--line)', paddingTop: '12px' } }, 'Your own permissions are paused while you act as someone else.') : null));
      var acting = imp ? el('section.panel', { style: { flex: '1 1 320px', minWidth: 0, borderColor: 'var(--imp)', boxShadow: '0 0 0 1px var(--imp)', background: 'color-mix(in srgb, var(--imp) 7%, var(--panel))' } },
        el('div.panel-body.stack', { style: { gap: '14px' } },
          el('div.row', null, el('span.cap', { style: { color: 'var(--imp)' } }, 'Acting as'), me.session_started_at ? el('span.mono.faint', { style: { marginLeft: 'auto' } }, 'since ' + GX.time(me.session_started_at) + ' ' + GX.zone) : null),
          el('div.row', { style: { flexWrap: 'nowrap' } }, el('span.avatar', { style: { width: '48px', height: '48px', fontSize: '16px', background: 'var(--imp)', color: '#FFFFFF' } }, GX.initials(me.display_name, me.email)),
            el('div.stack', null, el('strong', { style: { fontSize: '17px' } }, me.display_name || me.email), el('span.mono.dim', null, me.email))),
          el('p.dim', null, 'You see exactly what they see, including pseudonymised crown jewel names where their role withholds them. Everything you do is logged as ',
            el('span.mono', { style: { color: 'var(--text)' } }, imp.email.split('@')[0] + ' → ' + me.email.split('@')[0]), '.'),
          el('div', null, el('button.btn.imp', { type: 'button', onClick: props.endImpersonation }, 'End impersonation')))) : null;
      var orgCard = el('section.panel', { style: { flex: '1 1 280px', minWidth: 0 } }, el('div.panel-body.stack', { style: { gap: '12px' } },
        el('span.cap', null, 'Organisation'),
        el('div.row', { style: { flexWrap: 'nowrap' } }, el('span.org-tile', { style: { width: '36px', height: '36px', fontSize: '13px' } }, GX.initials(org.name)),
          el('div.stack', null, el('strong', { style: { fontSize: '16px' } }, org.name), el('span.mono.faint', null, 'org/' + org.slug))),
        el('dl', { style: { margin: 0, display: 'grid', gridTemplateColumns: '1fr auto', gap: '8px 12px' } },
          el('dt.dim', null, 'Organisation ID'), el('dd.mono', { style: { margin: 0 } }, GX.short(org.id)),
          el('dt.dim', null, 'Data residency'), el('dd', { style: { margin: 0, fontWeight: 600 } }, org.data_residency === 'global' ? 'Not restricted' : String(org.data_residency || '-').toUpperCase()),
          this.state.data && this.state.data.members !== undefined ? el('dt.dim', null, 'Members') : null,
          this.state.data && this.state.data.members !== undefined ? el('dd.mono', { style: { margin: 0 } }, n(this.state.data.members)) : null)));
      var total = PERMS.reduce(function (a, g) { return a + g[1].length; }, 0);
      var count = PERMS.reduce(function (a, g) { return a + g[1].filter(function (p) { return held.indexOf(p[0]) !== -1; }).length; }, 0);
      var whose = imp ? (me.display_name || me.email.split('@')[0]) + '\'s role allows' : 'What your role allows';
      var perms = el('section.panel.clip', null,
        el('div.panel-head', null, el('div.stack', null, el('h2', null, whose), el('span.faint', null, GX.cap1(me.roles.join(', ')) + ' carries ' + count + ' of ' + total + ' permissions.' +
          (imp ? ' These apply to everything you do until you end impersonation.' : ''))), rolePills(me.roles)),
        el('div.grid', { style: { gridTemplateColumns: 'repeat(auto-fit, minmax(min(360px, 100%), 1fr))', gap: 0 } }, PERMS.map(function (g) {
          var have = g[1].filter(function (p) { return held.indexOf(p[0]) !== -1; }).length;
          return el('div.perm-group', { key: g[0] }, el('div.head', null, el('span.cap', null, g[0]), el('span.mono.faint', null, have + ' of ' + g[1].length)),
            g[1].map(function (p) {
              var on = held.indexOf(p[0]) !== -1;
              return el('div.perm' + (on ? '' : '.off'), { key: p[0] }, el('span.tick.' + (on ? 'yes' : 'no'), { 'aria-label': on ? 'held' : 'not held' }, on ? '✓' : '–'),
                el('span', null, el('span.mono', { style: { display: 'block', fontWeight: on ? 600 : 400 } }, p[0]), el('span.sub', null, p[1])));
            }));
        })));
      return el(GX.Fragment, null, head('Profile', 'Who you are' + (imp ? ', who you are acting as,' : '') + ' and what that lets you do right now.'),
        el('div.split', null, signedIn, acting, orgCard), perms);
    }
  });
})();
