/* GraphOps console: the Graph screen. The whole estate, every system and
   relationship, with any one answer lit up on it. Every other screen shows
   an answer about the graph; this one shows the graph. */
(function () {
  'use strict';
  var GX = window.GX, el = GX.el, h = GX.h, icon = GX.icon, n = GX.n;
  GX.screens = GX.screens || {};

  var LENSES = [
    { id: 'routes', label: 'Routes to crown jewels' },
    { id: 'blast', label: 'Blast radius' },
    { id: 'new', label: 'New in 24h' },
    { id: 'unused', label: 'Unused access' },
    { id: 'none', label: 'Everything' }
  ];

  /* Trust zones run left to right, the way an attacker travels. A zone with
     more systems than fit in one column wraps into side-by-side columns, so
     a large estate grows wider rather than impossibly tall. */
  var BOX_W = 196, BOX_H = 26, ROW = 31, COL_GAP = 110, SUB_GAP = 22, TOP = 44, LEFT = 16, MAX_ROWS = 22;

  function layout(map) {
    var zones = map.zones || ['untrusted', 'perimeter', 'internal', 'crown'];
    var byZone = {};
    zones.forEach(function (z) { byZone[z] = []; });
    map.nodes.forEach(function (node, i) { (byZone[node.zone] || byZone.internal).push(i); });
    var pos = new Array(map.nodes.length), cols = [], x = LEFT, tallest = 1;
    zones.forEach(function (z) {
      var list = byZone[z], sub = Math.max(1, Math.ceil(list.length / MAX_ROWS)), rows = Math.ceil(list.length / sub) || 1;
      list.forEach(function (idx, k) {
        pos[idx] = { x: x + Math.floor(k / rows) * (BOX_W + SUB_GAP), y: TOP + (k % rows) * ROW };
      });
      var width = sub * BOX_W + (sub - 1) * SUB_GAP;
      cols.push({ zone: z, x: x, width: width, count: list.length });
      tallest = Math.max(tallest, rows);
      x += width + COL_GAP;
    });
    return { pos: pos, cols: cols, W: x - COL_GAP + LEFT, H: TOP + tallest * ROW + 12 };
  }

  /* A curve from the side of one box to the side of the other. Forward goes
     right edge to left edge; backward the reverse; within one column it
     bows out to the right, so it never runs through the boxes between. */
  function curve(a, b) {
    var ay = a.y + BOX_H / 2, by = b.y + BOX_H / 2, x1, x2, mx;
    if (b.x > a.x + BOX_W) { x1 = a.x + BOX_W; x2 = b.x; }
    else if (b.x + BOX_W < a.x) { x1 = a.x; x2 = b.x + BOX_W; }
    else {
      var xr = a.x + BOX_W, bow = 22 + Math.min(70, Math.abs(by - ay) / 5);
      return 'M' + xr + ' ' + ay + 'C' + (xr + bow) + ' ' + ay + ' ' + (xr + bow) + ' ' + by + ' ' + (xr + 4) + ' ' + by;
    }
    mx = (x1 + x2) / 2;
    return 'M' + x1 + ' ' + ay + 'C' + mx + ' ' + ay + ' ' + mx + ' ' + by + ' ' + (x2 - (x2 > x1 ? 4 : -4)) + ' ' + by;
  }

  /* One drawn curve per pair of systems. Parallel relationships (a grant and
     an observed use of it) are listed on the curve rather than stacked. */
  function pairs(map) {
    var byPair = {}, list = [];
    map.edges.forEach(function (e) {
      var key = e.s + '>' + e.t, p = byPair[key];
      if (!p) { p = byPair[key] = { key: key, s: e.s, t: e.t, kinds: [], isNew: false, tactics: [] }; list.push(p); }
      if (p.kinds.indexOf(e.kind) < 0) p.kinds.push(e.kind);
      if (e.tactic && p.tactics.indexOf(e.tactic) < 0) p.tactics.push(e.tactic);
      p.isNew = p.isNew || e.is_new;
    });
    return list;
  }

  function stepsOnto(steps, index, mark) {
    (steps || []).forEach(function (st) {
      var a = index[st.from.id], b = index[st.to.id];
      if (a === undefined || b === undefined) return;
      mark.nodes[a] = true; mark.nodes[b] = true; mark.pairs[a + '>' + b] = true;
    });
  }

  /* What the chosen answer lights up: nodes, curves, and the strongest of
     them (the cheapest route, the origin of a blast). */
  function lightUp(lens, s, index) {
    var mark = { nodes: {}, pairs: {}, strong: {}, strongNodes: {}, tone: 'crit', any: false };
    var d = s.data;
    if (lens === 'routes' && d.exposure.reachable) {
      (d.exposure.paths || []).forEach(function (p) { stepsOnto(p.steps, index, mark); });
      var best = { nodes: {}, pairs: {} };
      stepsOnto(d.exposure.cheapest.steps, index, best);
      mark.strong = best.pairs; mark.strongNodes = best.nodes;
    } else if (lens === 'blast' && s.blast && s.blast.origin === s.origin) {
      var hop = {}, origin = index[s.origin];
      if (origin !== undefined) { hop[origin] = 0; mark.nodes[origin] = true; mark.strongNodes[origin] = true; }
      Object.keys(s.blast.data.hops || {}).forEach(function (k) {
        (s.blast.data.hops[k] || []).forEach(function (m) {
          var i = index[m.id];
          if (i !== undefined) { hop[i] = +k; mark.nodes[i] = true; }
        });
      });
      s.pairs.forEach(function (p) {
        if (hop[p.s] !== undefined && hop[p.t] !== undefined && Math.abs(hop[p.s] - hop[p.t]) === 1) mark.pairs[p.key] = true;
      });
      mark.tone = 'accent';
    } else if (lens === 'new') {
      s.pairs.forEach(function (p) { if (p.isNew) { mark.pairs[p.key] = true; mark.nodes[p.s] = true; mark.nodes[p.t] = true; } });
      if (s.novel) (s.novel.new_reach || []).forEach(function (r) {
        if (!r.unflagged_by_rules) return;
        var strong = { nodes: {}, pairs: {} };
        stepsOnto(r.steps, index, strong);
        Object.keys(strong.pairs).forEach(function (k) { mark.strong[k] = true; mark.pairs[k] = true; });
        Object.keys(strong.nodes).forEach(function (k) { mark.strongNodes[k] = true; mark.nodes[k] = true; });
      });
      mark.tone = 'warn';
    } else if (lens === 'unused' && s.unused) {
      (s.unused.grants || []).forEach(function (g) {
        var a = index[g.identity.id], b = index[g.target.id];
        if (a === undefined || b === undefined) return;
        mark.nodes[a] = true; mark.nodes[b] = true; mark.pairs[a + '>' + b] = true;
      });
      mark.tone = 'jewel';
    }
    mark.any = Object.keys(mark.nodes).length > 0;
    return mark;
  }

  function MapSvg(props) {
    var map = props.map, lay = props.layout, mark = props.mark, sel = props.selected;
    var tone = 'var(--' + mark.tone + ')';
    var near = {};
    if (sel !== null) props.pairs.forEach(function (p) { if (p.s === sel || p.t === sel) { near[p.key] = true; near[p.s] = true; near[p.t] = true; } });
    var kids = [h('defs', { key: 'd' },
      h('marker', { id: 'gx-arrow', viewBox: '0 0 8 8', refX: 7, refY: 4, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' },
        h('path', { d: 'M0 0L8 4L0 8z', fill: tone })))];
    lay.cols.forEach(function (c) {
      var crown = c.zone === 'crown';
      kids.push(h('rect', { key: 'zb' + c.zone, x: c.x - 10, y: 8, width: c.width + 20, height: lay.H - 10, rx: 8,
        fill: crown ? 'color-mix(in srgb, var(--jewel) 7%, transparent)' : 'var(--panel-2)' }));
      kids.push(h('text', { key: 'zl' + c.zone, x: c.x, y: 29, fill: crown ? 'var(--jewel)' : 'var(--text-3)', 'font-size': 10.5,
        'font-weight': 650, 'letter-spacing': 1.1 }, (GX.ZONE[c.zone] || c.zone).toUpperCase() + ' · ' + c.count));
    });
    var lit = [];
    props.pairs.forEach(function (p) {
      var on = mark.pairs[p.key] || near[p.key], strong = mark.strong[p.key];
      var d = curve(lay.pos[p.s], lay.pos[p.t]);
      var title = p.kinds.join(', ') + (p.tactics.length ? ' · ' + p.tactics.join(', ') : '') + (p.isNew ? ' · new' : '');
      var path = h('path', { key: 'e' + p.key, d: d, fill: 'none',
        stroke: on ? (near[p.key] && !mark.pairs[p.key] ? 'var(--accent)' : tone) : 'var(--line-2)',
        'stroke-width': strong ? 2.6 : on ? 1.7 : 1, opacity: on ? 1 : (mark.any || sel !== null ? 0.28 : 0.75),
        'stroke-dasharray': p.kinds.length === 1 && p.kinds[0] === 'entitled' ? '4 3' : undefined,
        'marker-end': on ? 'url(#gx-arrow)' : undefined }, h('title', null, title));
      (on ? lit : kids).push(path);
    });
    kids = kids.concat(lit);
    map.nodes.forEach(function (node, i) {
      var p = lay.pos[i], on = mark.nodes[i] || near[i], strong = mark.strongNodes[i], picked = sel === i;
      var dim = (mark.any || sel !== null) && !on && !picked;
      var crown = node.is_crown_jewel;
      var stroke = picked ? 'var(--accent)' : strong ? tone : crown ? 'var(--jewel)' : on ? tone : 'var(--line-2)';
      var label = node.key.length > 24 ? node.key.slice(0, 23) + '…' : node.key;
      kids.push(h('a', { key: 'n' + i, href: '#/graph', 'aria-label': node.key + ', ' + (GX.KIND[node.kind] || node.kind) + ', ' + (GX.ZONE[node.zone] || node.zone),
        onClick: function (ev) { ev.preventDefault(); props.onPick(i); }, opacity: dim ? 0.38 : 1 },
        h('title', null, node.key + ' · ' + (GX.KIND[node.kind] || node.kind) + (crown ? ' · crown jewel' : '')),
        h('rect', { x: p.x, y: p.y, width: BOX_W, height: BOX_H, rx: 6, fill: 'var(--panel)', stroke: stroke,
          'stroke-width': picked || strong ? 2.2 : on || crown ? 1.5 : 1 }),
        h('g', { transform: 'translate(' + (p.x + 7) + ' ' + (p.y + 6) + ')', style: { color: crown ? 'var(--jewel)' : 'var(--text-3)' } },
          icon(GX.kindIcon(node.kind, crown), 14)),
        h('text', { x: p.x + 27, y: p.y + 17, fill: crown ? 'var(--jewel)' : 'var(--text)', 'font-size': 11.5,
          'font-weight': crown || strong ? 650 : 500, 'font-family': 'JetBrains Mono, monospace' }, label)));
    });
    return h('svg', { viewBox: '0 0 ' + lay.W + ' ' + lay.H, width: lay.W, height: lay.H, role: 'img',
      'aria-label': 'The estate: ' + map.shown_nodes + ' systems and ' + map.shown_edges + ' relationships across trust zones' }, kids);
  }

  GX.screens.graph = GX.extend(GX.Loader, {
    init: function () {
      this.state.lens = 'routes'; this.state.selected = null; this.state.origin = null;
      this.state.blast = null; this.state.novel = null; this.state.unused = null; this.state.lensError = null;
    },
    load: function () {
      return Promise.all([GX.get('/v1/graph/map'), GX.get('/v1/graph/exposure')])
        .then(function (r) { return { map: r[0], exposure: r[1] }; });
    },
    lens: function (id, origin) {
      var self = this;
      var next = { lens: id, lensError: null };
      if (origin !== undefined) next.origin = origin;
      this.setState(next, function () {
        var st = self.state, want;
        if (id === 'blast') {
          var o = st.origin || self.defaultOrigin();
          if (!o) return;
          if (st.origin !== o) self.setState({ origin: o });
          if (st.blast && st.blast.origin === o) return;
          want = GX.post('/v1/graph/blast-radius', { node_id: o, hops: 3 }).then(function (d) { self.setState({ blast: { origin: o, data: d } }); });
        } else if (id === 'new' && !st.novel) {
          want = GX.get('/v1/graph/novel').then(function (d) { self.setState({ novel: d }); });
        } else if (id === 'unused' && !st.unused) {
          want = GX.get('/v1/graph/over-privilege' + GX.qs({ status: 'dormant', limit: 200 })).then(function (d) { self.setState({ unused: d }); });
        }
        if (want) want.catch(function (err) { self.setState({ lensError: err }); });
      });
    },
    defaultOrigin: function () {
      var d = this.state.data, top = (d.exposure.choke_points || [])[0];
      if (top) return top.id;
      var first = d.map.nodes.filter(function (x) { return x.on_route && !x.is_crown_jewel && x.zone !== 'untrusted'; })[0] || d.map.nodes[0];
      return first ? first.id : null;
    },
    render: function (props, s) {
      var self = this;
      var lensBar = el('div.stack', { style: { gap: '6px' } }, el('span.cap#gl', null, 'Light up'),
        el('div.seg', { role: 'group', 'aria-labelledby': 'gl' }, LENSES.map(function (l) {
          return el('button', { key: l.id, type: 'button', 'aria-pressed': String(s.lens === l.id), onClick: function () { self.lens(l.id); } }, l.label);
        })));
      if (s.error) return el(GX.Fragment, null, GX.head('Graph', null), GX.Problem({ error: s.error, retry: function () { self.reload(); } }));
      if (!s.data) return el(GX.Fragment, null, GX.head('Graph', 'Every system and relationship in the estate'), GX.Loading({ label: 'Drawing the estate' }));

      var map = s.data.map, ex = s.data.exposure;
      var index = {};
      map.nodes.forEach(function (node, i) { index[node.id] = i; });
      var allPairs = pairs(map), lay = layout(map);
      var mark = lightUp(s.lens, Object.assign({ pairs: allPairs }, s), index);
      var crown = map.nodes.filter(function (x) { return x.is_crown_jewel; }).length;
      var fresh = map.edges.filter(function (e) { return e.is_new; }).length;
      var sub = 'Every system and relationship in the estate' + (props.overview ? ' · ' + GX.asOf(props.overview) : '');

      var tiles = el('div.grid.cols-4', null,
        el('div.panel.stat', null, el('span.cap', null, 'Systems'), el('span.v', null, n(map.total_nodes)),
          el('span.s', null, map.truncated ? n(map.shown_nodes) + ' drawn' : 'all drawn')),
        el('div.panel.stat', null, el('span.cap', null, 'Relationships'), el('span.v', null, n(map.total_edges)),
          el('span.s', null, allPairs.length + ' curves, one per pair of systems')),
        el('div.panel.stat', null, el('span.cap', null, 'Crown jewels'), el('span.v.jewel', null, n(crown)),
          el('span.s', null, ex.reachable ? n(ex.targets.length) + ' reachable from outside' : 'none reachable from outside')),
        el('div.panel.stat', null, el('span.cap', null, 'New in ' + map.window_hours + 'h'), el('span.v', { style: { color: fresh ? 'var(--warn)' : 'var(--text)' } }, n(fresh)),
          el('span.s', null, 'relationships first seen in the window')));

      var cut = map.truncated ? el('div.callout.warn', { role: 'status' }, icon('warn', 20), el('div.body', null,
        el('strong', null, 'Showing ' + n(map.shown_nodes) + ' of ' + n(map.total_nodes) + ' systems and ' + n(map.shown_edges) + ' of ' + n(map.total_edges) + ' relationships'),
        el('span.dim', null, map.kept_by ? 'Kept: ' + map.kept_by + '. Every count on the other screens is over the whole estate.'
          : 'Every system is drawn, and the relationships on routes come first.'))) : null;

      var legend = el('div.legend', null,
        s.lens === 'routes' ? el('span', null, el('i', { style: { width: '18px', borderTop: '2.6px solid var(--crit)', display: 'inline-block' } }), 'Cheapest route') : null,
        s.lens !== 'none' ? el('span', null, el('i', { style: { width: '18px', borderTop: '1.7px solid var(--' + mark.tone + ')', display: 'inline-block' } }), LENSES.filter(function (l) { return l.id === s.lens; })[0].label) : null,
        el('span', null, el('i', { style: { width: '18px', borderTop: '1px dashed var(--text-3)', display: 'inline-block' } }), 'Granted, no use observed'),
        el('span', null, el('i', { style: { width: '10px', height: '10px', borderRadius: '3px', border: '1.5px solid var(--jewel)', display: 'inline-block' } }), 'Crown jewel'));

      var canvas = el('section.panel.clip', null,
        el('div.panel-head', null, el('div.row', null, el('h2', null, 'The estate'),
          el('span.dim', null, n(map.shown_nodes) + ' systems · ' + n(map.shown_edges) + ' relationships · ' + map.zones.length + ' trust zones')), legend),
        el('div.graph-map', null, MapSvg({ map: map, layout: lay, mark: mark, pairs: allPairs, selected: s.selected,
          onPick: function (i) { self.setState({ selected: s.selected === i ? null : i }); } })));

      return el(GX.Fragment, null, GX.head('Graph', sub, lensBar), GX.redactionNote(map), tiles, cut, canvas,
        el('div.split', null, this.lensPanel(s, ex, map), this.systemPanel(s, map, allPairs)));
    },

    lensPanel: function (s, ex, map) {
      var self = this, body;
      var box = function (title, note, kids) {
        return el('section.panel.clip', { style: { flex: '7 1 520px', minWidth: 0 } },
          el('div.panel-head', null, el('h2', null, title), note ? el('span.faint', null, note) : null), el('div.lens-body', null, kids));
      };
      if (s.lensError) return box('Could not light this up', null, GX.Problem({ error: s.lensError, retry: function () { self.lens(s.lens); } }));
      if (s.lens === 'routes') {
        if (!ex.reachable) return box('Routes to crown jewels', null, GX.Empty({ title: ex.why || 'No route reaches a crown jewel' }));
        body = [el('p', { key: 'p' }, el('strong', null, n(ex.path_count) + ' routes'), ' run from the internet to ' + n(ex.targets.length) + ' of ' + n(ex.crown_jewels_total) +
          ' crown jewels' + (ex.capped ? ', and the search stopped at its cap, so that is a floor' : '') + '. The thick one is the cheapest, at effort ' + ex.cheapest.cost + '.'),
          el('div', { key: 'c' }, GX.Chain({ steps: ex.cheapest.steps })),
          el('a.btn.small', { key: 'a', href: '#/exposure', style: { marginTop: '14px', alignSelf: 'flex-start' } }, 'Open Exposure', icon('arrow', 14))];
        return box('Routes to crown jewels', 'every route lit, the cheapest thickest', body);
      }
      if (s.lens === 'blast') {
        if (!s.blast || s.blast.origin !== s.origin) return box('Blast radius', null, GX.Loading({ label: 'Walking out from the system' }));
        var b = s.blast.data, hops = b.hops || {};
        body = [el('p', { key: 'p' }, 'If ', el('strong.mono', null, b.origin.key), ' is taken, ', el('strong', null, n(b.total) + ' systems'), ' are within three hops.'),
          el('div.stats', { key: 's' }, Object.keys(hops).sort().map(function (k) {
            return el('div.stat', { key: k }, el('span.cap', null, k + (k === '1' ? ' hop' : ' hops')), el('span.v', null, n((hops[k] || []).length)));
          })),
          (b.crown_jewels_reached || []).length ? el('p', { key: 'j', style: { color: 'var(--jewel)', fontWeight: 600, marginTop: '12px' } },
            'Crown jewels in reach: ' + b.crown_jewels_reached.map(function (c) { return c.key; }).join(', ')) : el('p.faint', { key: 'j', style: { marginTop: '12px' } }, 'No crown jewel within three hops.'),
          el('p.faint', { key: 'h' }, 'Pick any system on the map, then Blast radius from here.')];
        return box('Blast radius', 'what one compromise puts in reach', body);
      }
      if (s.lens === 'new') {
        if (!s.novel) return box('New in 24h', null, GX.Loading({ label: 'Comparing with the graph before the window' }));
        var unflagged = (s.novel.new_reach || []).filter(function (r) { return r.unflagged_by_rules; });
        body = [el('p', { key: 'p' }, el('strong', null, n(s.novel.new_edge_count) + ' relationships'), ' were first seen in the last ' + s.novel.window_hours + ' hours. ',
          el('strong', null, n(unflagged.length)), ' new routes crossed only steps no rule has fired on, drawn thickest.')]
          .concat(unflagged.slice(0, 3).map(function (r, i) {
            return el('div', { key: 'r' + i, style: { marginTop: '10px' } }, GX.Chain({ steps: r.steps }));
          }));
        return box('New in 24h', 'first sightings, and the routes they open', body);
      }
      if (s.lens === 'unused') {
        if (!s.unused) return box('Unused access', null, GX.Loading({ label: 'Comparing access granted with access used' }));
        var grants = s.unused.grants || [];
        body = [el('p', { key: 'p' }, el('strong', null, n(s.unused.total) + ' grants'), ' have never been used, or not inside the idle window. ',
          n(grants.filter(function (g) { return g.reaches_crown_jewel; }).length) + ' of them reach a crown jewel.')]
          .concat(grants.slice(0, 6).map(function (g, i) {
            return el('div.row', { key: 'g' + i, style: { gap: '8px', marginTop: '8px' } }, GX.NodeLink({ node: g.identity }), el('span.faint', null, 'may reach'),
              el('span' + (g.reaches_crown_jewel ? '.jewel' : ''), null, GX.NodeLink({ node: g.target })), GX.Pill({ tone: 'outline', children: GX.cap1(g.status) }));
          }))
          .concat([el('a.btn.small', { key: 'a', href: '#/access', style: { marginTop: '14px', alignSelf: 'flex-start' } }, 'Open Access', icon('arrow', 14))]);
        return box('Unused access', 'granted, against observed', body);
      }
      return box('Everything', null, el('p', null, 'Every system the sources reported, in the trust zone it sits in, with every relationship between them. ' +
        'Pick a lens above to light one answer up on it, or pick a system to see what it touches.'));
    },

    systemPanel: function (s, map, allPairs) {
      var self = this;
      var wrap = function (kids) {
        return el('section.panel.clip', { style: { flex: '5 1 340px', minWidth: 0 } }, el('div.panel-head', null, el('h2', null, 'System')), el('div.lens-body', null, kids));
      };
      if (s.selected === null || !map.nodes[s.selected]) return wrap(el('p.faint', null, 'Pick any system on the map. Its relationships light up, and it can be opened or used as the origin of a blast radius.'));
      var node = map.nodes[s.selected], i = s.selected;
      var out = allPairs.filter(function (p) { return p.s === i; }).length, inn = allPairs.filter(function (p) { return p.t === i; }).length;
      return wrap([
        el('div.row', { key: 'k', style: { gap: '8px' } }, el('strong.mono' + (node.is_crown_jewel ? '.jewel' : ''), { style: { fontSize: '15px' } }, node.key),
          node.is_crown_jewel ? GX.Pill({ tone: 'jewel', children: 'Crown jewel' }) : null),
        el('p.dim', { key: 'd' }, (GX.KIND[node.kind] || node.kind) + ' · ' + (GX.ZONE[node.zone] || node.zone) +
          (node.regimes && node.regimes.length ? ' · ' + node.regimes.join(', ') : '') + (node.on_route ? ' · on a route to a crown jewel' : '')),
        el('p', { key: 'c' }, n(out) + ' outgoing and ' + n(inn) + ' incoming, ' + n(node.degree) + ' relationships in all.'),
        el('div.row', { key: 'b', style: { gap: '8px', marginTop: '12px' } },
          el('button.btn.small', { type: 'button', onClick: function () { GX.openNode(node.id); } }, 'Open system', icon('arrow', 14)),
          el('button.btn.small', { type: 'button', onClick: function () { self.lens('blast', node.id); } }, 'Blast radius from here'))
      ]);
    }
  });
})();
