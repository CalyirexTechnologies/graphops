/* GraphOps console, shared core.
 *
 * Plain scripts, no build step, matching the rest of the repository: the
 * engine runs with nothing installed and so does this. Preact is vendored
 * from the design export (MIT, see vendor/PREACT-LICENSE).
 *
 * Two rules hold everywhere in the console:
 *   - Every number on screen comes from the API. Nothing is sample data.
 *   - No markup is built from strings. Every element goes through h(), so
 *     a crown jewel name or a log line can never become HTML, and the page
 *     runs under a CSP with no 'unsafe-inline' scripts and no eval.
 */
(function () {
  'use strict';
  var P = window.preact;
  var GX = window.GX = {};
  GX.h = P.h;
  GX.Component = P.Component;
  GX.Fragment = P.Fragment;
  GX.render = P.render;

  /* el('div.panel.clip#id', props, ...children): a tag with classes and an
     id. A component (a function) passes straight through to h(). */
  function isVNode(v) { return v && typeof v === 'object' && v.type !== undefined && v.props !== undefined; }
  function el(spec) {
    var props = arguments[1];
    var kids = Array.prototype.slice.call(arguments, 2);
    if (props === null || props === undefined || typeof props !== 'object'
        || Array.isArray(props) || isVNode(props)) {
      if (props !== undefined && props !== null) kids.unshift(props);
      props = {};
    }
    if (typeof spec !== 'string') return P.h.apply(null, [spec, props].concat(kids));
    var id = null;
    var hash = spec.indexOf('#');
    if (hash !== -1) { id = spec.slice(hash + 1); spec = spec.slice(0, hash); }
    var parts = spec.split('.');
    var tag = parts[0] || 'div';
    var extra = parts.slice(1).filter(Boolean).join(' ');
    if (extra || id) {
      props = Object.assign({}, props);
      if (extra) props['class'] = props['class'] ? extra + ' ' + props['class'] : extra;
      if (id && !props.id) props.id = id;
    }
    return P.h.apply(null, [tag, props].concat(kids));
  }
  GX.el = el;

  /* ------------------------------------------------------------ storage */
  // sessionStorage for the session's tokens, so closing the tab signs out.
  // localStorage only for the theme, a per-viewer convenience.
  function store(kind) {
    try { return window[kind]; } catch (e) { return null; }
  }
  GX.session = {
    get: function (k) { var s = store('sessionStorage'); try { return s ? s.getItem(k) : null; } catch (e) { return null; } },
    set: function (k, v) { var s = store('sessionStorage'); try { if (s) { if (v === null || v === undefined) s.removeItem(k); else s.setItem(k, v); } } catch (e) { /* private mode */ } }
  };
  GX.local = {
    get: function (k) { var s = store('localStorage'); try { return s ? s.getItem(k) : null; } catch (e) { return null; } },
    set: function (k, v) { var s = store('localStorage'); try { if (s) s.setItem(k, v); } catch (e) { /* private mode */ } }
  };

  /* ---------------------------------------------------------------- api */
  // An error the console can show. The server never sends exception text
  // (it returns a generic message and a request id), and this never adds
  // any: a failed request reads as what went wrong plus the id support
  // needs.
  function ApiError(status, body, requestId) {
    this.status = status;
    this.body = body || {};
    this.requestId = requestId || '';
    this.message = (body && (body.error || body.detail)) || ('request failed (' + status + ')');
    if (typeof this.message !== 'string') this.message = 'the request was not accepted';
  }
  GX.ApiError = ApiError;

  var listeners = [];
  GX.onSignedOut = function (fn) { listeners.push(fn); };

  function tokens() {
    return { access: GX.session.get('gx.access'), refresh: GX.session.get('gx.refresh') };
  }
  GX.tokens = tokens;
  GX.setTokens = function (pair) {
    GX.session.set('gx.access', pair ? pair.access_token : null);
    GX.session.set('gx.refresh', pair ? pair.refresh_token : null);
  };

  var refreshing = null;
  function refresh() {
    if (refreshing) return refreshing;
    var r = tokens().refresh;
    if (!r) return Promise.reject(new ApiError(401, { error: 'signed out' }));
    refreshing = fetch('/v1/auth/refresh', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: r }), credentials: 'same-origin'
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        if (!res.ok) throw new ApiError(res.status, body);
        GX.setTokens(body);
        return body;
      });
    }).finally(function () { refreshing = null; });
    return refreshing;
  }

  GX.api = function (method, path, body, retried) {
    var headers = { 'Accept': 'application/json' };
    var t = tokens().access;
    if (t) headers['Authorization'] = 'Bearer ' + t;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return fetch(path, {
      method: method, headers: headers, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (res) {
      var rid = res.headers.get('X-Request-Id') || '';
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.status === 401 && !retried && tokens().refresh && path.indexOf('/v1/auth/') !== 0) {
          return refresh().then(function () { return GX.api(method, path, body, true); }, function () {
            GX.setTokens(null);
            listeners.forEach(function (fn) { fn(); });
            throw new ApiError(401, data, rid);
          });
        }
        if (!res.ok) throw new ApiError(res.status, data, rid);
        return data;
      });
    });
  };
  GX.get = function (path) { return GX.api('GET', path); };
  GX.post = function (path, body) { return GX.api('POST', path, body || {}); };
  GX.del = function (path) { return GX.api('DELETE', path); };

  GX.qs = function (params) {
    var out = [];
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (v === undefined || v === null || v === '') return;
      out.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    });
    return out.length ? '?' + out.join('&') : '';
  };

  /* -------------------------------------------------------- permissions */
  GX.can = function (me, permission) {
    return !!(me && me.permissions && me.permissions.indexOf(permission) !== -1);
  };

  /* --------------------------------------------------------- formatting */
  var nf = new Intl.NumberFormat('en-IN');
  GX.n = function (v) { return v === null || v === undefined ? '-' : nf.format(v); };
  GX.pct = function (share) { return (Math.round(share * 1000) / 10) + '%'; };

  function toDate(v) {
    if (v === null || v === undefined || v === '') return null;
    if (typeof v === 'number') return new Date(v * 1000);
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  }
  GX.toDate = toDate;
  var tf = new Intl.DateTimeFormat('en-IN', { hour: '2-digit', minute: '2-digit', hour12: false });
  var df = new Intl.DateTimeFormat('en-IN', { weekday: 'short', day: 'numeric', month: 'short' });
  var zone = (function () {
    try {
      var p = new Intl.DateTimeFormat('en-IN', { timeZoneName: 'short' }).formatToParts(new Date());
      var z = p.filter(function (x) { return x.type === 'timeZoneName'; })[0];
      return z ? z.value : '';
    } catch (e) { return ''; }
  })();
  GX.zone = zone === 'GMT+5:30' ? 'IST' : zone;
  GX.time = function (v) { var d = toDate(v); return d ? tf.format(d) : '-'; };
  GX.day = function (v) { var d = toDate(v); return d ? df.format(d) : '-'; };
  GX.when = function (v) {
    var d = toDate(v);
    if (!d) return '-';
    var today = new Date();
    if (d.toDateString() === today.toDateString()) return 'Today ' + tf.format(d);
    return df.format(d) + ' ' + tf.format(d);
  };
  GX.ago = function (v, now) {
    var d = toDate(v);
    if (!d) return '';
    var s = Math.round(((now ? toDate(now) : new Date()) - d) / 1000);
    if (s < 0) s = 0;
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' days ago';
  };
  GX.duration = function (seconds) {
    seconds = Math.max(0, Math.round(seconds || 0));
    if (seconds < 60) return seconds + ' s';
    return Math.floor(seconds / 60) + ' min ' + (seconds % 60) + ' s';
  };
  GX.initials = function (name, email) {
    var src = (name || '').trim() || (email || '').split('@')[0].replace(/[._-]+/g, ' ');
    var bits = src.split(/\s+/).filter(Boolean);
    var out = (bits[0] || '?').charAt(0) + (bits.length > 1 ? bits[bits.length - 1].charAt(0) : '');
    return out.toUpperCase();
  };
  GX.short = function (id) { return String(id || '').slice(0, 8); };

  GX.ZONE = { untrusted: 'Internet', perimeter: 'Perimeter', internal: 'Internal', crown: 'Crown' };
  GX.KIND = { identity: 'Identity', address: 'Address', endpoint: 'Endpoint', asset: 'System',
    vulnerability: 'Vulnerability', service: 'Service', rule: 'Detection rule' };
  GX.FINDING_KIND = { 'attack-path': 'Route', 'choke-point': 'Choke point', 'containment': 'Best fix',
    'over-privilege': 'Dormant access', 'novel-activity': 'Newly reachable' };
  GX.SEVERITIES = ['critical', 'high', 'medium', 'low'];
  GX.cap1 = function (s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); };

  /* -------------------------------------------------------------- icons */
  var ICONS = {
    overview: [['rect', { x: 3, y: 3, width: 7, height: 7, rx: 1.5 }], ['rect', { x: 14, y: 3, width: 7, height: 7, rx: 1.5 }], ['rect', { x: 3, y: 14, width: 7, height: 7, rx: 1.5 }], ['rect', { x: 14, y: 14, width: 7, height: 7, rx: 1.5 }]],
    exposure: [['circle', { cx: 6, cy: 19, r: 2.5 }], ['circle', { cx: 18, cy: 5, r: 2.5 }], ['path', { d: 'M8.5 19H15a3.5 3.5 0 0 0 0-7H9a3.5 3.5 0 0 1 0-7h6.5' }]],
    findings: [['path', { d: 'M12 3l9.5 17h-19L12 3z' }], ['path', { d: 'M12 10v4M12 17.5v.01' }]],
    access: [['circle', { cx: 8, cy: 15, r: 4 }], ['path', { d: 'M10.8 12.2L20 3M16 7l3 3M14 9l2 2' }]],
    compliance: [['path', { d: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z' }], ['path', { d: 'M9 12h6' }]],
    connectors: [['path', { d: 'M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-10 0V8zM12 16v5' }]],
    admin: [['path', { d: 'M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12' }], ['circle', { cx: 16, cy: 6, r: 2 }], ['circle', { cx: 10, cy: 12, r: 2 }], ['circle', { cx: 18, cy: 18, r: 2 }]],
    profile: [['circle', { cx: 12, cy: 8, r: 4 }], ['path', { d: 'M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6' }]],
    signout: [['path', { d: 'M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10' }]],
    search: [['circle', { cx: 11, cy: 11, r: 7 }], ['path', { d: 'M20 20l-3.5-3.5' }]],
    warn: [['path', { d: 'M12 3l9.5 17h-19L12 3z' }], ['path', { d: 'M12 10v4M12 17.5v.01' }]],
    info: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 11v5M12 8v.01' }]],
    sun: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4' }]],
    moon: [['path', { d: 'M20.5 14.2A8.5 8.5 0 1 1 9.8 3.5a6.6 6.6 0 0 0 10.7 10.7z' }]],
    eye: [['path', { d: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
    globe: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z' }]],
    server: [['rect', { x: 4, y: 4, width: 16, height: 6, rx: 1.5 }], ['rect', { x: 4, y: 14, width: 16, height: 6, rx: 1.5 }], ['path', { d: 'M8 7h.01M8 17h.01' }]],
    person: [['circle', { cx: 12, cy: 8, r: 3.5 }], ['path', { d: 'M5 20c1.3-3.5 4-5 7-5s5.7 1.5 7 5' }]],
    diamond: [['path', { d: 'M12 3l8 9-8 9-8-9 8-9z' }]],
    bug: [['rect', { x: 7, y: 8, width: 10, height: 12, rx: 5 }], ['path', { d: 'M12 8V5M4 12h3M17 12h3M5 18l2.5-1.5M19 18l-2.5-1.5M5 6l2.5 2M19 6l-2.5 2' }]],
    cloud: [['path', { d: 'M7 18h10a4 4 0 0 0 .5-8 6 6 0 0 0-11.5 1.5A3.3 3.3 0 0 0 7 18z' }]],
    bell: [['path', { d: 'M6 16V11a6 6 0 0 1 12 0v5l2 2H4l2-2zM10 20a2 2 0 0 0 4 0' }]],
    link: [['path', { d: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1' }]],
    play: [['path', { d: 'M8 5v14l11-7z' }]],
    download: [['path', { d: 'M12 4v11M7 10l5 5 5-5M5 20h14' }]],
    plus: [['path', { d: 'M12 5v14M5 12h14' }]],
    scissors: [['circle', { cx: 6, cy: 6, r: 2.5 }], ['circle', { cx: 6, cy: 18, r: 2.5 }], ['path', { d: 'M8 7.5L20 18M8 16.5L20 6' }]],
    check: [['path', { d: 'M5 12l4 4 10-10' }]],
    ban: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M6 6l12 12' }]],
    circle: [['circle', { cx: 12, cy: 12, r: 8 }]],
    lock: [['rect', { x: 5, y: 11, width: 14, height: 10, rx: 2 }], ['path', { d: 'M8 11V8a4 4 0 0 1 8 0v3' }]],
    arrow: [['path', { d: 'M5 12h14M13 6l6 6-6 6' }]],
    copy: [['rect', { x: 8, y: 8, width: 12, height: 12, rx: 2 }], ['path', { d: 'M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3' }]]
  };
  GX.icon = function (name, size, extra) {
    var defs = ICONS[name] || ICONS.circle;
    return P.h('svg', Object.assign({
      width: size || 16, height: size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
      'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true'
    }, extra || {}), defs.map(function (d, i) { return P.h(d[0], Object.assign({ key: i }, d[1])); }));
  };
  GX.kindIcon = function (kind, crown) {
    if (crown) return 'diamond';
    return { address: 'globe', identity: 'person', asset: 'server', service: 'cloud',
      endpoint: 'link', vulnerability: 'bug', rule: 'bell' }[kind] || 'circle';
  };

  /* --------------------------------------------------------- components */
  GX.Pill = function (props) {
    return el('span.pill' + (props.tone ? '.' + props.tone : ''), { title: props.title }, props.children);
  };
  GX.Sev = function (props) {
    return el('span.sev.' + props.level, null,
      el('span.bars', { 'aria-hidden': 'true' }, el('i'), el('i'), el('i'), el('i')),
      GX.cap1(props.level));
  };
  GX.Regimes = function (props) {
    var list = props.regimes || [];
    if (!list.length) return null;
    return el('span.row', { style: { gap: '4px' } }, list.map(function (r) {
      return el('span.pill.' + (r === 'PCI' ? 'jewel' : 'high'), { key: r }, r);
    }));
  };
  GX.Loading = function (props) {
    return el('div.loading', { role: 'status' }, props.label || 'Loading');
  };
  GX.Problem = function (props) {
    var e = props.error || {};
    var forbidden = e.status === 403;
    return el('div.callout.' + (forbidden ? 'info' : 'bad'), { role: 'alert' },
      GX.icon(forbidden ? 'lock' : 'warn', 20),
      el('div.body', null,
        el('strong', null, forbidden ? 'Your role cannot see this'
          : e.status === 503 ? 'No estate is loaded yet' : 'This did not load'),
        el('span.dim', null, forbidden
          ? 'It needs the ' + ((e.body && e.body.missing_permission) || 'right') + ' permission. An owner or admin can grant it.'
          : e.status === 503 ? 'Run an ingest from Connectors to build one.'
          : 'Try again in a moment.' + (e.requestId ? ' If it keeps happening, quote request ' + e.requestId + '.' : '')),
        props.retry ? el('div', { style: { marginTop: '8px' } }, el('button.btn.small', { type: 'button', onClick: props.retry }, 'Try again')) : null));
  };

  /* A node name that opens its page. Crown jewels read in the jewel colour,
     and a pseudonymised one opens by its pseudonym, which the API resolves. */
  GX.NodeLink = function (props) {
    var n = props.node || {};
    var text = props.text || n.key || n.label || n.id;
    var cls = 'mono' + (n.is_crown_jewel || n.crown ? ' jewel' : '');
    var me = GX._app && GX._app.state.me;
    // A role that cannot open a node page gets the name, not a link to a 403.
    if (me && !GX.can(me, 'graph:query')) return el('span', { 'class': cls }, text);
    return el('a', {
      href: '#/node', 'class': cls, title: n.label && n.label !== text ? n.label : undefined,
      onClick: function (ev) { ev.preventDefault(); GX.openNode(n.id); }
    }, text);
  };

  /* A route as its kill chain: each hop's ATT&CK tactic above the node it reaches. */
  GX.Chain = function (props) {
    var steps = props.steps || [];
    if (!steps.length) return el('span.faint', null, 'No steps');
    var out = [el('span.step', { key: 's' },
      el('span.cap', null, props.startLabel || GX.ZONE[steps[0].from.zone] || 'Start'),
      el('span.n', null, GX.NodeLink({ node: steps[0].from })))];
    steps.forEach(function (s, i) {
      out.push(el('span.arrow', { key: 'a' + i, 'aria-hidden': 'true' }, '›'));
      out.push(el('span.step', { key: 'n' + i },
        el('span.cap', { title: s.technique ? s.tactic_id + ' ' + s.technique : '' }, s.tactic || s.edge),
        el('span.n' + (s.to.is_crown_jewel ? '.crown' : ''), null, GX.NodeLink({ node: s.to }))));
    });
    return el('div.chain', null, out);
  };

  /* Empty({title}, ...children). Takes children as arguments as well as in
     props, because it is called as a function rather than through h(). */
  GX.Empty = function (props) {
    var kids = Array.prototype.slice.call(arguments, 1);
    return el('div.empty', null, props.title ? el('strong', null, props.title) : null,
      kids.length ? kids : props.children);
  };

  /* Download a file the API produced. A real download from our own origin,
     not a data: link a sandbox would block. */
  GX.save = function (name, text, type) {
    var blob = new Blob([text], { type: type || 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 0);
  };

  /* A component that loads one thing. Subclasses define load(). */
  function Loader(props) { P.Component.call(this, props); this.state = { data: null, error: null, busy: true }; }
  Loader.prototype = Object.create(P.Component.prototype);
  Loader.prototype.constructor = Loader;
  Loader.prototype.componentDidMount = function () { this.reload(); };
  Loader.prototype.reload = function () {
    var self = this;
    self.setState({ busy: true });
    var seq = (self._seq = (self._seq || 0) + 1);
    return Promise.resolve(self.load()).then(function (data) {
      if (seq !== self._seq) return;
      self.setState({ data: data, error: null, busy: false });
    }, function (error) {
      if (seq !== self._seq) return;
      self.setState({ error: error, busy: false });
    });
  };
  GX.Loader = Loader;
  GX.extend = function (Base, proto) {
    function C(props) { Base.call(this, props); if (proto.init) proto.init.call(this, props); }
    C.prototype = Object.create(Base.prototype);
    C.prototype.constructor = C;
    Object.keys(proto).forEach(function (k) { C.prototype[k] = proto[k]; });
    return C;
  };
})();
