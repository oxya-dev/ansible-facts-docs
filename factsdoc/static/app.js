(function () {
  'use strict';

  const INDEX = window.FACTS_INDEX;
  const REPO = 'https://github.com/ansible/ansible/blob/v';
  // Presentation groups, by the gather_subset (collector) that produces a fact.
  const CATEGORIES = [
    ['System', ['platform', 'distribution', 'lsb', 'pkg_mgr', 'service_mgr', 'python', 'date_time', 'env',
                'user', 'cmdline', 'systemd', 'loadavg']],
    ['Hardware', ['hardware']],
    ['Network', ['network', 'dns', 'fibre_channel_wwn', 'iscsi', 'nvme']],
    ['Virtualization', ['virtual']],
    ['Security', ['selinux', 'apparmor', 'caps', 'fips', 'chroot', 'ssh_pub_keys']],
    ['Custom and third-party facts', ['local', 'facter', 'ohai']],
    ['Gathering metadata', ['gather_subset']],
  ];
  const TYPE_CLASS = { str: 'str', int: 'num', float: 'num', bool: 'bool', list: 'list', dict: 'dict', null: 'null', any: 'any' };
  const CHEVRON = '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M6 4l4 4-4 4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  const $ = (s) => document.querySelector(s);
  const ui = {
    version: $('#version'), search: $('#search'), subset: $('#subset'), platform: $('#platform'),
    facts: $('#facts'), nav: $('#nav'), count: $('#count'), empty: $('#empty'), stats: $('#stats'), ver: $('#ver'),
  };

  let data = null;
  let rows = [];        // every node, depth-first; depth 0 = top-level fact
  let groups = [];      // [{name, el, navEl, facts: [row]}]
  // Explicit user choice per node path (true = open, false = closed). Nodes without a
  // choice are closed, except during a search where they open to reveal matches.
  let opened = new Map();
  let hit = new Set();
  let focusFact = '';

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
  const slug = (s) => 'fact-' + s.replace(/[^A-Za-z0-9_-]+/g, '-');

  function loadVersion(minor) {
    window.FACTS_DATA = window.FACTS_DATA || {};
    if (window.FACTS_DATA[minor]) return Promise.resolve(window.FACTS_DATA[minor]);
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'data/' + minor + '.js';
      s.onload = () => resolve(window.FACTS_DATA[minor]);
      s.onerror = () => reject(new Error('Cannot load ' + s.src));
      document.head.appendChild(s);
    });
  }

  function flatten(recs, depth, parent, top, out) {
    for (const rec of recs) {
      const path = !parent ? rec.n : (rec.n === '[]' ? parent.path + '[]' : parent.path + '.' + rec.n);
      const row = { rec, depth, parent, top: null, path, kids: [] };
      row.top = top || row;
      row.text = (path + ' ' + (rec.v || '') + ' ' + rec.d + ' ' + (rec.note || '') + ' ' +
                  (rec.src || []).join(' ')).toLowerCase();
      out.push(row);
      if (parent) parent.kids.push(row);
      if (rec.c) flatten(rec.c, depth + 1, row, row.top, out);
    }
    return out;
  }

  // ------------------------------------------------------------------ rendering

  function typeHtml(types) {
    return '<span class="type">' + esc(types.join(' | ')).replace(/[a-z]+|[[\]|]/g, (w) =>
      TYPE_CLASS[w] ? '<span class="t-' + TYPE_CLASS[w] + '">' + w + '</span>' : '<span class="t-punct">' + w + '</span>') +
      '</span>';
  }

  function keyClass(name) {
    return name === '[]' || name.includes('<') ? ' ph' : '';
  }

  function sourcesHtml(rec) {
    const items = (rec.src || []).map((s) => {
      const i = s.indexOf(':');
      const kind = s.slice(0, i);
      return '<li><span class="origin origin-' + esc(kind) + '">' + esc(kind) + '</span><code>' +
        esc(s.slice(i + 1)) + '</code></li>';
    });
    return items.length ? '<ul class="origins">' + items.join('') + '</ul>' : '';
  }

  function linksHtml(rec, limit) {
    const at = rec.at || [];
    const shown = at.slice(0, limit).map(([file, line, func]) =>
      '<a class="codelink" href="' + REPO + esc(data.version) + '/lib/' + esc(file) + '#L' + line +
      '" target="_blank" rel="noopener" title="' + esc(file + ' · ' + func) + '">' +
      esc(file.split('/').pop()) + ':' + line + '</a>');
    if (at.length > limit) {
      shown.push('<span class="more" title="' + esc(at.slice(limit).map((a) => a[0] + ':' + a[1]).join('\n')) +
                 '">+' + (at.length - limit) + ' more</span>');
    }
    return shown.join('');
  }

  function factHtml(row) {
    const r = row.rec;
    const minimal = new Set(data.minimal_subset);
    const subsets = r.s.map((s) => '<span class="chip subset' + (minimal.has(s) ? ' min' : '') + '"' +
      (minimal.has(s) ? ' title="Gathered even with gather_subset: [min]"' : '') + '>' + esc(s) + '</span>').join('');
    const plats = r.p.includes('any')
      ? '<span class="chip plat any">All platforms</span>'
      : r.p.map((p) => '<span class="chip plat">' + esc(p) + '</span>').join('');
    const nsrc = (r.src || []).length;
    const nat = (r.at || []).length;
    const source = nsrc || nat || r.note
      ? '<details class="source"><summary>Source <span class="muted">' +
        [nsrc ? nsrc + (nsrc > 1 ? ' inputs' : ' input') : '', nat ? nat + (nat > 1 ? ' code locations' : ' code location') : '']
          .filter(Boolean).join(' · ') + '</span></summary>' + sourcesHtml(r) +
        (nat ? '<div class="codelinks">' + linksHtml(r, 12) + '</div>' : '') +
        (r.note ? '<p class="note">Comment in the code: ' + esc(r.note) + '</p>' : '') + '</details>'
      : '';
    const kids = row.kids.length
      ? '<button class="kids-toggle" type="button" aria-expanded="false">' + CHEVRON + '<span></span></button>' +
        '<div class="props" hidden></div>'
      : '';
    return '<header class="fact-head"><h3><a class="anchor" href="#" aria-label="Link to ' + esc(r.n) + '">#</a>' +
      '<code class="fact-name' + keyClass(r.n) + '">' + esc(r.n) + '</code></h3>' + typeHtml(r.t) +
      (r.g ? '<span class="tag-auto" title="Description derived from the fact name">auto</span>' : '') + '</header>' +
      '<p class="desc">' + inline(r.d) + '</p>' +
      '<dl class="meta">' +
      '<div><dt>Access</dt><dd><code>ansible_facts[\'' + esc(r.n) + '\']</code><code class="legacy">' + esc(r.v) + '</code></dd></div>' +
      '<div><dt>gather_subset</dt><dd>' + subsets + '</dd></div>' +
      '<div><dt>Platforms</dt><dd>' + plats + '</dd></div>' +
      '</dl>' + source + kids;
  }

  function propHtml(row) {
    const r = row.rec;
    const tog = row.kids.length
      ? '<button class="tog" type="button" aria-label="Toggle child keys" aria-expanded="false">' + CHEVRON + '</button>'
      : '<span class="tog-pad"></span>';
    const src = sourcesHtml(r);
    const links = linksHtml(r, 3);
    return '<div class="prop-line">' + tog + '<code class="key' + keyClass(r.n) + '">' + esc(r.n) + '</code>' +
      typeHtml(r.t) + (r.g ? '<span class="tag-auto" title="Description derived from the fact name">auto</span>' : '') +
      '</div><div class="prop-body"><p class="desc">' + inline(r.d) + '</p>' +
      (src || links || r.note ? '<div class="prop-src">' + src + (links ? '<div class="codelinks">' + links + '</div>' : '') +
        (r.note ? '<span class="note-icon" tabindex="0" title="Comment in the code: ' + esc(r.note) + '">comment</span>' : '') +
        '</div>' : '') +
      '</div>';
  }

  function categoryOf(rec) {
    for (const [name, subsets] of CATEGORIES) if (rec.s.some((s) => subsets.includes(s))) return name;
    return 'Other';
  }

  function render() {
    rows = flatten(data.facts, 0, null, null, []);
    const byCat = new Map(CATEGORIES.map(([n]) => [n, []]));
    byCat.set('Other', []);
    const main = document.createDocumentFragment();
    const nav = document.createDocumentFragment();
    let currentProps = null;
    rows.forEach((row, i) => {
      row.i = i;
      if (row.depth === 0) {
        const sec = document.createElement('section');
        sec.className = 'fact';
        sec.id = slug(row.path);
        sec.dataset.i = i;
        sec.innerHTML = factHtml(row);
        row.el = sec;
        row.btn = sec.querySelector('.kids-toggle');
        row.props = sec.querySelector('.props');
        currentProps = row.props;
        byCat.get(categoryOf(row.rec)).push(row);
      } else {
        const div = document.createElement('div');
        div.className = 'prop';
        div.style.setProperty('--depth', row.depth - 1);
        div.dataset.i = i;
        div.innerHTML = propHtml(row);
        row.el = div;
        row.btn = div.querySelector('.tog');
        currentProps.appendChild(div);
      }
    });
    groups = [];
    for (const [name, facts] of byCat) {
      if (!facts.length) continue;
      const head = document.createElement('h2');
      head.className = 'group';
      head.textContent = name;
      main.appendChild(head);
      facts.forEach((f) => main.appendChild(f.el));
      const navGroup = document.createElement('div');
      navGroup.className = 'nav-group';
      navGroup.innerHTML = '<p class="nav-title">' + esc(name) + '</p><ul>' + facts.map((f) =>
        '<li><a href="#" data-i="' + f.i + '" class="' + keyClass(f.rec.n).trim() + '">' + esc(f.rec.n) + '</a></li>').join('') + '</ul>';
      nav.appendChild(navGroup);
      facts.forEach((f) => { f.navEl = navGroup.querySelector('a[data-i="' + f.i + '"]'); });
      groups.push({ name, el: head, navEl: navGroup, facts });
    }
    ui.facts.replaceChildren(main);
    ui.nav.replaceChildren(nav);
    for (const row of rows) {
      if (row.depth === 0) row.el.querySelector('.anchor').href = hashFor(row.path);
      if (row.navEl) row.navEl.href = hashFor(row.path);
    }
    const s = data.stats;
    ui.ver.textContent = data.version;
    ui.stats.innerHTML =
      '<div><dt>Top-level facts</dt><dd>' + s.top + '</dd></div>' +
      '<div><dt>Keys, nested included</dt><dd>' + s.total + '</dd></div>' +
      '<div><dt>Collectors</dt><dd>' + data.collectors.length + '</dd></div>' +
      '<div><dt>Source</dt><dd><a href="https://github.com/ansible/ansible/tree/v' + esc(data.version) +
      '/lib/ansible/module_utils/facts" target="_blank" rel="noopener">v' + esc(data.version) + '</a></dd></div>';
    refresh();
    observeSections();
  }

  // ------------------------------------------------------------------ state

  function passesFilters(rec) {
    const subset = ui.subset.value;
    const plat = ui.platform.value;
    if (subset === 'min:') {
      if (!rec.s.some((s) => data.minimal_subset.includes(s))) return false;
    } else if (subset && !rec.s.includes(subset)) return false;
    if (plat && !rec.p.includes(plat) && !rec.p.includes('any')) return false;
    return true;
  }

  function isOpen(row) {
    return opened.has(row.path) ? opened.get(row.path) : row.kids.some((k) => hit.has(k));
  }

  function refresh() {
    const q = ui.search.value.trim().toLowerCase();
    hit = new Set();
    if (q) {
      for (let i = rows.length - 1; i >= 0; i--) {
        const row = rows[i];
        if (row.text.includes(q) || row.kids.some((k) => hit.has(k))) hit.add(row);
      }
    }
    const show = new Set();
    for (const row of rows) {
      const p = row.parent;
      let vis;
      if (!p) vis = passesFilters(row.rec) && (!q || hit.has(row));
      // Opened by hand: every child; opened by the search: only the matching branches.
      else vis = show.has(p) && isOpen(p) && (!q || opened.get(p.path) === true || hit.has(row));
      if (vis) show.add(row);
    }
    let count = 0;
    for (const row of rows) {
      const vis = show.has(row);
      row.el.hidden = !vis;
      if (row.depth === 0) {
        if (vis) count++;
        const details = row.el.querySelector('details.source');
        if (details && q && (row.rec.src || []).join(' ').toLowerCase().includes(q)) details.open = true;
        row.navEl.parentElement.hidden = !vis;
        if (row.props) {
          const open = isOpen(row);
          row.props.hidden = !open;
          row.btn.setAttribute('aria-expanded', String(open));
          row.btn.lastChild.textContent = open ? 'Hide child keys'
            : 'Show ' + row.kids.length + (row.kids.length > 1 ? ' child keys' : ' child key');
        }
      } else if (row.btn) {
        row.btn.setAttribute('aria-expanded', String(isOpen(row)));
      }
    }
    for (const g of groups) {
      const any = g.facts.some((f) => show.has(f));
      g.el.hidden = !any;
      g.navEl.hidden = !any;
    }
    ui.empty.hidden = count > 0;
    ui.count.textContent = count === data.facts.length
      ? data.facts.length + ' facts'
      : 'Showing ' + count + ' of ' + data.facts.length + ' facts';
    writeHash();
  }

  // ------------------------------------------------------------------ navigation

  function hashFor(fact) {
    const h = new URLSearchParams();
    h.set('v', data.minor);
    if (ui.search.value) h.set('q', ui.search.value);
    if (fact) h.set('f', fact);
    return '#' + h.toString();
  }

  function readHash() {
    const h = new URLSearchParams(location.hash.slice(1));
    return { v: h.get('v'), q: h.get('q') || '', f: h.get('f') || '' };
  }

  function writeHash() {
    const next = hashFor(focusFact);
    if (location.hash !== next) history.replaceState(null, '', next);
  }

  function goTo(fact) {
    const row = rows.find((r) => r.depth === 0 && r.path === fact);
    if (!row) return;
    focusFact = fact;
    if (row.el.hidden) {
      ui.search.value = '';
      ui.subset.value = '';
      ui.platform.value = '';
      refresh();
    }
    writeHash();
    row.el.scrollIntoView({ block: 'start' });
    row.el.classList.remove('flash');
    void row.el.offsetWidth;
    row.el.classList.add('flash');
    document.body.classList.remove('nav-open');
  }

  let observer = null;
  function observeSections() {
    if (observer) observer.disconnect();
    if (!('IntersectionObserver' in window)) return;
    const visible = new Set();
    observer = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (e.isIntersecting) visible.add(e.target); else visible.delete(e.target);
      }
      let first = null;
      for (const el of visible) if (!first || el.offsetTop < first.offsetTop) first = el;
      ui.nav.querySelectorAll('a.active').forEach((a) => a.classList.remove('active'));
      if (first) {
        const a = rows[first.dataset.i].navEl;
        a.classList.add('active');
        const nav = $('#sidebar');
        const r = a.getBoundingClientRect();
        const nr = nav.getBoundingClientRect();
        if (r.top < nr.top + 80 || r.bottom > nr.bottom - 20) a.scrollIntoView({ block: 'nearest' });
      }
    }, { rootMargin: '-130px 0px -55% 0px' });
    rows.forEach((r) => r.depth === 0 && observer.observe(r.el));
  }

  function fillSelect(sel, values, label) {
    const keep = sel.value;
    sel.replaceChildren(new Option(label, ''));
    for (const [v, text] of values) sel.add(new Option(text, v));
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : '';
  }

  async function show(minor, fact) {
    try {
      data = await loadVersion(minor);
    } catch (e) {
      ui.count.textContent = e.message;
      return;
    }
    ui.version.value = minor;
    const subsets = new Set();
    const plats = new Set();
    for (const f of data.facts) {
      f.s.forEach((s) => subsets.add(s));
      f.p.forEach((p) => p !== 'any' && plats.add(p));
    }
    fillSelect(ui.subset, [['min:', 'min (always gathered)'], ...[...subsets].sort().map((s) => [s, s])], 'All');
    fillSelect(ui.platform, [...plats].sort().map((p) => [p, p]), 'All');
    render();
    if (fact) goTo(fact);
  }

  function init() {
    for (const v of INDEX.versions) ui.version.add(new Option(v.minor + '  ·  ' + v.version, v.minor));
    const h = readHash();
    ui.search.value = h.q;
    const minor = INDEX.versions.some((v) => v.minor === h.v) ? h.v : INDEX.default;

    ui.version.addEventListener('change', () => show(ui.version.value, focusFact));
    let t = null;
    ui.search.addEventListener('input', () => {
      clearTimeout(t);
      t = setTimeout(() => {
        // A new search must be able to reveal its matches: forget hand-closed nodes.
        for (const [k, v] of opened) if (!v) opened.delete(k);
        focusFact = '';
        refresh();
      }, 120);
    });
    ui.subset.addEventListener('change', refresh);
    ui.platform.addEventListener('change', refresh);
    $('#expand').addEventListener('click', () => {
      rows.forEach((r) => r.kids.length && opened.set(r.path, true));
      refresh();
    });
    $('#collapse').addEventListener('click', () => {
      opened = new Map();
      rows.forEach((r) => r.kids.length && opened.set(r.path, false));
      refresh();
    });
    ui.facts.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.tog, .kids-toggle');
      if (btn) {
        const row = rows[btn.closest('[data-i]').dataset.i];
        opened.set(row.path, !isOpen(row));
        refresh();
        return;
      }
      const anchor = ev.target.closest('.anchor');
      if (anchor) {
        ev.preventDefault();
        goTo(rows[anchor.closest('[data-i]').dataset.i].path);
      }
    });
    ui.nav.addEventListener('click', (ev) => {
      const a = ev.target.closest('a[data-i]');
      if (!a) return;
      ev.preventDefault();
      goTo(rows[a.dataset.i].path);
    });
    $('#menu').addEventListener('click', () => {
      const open = document.body.classList.toggle('nav-open');
      $('#menu').setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('keydown', (ev) => {
      if (ev.key === '/' && document.activeElement !== ui.search && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) {
        ev.preventDefault();
        ui.search.focus();
        ui.search.select();
      } else if (ev.key === 'Escape' && document.activeElement === ui.search && ui.search.value) {
        ui.search.value = '';
        ui.search.dispatchEvent(new Event('input'));
      }
    });
    window.addEventListener('hashchange', () => {
      const next = readHash();
      if (next.q !== ui.search.value) ui.search.value = next.q;
      if (next.v && next.v !== data.minor && INDEX.versions.some((v) => v.minor === next.v)) show(next.v, next.f);
      else if (next.f && next.f !== focusFact) goTo(next.f);
      else refresh();
    });
    show(minor, h.f);
  }

  init();
})();
