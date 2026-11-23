(function () {
  'use strict';

  const INDEX = window.FACTS_INDEX;
  const REPO = 'https://github.com/ansible/ansible/blob/v';
  const $ = (s) => document.querySelector(s);
  const ui = {
    version: $('#version'), search: $('#search'), subset: $('#subset'), platform: $('#platform'),
    tbody: $('#facts tbody'), meta: $('#meta'), empty: $('#empty'),
  };
  let rows = [];
  let expanded = new Set();
  let data = null;

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');

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

  function pathOf(parentPath, name) {
    if (!parentPath) return name;
    return name === '[]' ? parentPath + '[]' : parentPath + '.' + name;
  }

  function flatten(recs, depth, parent, top, out) {
    for (const rec of recs) {
      const row = {
        rec, depth, parent, top: top || rec,
        path: pathOf(parent ? parent.path : '', rec.n),
        kids: [],
      };
      row.text = (row.path + ' ' + (rec.v || '') + ' ' + rec.d + ' ' + (rec.note || '') + ' ' +
                  (rec.src || []).join(' ')).toLowerCase();
      out.push(row);
      if (parent) parent.kids.push(row);
      if (rec.c) flatten(rec.c, depth + 1, row, row.top, out);
    }
    return out;
  }

  const TYPE_CLASS = { str: 'str', int: 'num', float: 'num', bool: 'bool', list: 'list', dict: 'dict', null: 'null', any: 'any' };
  function typeHtml(types) {
    return esc(types.join(' | ')).replace(/[a-z]+|[[\]|]/g, (w) =>
      TYPE_CLASS[w] ? '<span class="t-' + TYPE_CLASS[w] + '">' + w + '</span>' : '<span class="t-punct">' + w + '</span>');
  }

  function keyHtml(name) {
    const placeholder = name === '[]' || name.includes('<');
    return '<code class="key' + (placeholder ? ' ph' : '') + '">' + esc(name) + '</code>';
  }

  function sourceCell(rec, version) {
    const parts = [];
    for (const s of rec.src || []) {
      const i = s.indexOf(':');
      const kind = s.slice(0, i);
      parts.push('<span class="s"><span class="k k-' + esc(kind) + '">' + esc(kind) + '</span><code>' +
                 esc(s.slice(i + 1)) + '</code></span>');
    }
    const at = rec.at || [];
    const links = at.slice(0, 3).map(([file, line, func]) =>
      '<a href="' + REPO + esc(version) + '/lib/' + esc(file) + '#L' + line + '" title="' +
      esc(file + ' · ' + func) + '" target="_blank" rel="noopener">' +
      esc(file.split('/').pop()) + ':' + line + '</a>');
    if (at.length > 3) {
      links.push('<span class="more" title="' + esc(at.slice(3).map((a) => a[0] + ':' + a[1]).join('\n')) +
                 '">+' + (at.length - 3) + '</span>');
    }
    return parts.join('') + (links.length ? '<div>' + links.join('') + '</div>' : '');
  }

  function render() {
    const minimal = new Set(data.minimal_subset);
    rows = flatten(data.facts, 0, null, null, []);
    const frag = document.createDocumentFragment();
    rows.forEach((row, i) => {
      const r = row.rec;
      const tr = document.createElement('tr');
      if (row.depth === 0) tr.className = 'top';
      tr.dataset.i = i;
      const tog = row.kids.length
        ? '<button class="tog" type="button" aria-label="Toggle children">▸</button>'
        : '<span class="tog-pad"></span>';
      const v = r.v ? '<div class="var">' + esc(r.v) + '</div>' : '';
      const desc = inline(r.d) + (r.g ? '<span class="gen" title="Generated from the fact name">auto</span>' : '') +
        (r.note ? '<div class="note">Source comment: ' + esc(r.note) + '</div>' : '');
      const subsets = (r.s || []).map((s) =>
        '<span class="badge sub' + (minimal.has(s) ? ' min" title="Gathered even with gather_subset: min' : '') +
        '">' + esc(s) + '</span>').join('');
      const plats = (r.p || []).map((p) =>
        '<span class="badge plat' + (p === 'any' ? ' any' : '') + '">' + esc(p) + '</span>').join('');
      tr.innerHTML =
        '<td class="name" style="--depth:' + row.depth + '" title="' + esc(row.path) + '">' + tog +
        keyHtml(r.n) + v + '</td>' +
        '<td class="type"><code>' + typeHtml(r.t) + '</code></td>' +
        '<td class="desc">' + desc + '</td>' +
        '<td>' + subsets + '</td><td>' + plats + '</td>' +
        '<td class="src">' + sourceCell(r, data.version) + '</td>';
      row.el = tr;
      row.btn = tr.querySelector('.tog');
      frag.appendChild(tr);
    });
    ui.tbody.replaceChildren(frag);
    refresh();
  }

  function passesFilters(top) {
    const subset = ui.subset.value;
    const plat = ui.platform.value;
    if (subset === 'min:') {
      if (!top.s.some((s) => data.minimal_subset.includes(s))) return false;
    } else if (subset && !top.s.includes(subset)) return false;
    if (plat && !top.p.includes(plat) && !top.p.includes('any')) return false;
    return true;
  }

  function refresh() {
    const q = ui.search.value.trim().toLowerCase();
    // Rows are in depth-first order: children follow their parent.
    const hit = new Set();
    if (q) {
      for (let i = rows.length - 1; i >= 0; i--) {
        const row = rows[i];
        if (row.text.includes(q) || row.kids.some((k) => hit.has(k))) hit.add(row);
      }
    }
    const show = new Set();
    for (const row of rows) {
      if (!passesFilters(row.top)) continue;
      const p = row.parent;
      const vis = p
        ? show.has(p) && (expanded.has(p.path) || hit.has(row))
        : (!q || hit.has(row));
      if (vis) show.add(row);
    }
    let count = 0;
    for (const row of rows) {
      const vis = show.has(row);
      row.el.hidden = !vis;
      if (vis && row.depth === 0) count++;
      if (row.btn) {
        const isOpen = expanded.has(row.path) || row.kids.some((k) => hit.has(k));
        row.btn.textContent = isOpen ? '▾' : '▸';
        row.btn.setAttribute('aria-expanded', String(isOpen));
      }
    }
    ui.empty.hidden = show.size > 0;
    const s = data.stats;
    ui.meta.innerHTML = 'ansible-core <a href="https://github.com/ansible/ansible/tree/v' + esc(data.version) +
      '/lib/ansible/module_utils/facts" target="_blank" rel="noopener">' + esc(data.version) + '</a> · ' +
      s.top + ' top-level facts, ' + s.total + ' keys in total · ' + data.collectors.length + ' collectors' +
      (q || ui.subset.value || ui.platform.value ? ' · showing ' + count + ' top-level facts' : '');
    writeHash();
  }

  function fillSelect(sel, values, label) {
    const keep = sel.value;
    sel.replaceChildren(new Option(label, ''));
    for (const [v, text] of values) sel.add(new Option(text, v));
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : '';
  }

  function readHash() {
    const h = new URLSearchParams(location.hash.slice(1));
    return { v: h.get('v'), q: h.get('q') || '' };
  }

  function writeHash() {
    const h = new URLSearchParams();
    h.set('v', data.minor);
    if (ui.search.value) h.set('q', ui.search.value);
    const next = '#' + h.toString();
    if (location.hash !== next) history.replaceState(null, '', next);
  }

  async function show(minor) {
    try {
      data = await loadVersion(minor);
    } catch (e) {
      ui.meta.textContent = e.message;
      return;
    }
    ui.version.value = minor;
    const subsets = new Set();
    const plats = new Set();
    for (const f of data.facts) {
      f.s.forEach((s) => subsets.add(s));
      f.p.forEach((p) => p !== 'any' && plats.add(p));
    }
    fillSelect(ui.subset, [['min:', 'min (always gathered)'], ...[...subsets].sort().map((s) => [s, s])],
               'Any gather_subset');
    fillSelect(ui.platform, [...plats].sort().map((p) => [p, p]), 'Any platform');
    render();
  }

  function init() {
    for (const v of INDEX.versions) {
      ui.version.add(new Option(v.minor + ' (' + v.version + ')', v.minor));
    }
    const h = readHash();
    ui.search.value = h.q;
    const minor = INDEX.versions.some((v) => v.minor === h.v) ? h.v : INDEX.default;
    ui.version.addEventListener('change', () => show(ui.version.value));
    let t = null;
    ui.search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(refresh, 120); });
    ui.subset.addEventListener('change', refresh);
    ui.platform.addEventListener('change', refresh);
    $('#expand').addEventListener('click', () => {
      rows.forEach((r) => r.kids.length && expanded.add(r.path));
      refresh();
    });
    $('#collapse').addEventListener('click', () => { expanded = new Set(); refresh(); });
    ui.tbody.addEventListener('click', (ev) => {
      const btn = ev.target.closest('.tog');
      if (!btn) return;
      const row = rows[btn.closest('tr').dataset.i];
      if (expanded.has(row.path)) expanded.delete(row.path); else expanded.add(row.path);
      refresh();
    });
    window.addEventListener('hashchange', () => {
      const next = readHash();
      ui.search.value = next.q;
      if (next.v && next.v !== data.minor && INDEX.versions.some((v) => v.minor === next.v)) show(next.v);
      else refresh();
    });
    show(minor);
  }

  init();
})();
