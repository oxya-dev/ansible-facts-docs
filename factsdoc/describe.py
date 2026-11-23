"""Turn the analyzed fact tree into documentation records.

Descriptions come, in order of preference, from the curated ``descriptions.toml``
or from the fact name itself. Comments found next to the assigning source lines
are kept separately as notes; they describe code, not always the fact.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

TYPE_ORDER = ['str', 'int', 'float', 'bool', 'list', 'dict', 'null', 'any']

WORDS = {
    'ip': 'IP', 'ipv4': 'IPv4', 'ipv6': 'IPv6', 'mtu': 'MTU', 'mac': 'MAC', 'macaddress': 'MAC address',
    'uuid': 'UUID', 'uuids': 'UUIDs', 'dmi': 'DMI', 'bios': 'BIOS', 'cpu': 'CPU', 'os': 'OS',
    'fqdn': 'FQDN', 'dns': 'DNS', 'id': 'ID', 'ids': 'IDs', 'lvm': 'LVM', 'lv': 'LV', 'lvs': 'LVs',
    'vg': 'VG', 'vgs': 'VGs', 'pv': 'PV', 'pvs': 'PVs', 'ssh': 'SSH', 'rsa': 'RSA', 'dsa': 'DSA',
    'ecdsa': 'ECDSA', 'ed25519': 'Ed25519', 'fips': 'FIPS', 'selinux': 'SELinux', 'apparmor': 'AppArmor',
    'lsb': 'LSB', 'nvme': 'NVMe', 'iscsi': 'iSCSI', 'iqn': 'IQN', 'wwn': 'WWN', 'pci': 'PCI',
    'pciid': 'PCI ID', 'sas': 'SAS', 'vcpus': 'vCPUs', 'tz': 'time zone', 'dst': 'DST',
    'iso8601': 'ISO 8601', 'utc': 'UTC', 'lacp': 'LACP', 'stp': 'STP', 'cpe': 'CPE', 'uid': 'UID',
    'gid': 'GID', 'gecos': 'GECOS', 'nqn': 'NQN', 'hostnqn': 'host NQN', 'lpar': 'LPAR', 'phc': 'PHC',
    'hw': 'hardware', 'pp': 'PP', 'pps': 'PPs', 'lladdr': 'link-layer address', 'mgr': 'manager',
    'pkg': 'package', 'cmdline': 'command line', 'env': 'environment', 'dir': 'directory',
    'sslcontext': 'SSLContext', 'nproc': 'nproc',
}
UNITS = {'mb': 'MB', 'gb': 'GB', 'kb': 'KB', 'g': 'GB'}
NOISE_RE = re.compile(r'^(todo|fixme|xxx|note|noqa|type:|pylint|pragma|nosec|https?:|see\b|-\*-)', re.I)
PLACEHOLDER_RE = re.compile(r'<[^>]+>')


def path_str(segments):
    out = ''
    for s in segments:
        out += s if s == '[]' or not out else '.' + s
    return out


def norm_path(p):
    return PLACEHOLDER_RE.sub('<*>', p)


def load_overrides(path: Path):
    """``{'facts': {path: entry}, 'windows': {path: entry}}`` from descriptions.toml."""
    data = tomllib.loads(path.read_text(encoding='utf-8'))
    out = {}
    for table in ('facts', 'windows'):
        out[table] = {norm_path(k): ({'description': v} if isinstance(v, str) else dict(v))
                      for k, v in data.get(table, {}).items()}
    return out


def _split_top(s):
    parts, depth, cur = [], 0, ''
    i = 0
    while i < len(s):
        if s.startswith(' | ', i) and depth == 0:
            parts.append(cur)
            cur = ''
            i += 3
            continue
        depth += s[i] == '['
        depth -= s[i] == ']'
        cur += s[i]
        i += 1
    if cur:
        parts.append(cur)
    return parts


def _type_key(t):
    base = t.split('[', 1)[0]
    return (TYPE_ORDER.index(base) if base in TYPE_ORDER else len(TYPE_ORDER), t)


def norm_types(types):
    """Merge ``list`` variants into one ``list[...]`` and order types predictably."""
    inner, has_list, out = set(), False, set()
    for t in types:
        if t.startswith('list['):
            inner |= set(_split_top(t[5:-1]))
        elif t == 'list':
            has_list = True
        else:
            out.add(t)
    inner.discard('any')
    if inner:
        out.add('list[' + ' | '.join(sorted(inner, key=_type_key)) + ']')
    elif has_list:
        out.add('list')
    if out - {'any', 'null'}:
        out.discard('any')
    return sorted(out, key=_type_key) or ['any']


def humanize(name):
    if name == '[]':
        return 'List element.'
    if name.startswith('<') and name.endswith('>'):
        return 'One entry per ' + name[1:-1].replace('_', ' ') + '.'
    toks = [t for t in name.split('_') if t]
    if not toks:
        return name
    unit = None
    if toks[-1] in UNITS and len(toks) > 1:
        unit = UNITS[toks.pop()]
    lead = ''
    if toks[0] == 'is' and len(toks) > 1:
        lead, toks = 'Whether ', toks[1:]
    elif toks[0] == 'has' and len(toks) > 1:
        lead, toks = 'Whether it has ', toks[1:]
    elif toks[0] == 'num' and len(toks) > 1:
        lead, toks = 'Number of ', toks[1:]
    words = ' '.join(WORDS.get(t.lower(), t) for t in toks)
    text = lead + words
    text = text[0].upper() + text[1:]
    if unit:
        text += f' ({unit})'
    return text + '.'


def _site_comment(sources, site):
    mod = sources.get(site.file)
    if mod is None or not site.line:
        return None
    com = mod.comments()
    cands = []
    c = com.get(site.line)
    if c and not c[1]:
        cands.append(c[0])
    block, ln = [], site.line - 1
    while ln > 0 and ln in com and com[ln][1]:
        block.insert(0, com[ln][0])
        ln -= 1
    if block and len(block) <= 3:
        cands.append(' '.join(block))
    for text in cands:
        text = ' '.join(text.split())
        if 15 <= len(text) <= 220 and not NOISE_RE.match(text) and ' = ' not in text:
            return text
    return None


def _note(sources, sites):
    for s in sorted(sites):
        text = _site_comment(sources, s)
        if text:
            return text
    return None


WINDOWS = 'Windows'


def _platforms(platforms):
    """Platform labels: ``posix`` for collectors that run on every POSIX system, then specific ones."""
    posix = platforms - {WINDOWS}
    out = ['posix'] if 'Generic' in posix else sorted(posix)
    if WINDOWS in platforms:
        out.append(WINDOWS)
    return out


def _record(node, segments, ctx, parent_p=None):
    segments = segments + [node.name]
    path = norm_path(path_str(segments))
    posix = bool(node.platforms - {WINDOWS})
    windows = WINDOWS in node.platforms
    ov = ctx['facts'].get(path) if posix else None
    wov = ctx['windows'].get(path) if windows else None
    if not posix and wov is None:
        wov = ctx['facts'].get(path)  # same meaning on Windows
    main = ov if posix else wov
    types = norm_types(node.types)
    # A curated type replaces the inferred one for its platform family; keep the
    # inferred types when the other family present has no curated type.
    typed = {o['type'] for o in (ov, wov) if o and o.get('type')}
    if typed:
        uncovered = (posix and not (ov and ov.get('type'))) or (windows and not (wov and wov.get('type')))
        types = norm_types(typed | (set(types) - {'any'} if uncovered else set()))
    rec = {'n': node.name, 'k': node.kind, 't': types}
    if main and main.get('description'):
        rec['d'] = main['description']
        ctx['stats']['curated'] += 1
    else:
        rec['d'] = humanize(node.name)
        rec['g'] = 1
    if posix and windows and wov and wov.get('description'):
        rec['dw'] = wov['description']
    ctx['stats']['total'] += 1
    note = _note(ctx['sources'], node.sites)
    if note:
        rec['note'] = note
    if node.src:
        rec['src'] = sorted(node.src)[:8]
    if node.sites:
        rec['at'] = [[s.file, s.line, s.func] for s in sorted(node.sites)[:12]]
    plats = _platforms(node.platforms)
    if parent_p is None:
        rec['v'] = node.name if node.name.startswith(('facter_', 'ohai_')) else 'ansible_' + node.name
        rec['p'] = plats
        rec['s'] = sorted(node.subsets)
    elif plats != parent_p:
        rec['p'] = plats
    kids = [_record(c, segments, ctx, plats) for _, c in sorted(node.children.items())]
    if kids:
        rec['c'] = kids
    return rec


def build_version(result, version, overrides, windows=None):
    """JSON-ready documentation for one ansible-core version (plus the Windows facts, if given)."""
    ctx = {**overrides, 'sources': result['sources'], 'stats': {'total': 0, 'curated': 0}}
    root = result['root']
    facts = [_record(c, [], ctx) for _, c in sorted(root.children.items())]
    collectors = [
        {'name': c['name'], 'platform': c['platform'], 'class': c['class'], 'file': c['file'], 'line': c['line']}
        for c in result['collectors'] if c['name']
    ]
    errors = [f'{c["class"]}: {c["error"]}' for c in result['collectors'] if c['error']]
    st = ctx['stats']
    doc = {
        'version': version,
        'minor': '.'.join(version.split('.')[:2]),
        'minimal_subset': result['minimal_subset'],
        'collectors': collectors,
        'stats': {'top': len(facts), 'total': st['total'], 'curated': st['curated'],
                  'windows': sum(1 for f in facts if WINDOWS in f['p'])},
        'errors': errors,
        'facts': facts,
    }
    if windows:
        doc['windows'] = windows
    return doc
