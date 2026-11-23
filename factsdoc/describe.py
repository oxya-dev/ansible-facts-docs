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
    data = tomllib.loads(path.read_text(encoding='utf-8'))
    out = {}
    for key, val in data.get('facts', {}).items():
        out[norm_path(key)] = {'description': val} if isinstance(val, str) else dict(val)
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


def _site_comment(index, site):
    mod = index.by_rel.get(site.file)
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


def _note(index, sites):
    for s in sorted(sites):
        text = _site_comment(index, s)
        if text:
            return text
    return None


def _platforms(platforms):
    return ['any'] if 'Generic' in platforms else sorted(platforms)


def _record(node, segments, index, overrides, stats, top=False):
    segments = segments + [node.name]
    path = path_str(segments)
    ov = overrides.get(norm_path(path))
    types = norm_types(node.types)
    if ov and ov.get('type'):
        types = [ov['type']]
    rec = {'n': node.name, 'k': node.kind, 't': types}
    if ov and ov.get('description'):
        rec['d'] = ov['description']
        stats['curated'] += 1
    else:
        rec['d'] = humanize(node.name)
        rec['g'] = 1
    stats['total'] += 1
    note = _note(index, node.sites)
    if note:
        rec['note'] = note
    if node.src:
        rec['src'] = sorted(node.src)[:8]
    if node.sites:
        rec['at'] = [[s.file, s.line, s.func] for s in sorted(node.sites)[:12]]
    if top:
        rec['v'] = node.name if node.name.startswith(('facter_', 'ohai_')) else 'ansible_' + node.name
        rec['p'] = _platforms(node.platforms)
        rec['s'] = sorted(node.subsets)
    kids = [_record(c, segments, index, overrides, stats) for _, c in sorted(node.children.items())]
    if kids:
        rec['c'] = kids
    return rec


def build_version(result, version, overrides):
    """JSON-ready documentation for one ansible-core version."""
    stats = {'total': 0, 'curated': 0}
    root = result['root']
    facts = [_record(c, [], result['index'], overrides, stats, top=True) for _, c in sorted(root.children.items())]
    collectors = [
        {'name': c['name'], 'platform': c['platform'], 'class': c['class'], 'file': c['file'], 'line': c['line']}
        for c in result['collectors'] if c['name']
    ]
    errors = [f'{c["class"]}: {c["error"]}' for c in result['collectors'] if c['error']]
    return {
        'version': version,
        'minor': '.'.join(version.split('.')[:2]),
        'minimal_subset': result['minimal_subset'],
        'collectors': collectors,
        'stats': {'top': len(facts), 'total': stats['total'], 'curated': stats['curated']},
        'errors': errors,
        'facts': facts,
    }
