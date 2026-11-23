"""Download and extract ansible-core (PyPI) and ansible.windows (Galaxy) sources."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import urllib.request
import urllib.parse
from pathlib import Path

PYPI = 'https://pypi.org/pypi/ansible-core'
GALAXY = 'https://galaxy.ansible.com'
WINDOWS_VERSIONS = GALAXY + '/api/v3/plugin/ansible/content/published/collections/index/ansible/windows/versions/'
_FINAL = re.compile(r'(\d+)\.(\d+)\.(\d+)')


def _get_json(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def _key(v):
    return tuple(int(x) for x in v.split('.'))


def latest_patches(minors, cache: Path, offline=False):
    """Map each ``X.Y`` to its latest final ``X.Y.Z`` release (PyPI, or the local cache offline)."""
    found = {}
    if not offline:
        for v, files in _get_json(PYPI + '/json')['releases'].items():
            m = _FINAL.fullmatch(v)
            if m and files and not all(f.get('yanked') for f in files):
                minor = f'{m[1]}.{m[2]}'
                if minor in minors and (minor not in found or _key(v) > _key(found[minor])):
                    found[minor] = v
    else:
        for p in (cache / 'sdist').glob('ansible_core-*.tar.gz'):
            v = p.name[len('ansible_core-'):-len('.tar.gz')]
            m = _FINAL.fullmatch(v)
            minor = f'{m[1]}.{m[2]}' if m else None
            if minor in minors and (minor not in found or _key(v) > _key(found[minor])):
                found[minor] = v
    missing = [m for m in minors if m not in found]
    if missing:
        raise SystemExit(f'no ansible-core release found for: {", ".join(missing)}')
    return found


def ensure_source(version: str, cache: Path) -> Path:
    """Return ``<cache>/src/<version>/lib``, downloading and extracting the sdist if needed."""
    lib = cache / 'src' / version / 'lib'
    if (lib / 'ansible' / 'module_utils' / 'facts').is_dir():
        return lib
    tarball = cache / 'sdist' / f'ansible_core-{version}.tar.gz'
    if not tarball.exists():
        meta = _get_json(f'{PYPI}/{version}/json')
        sdist = next(u for u in meta['urls'] if u['packagetype'] == 'sdist')
        _download(sdist['url'], sdist['digests']['sha256'], tarball)
    dest = cache / 'src' / version
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with tarfile.open(tarball) as tf:
        top = tf.getmembers()[0].name.split('/')[0]
        prefix = f'{top}/lib/'
        members = []
        for m in tf.getmembers():
            if m.name.startswith(prefix):
                m.name = 'lib/' + m.name[len(prefix):]
                members.append(m)
        tf.extractall(dest, members=members, filter='data')
    return lib


def _download(url, sha256, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + '.part')
    with urllib.request.urlopen(url, timeout=300) as r, open(tmp, 'wb') as f:
        shutil.copyfileobj(r, f)
    if hashlib.sha256(tmp.read_bytes()).hexdigest() != sha256:
        tmp.unlink()
        raise SystemExit(f'sha256 mismatch for {url}')
    tmp.rename(dest)


def windows_releases(cache: Path, offline=False):
    """``[{'version', 'requires_ansible'}]`` of the ansible.windows collection on Galaxy."""
    index = cache / 'windows' / 'versions.json'
    if offline:
        if not index.exists():
            raise SystemExit('no cached ansible.windows release list; run once without --offline')
        return json.loads(index.read_text())
    out, url = [], WINDOWS_VERSIONS + '?limit=100'
    while url:
        page = _get_json(url)
        out += [{'version': v['version'], 'requires_ansible': v.get('requires_ansible') or ''}
                for v in page['data'] if _FINAL.fullmatch(v['version'])]
        nxt = (page.get('links') or {}).get('next')
        url = urllib.parse.urljoin(GALAXY, nxt) if nxt else None
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text(json.dumps(out, indent=1))
    return out


def _satisfies(version, spec):
    """``requires_ansible`` check, e.g. ``'2.18.20'`` against ``'>=2.16.0,<2.20'``."""
    v = _key(version)
    for clause in filter(None, (c.strip() for c in spec.split(','))):
        m = re.fullmatch(r'(>=|<=|==|!=|>|<|~=)?\s*([\d.]+)(?:\.\*)?', clause)
        if not m:
            continue
        op, bound = m.group(1) or '==', tuple(int(x) for x in m.group(2).split('.'))
        cur = v[:len(bound)] if op in ('==', '!=') else v
        ok = {'>=': cur >= bound, '<=': cur <= bound, '>': cur > bound, '<': cur < bound,
              '==': cur == bound, '!=': cur != bound,
              '~=': cur >= bound and cur[:len(bound) - 1] == bound[:-1]}[op]
        if not ok:
            return False
    return True


def windows_for(core_version, releases):
    """Latest ansible.windows release whose ``requires_ansible`` accepts this ansible-core."""
    ok = [r['version'] for r in releases if _satisfies(core_version, r['requires_ansible'])]
    return max(ok, key=_key) if ok else None


def ensure_windows(version: str, cache: Path) -> Path:
    """Return ``<cache>/windows/<version>/setup.ps1``, downloading the collection if needed."""
    ps1 = cache / 'windows' / version / 'setup.ps1'
    if ps1.exists():
        return ps1
    tarball = cache / 'windows' / f'ansible-windows-{version}.tar.gz'
    if not tarball.exists():
        meta = _get_json(f'{WINDOWS_VERSIONS}{version}/')
        _download(meta['download_url'], meta['artifact']['sha256'], tarball)
    with tarfile.open(tarball) as tf:
        name = next(n for n in tf.getnames() if n.endswith('plugins/modules/setup.ps1'))
        ps1.parent.mkdir(parents=True, exist_ok=True)
        ps1.write_bytes(tf.extractfile(name).read())
    return ps1
