"""Download and extract ansible-core source distributions from PyPI."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path

PYPI = 'https://pypi.org/pypi/ansible-core'
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
        tarball.parent.mkdir(parents=True, exist_ok=True)
        tmp = tarball.with_suffix('.part')
        with urllib.request.urlopen(sdist['url'], timeout=300) as r, open(tmp, 'wb') as f:
            shutil.copyfileobj(r, f)
        digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
        if digest != sdist['digests']['sha256']:
            tmp.unlink()
            raise SystemExit(f'sha256 mismatch for {sdist["url"]}')
        tmp.rename(tarball)
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
