"""Build the Ansible facts documentation site: ``python -m factsdoc``."""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

from . import windows
from .analyzer import analyze
from .describe import build_version, load_overrides
from .fetch import ensure_source, ensure_windows, latest_patches, windows_for, windows_releases
from .site import write_site


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m factsdoc', description=__doc__)
    ap.add_argument('--config', default='config.toml', help='configuration file (default: %(default)s)')
    ap.add_argument('--versions', help='comma-separated ansible-core minor versions, overrides the config')
    ap.add_argument('--default', help='version selected when the site opens, overrides the config')
    ap.add_argument('--out', help='output directory, overrides the config')
    ap.add_argument('--offline', action='store_true', help='use only sources already in the cache')
    ap.add_argument('--no-windows', action='store_true', help='skip the Windows facts (ansible.windows)')
    args = ap.parse_args(argv)

    cfg_path = Path(args.config).resolve()
    cfg = tomllib.loads(cfg_path.read_text(encoding='utf-8'))
    base = cfg_path.parent
    minors = args.versions.split(',') if args.versions else cfg['versions']
    default = args.default or cfg.get('default') or minors[-1]
    if default not in minors:
        ap.error(f'default version {default} is not in {", ".join(minors)}')
    out = Path(args.out) if args.out else base / cfg.get('output', 'site')
    cache = base / cfg.get('cache', '.cache')
    overrides = load_overrides(base / cfg.get('descriptions', 'descriptions.toml'))

    patches = latest_patches(minors, cache, offline=args.offline)
    win_releases = [] if args.no_windows else windows_releases(cache, offline=args.offline)
    docs = []
    for minor in minors:
        version = patches[minor]
        result = analyze(ensure_source(version, cache))
        win_meta = None
        win_version = windows_for(version, win_releases) if win_releases else None
        if win_version:
            win = windows.analyze(ensure_windows(win_version, cache))
            windows.merge(result, win)
            win_meta = {'version': win_version, 'minimal_subset': win['minimal_subset'], 'groups': win['groups']}
        doc = build_version(result, version, overrides, win_meta)
        st = doc['stats']
        print(f'{version}: {st["top"]} top-level facts ({st["windows"]} on Windows'
              f'{", ansible.windows " + win_version if win_version else ""}), {st["total"]} keys, '
              f'{st["curated"]} curated descriptions')
        for err in doc['errors']:
            print(f'  warning: {err}', file=sys.stderr)
        docs.append(doc)
    write_site(out, docs, default)
    print(f'site written to {out}')


if __name__ == '__main__':
    main()
