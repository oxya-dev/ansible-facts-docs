"""Build the Ansible facts documentation site: ``python -m factsdoc``."""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

from .analyzer import analyze
from .describe import build_version, load_overrides
from .fetch import ensure_source, latest_patches
from .site import write_site


def main(argv=None):
    ap = argparse.ArgumentParser(prog='python -m factsdoc', description=__doc__)
    ap.add_argument('--config', default='config.toml', help='configuration file (default: %(default)s)')
    ap.add_argument('--versions', help='comma-separated ansible-core minor versions, overrides the config')
    ap.add_argument('--default', help='version selected when the site opens, overrides the config')
    ap.add_argument('--out', help='output directory, overrides the config')
    ap.add_argument('--offline', action='store_true', help='use only sdists already in the cache')
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
    docs = []
    for minor in minors:
        version = patches[minor]
        doc = build_version(analyze(ensure_source(version, cache)), version, overrides)
        st = doc['stats']
        print(f'{version}: {st["top"]} top-level facts, {st["total"]} keys, {st["curated"]} curated descriptions')
        for err in doc['errors']:
            print(f'  warning: {err}', file=sys.stderr)
        docs.append(doc)
    write_site(out, docs, default)
    print(f'site written to {out}')


if __name__ == '__main__':
    main()
