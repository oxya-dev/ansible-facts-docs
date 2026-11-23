"""Check the static analysis against a real ``setup`` run on this machine.

Runs ``ansible.modules.setup`` from the extracted source tree, then walks the
returned facts and reports every key or type the generated documentation does
not cover. Usage::

    python -m factsdoc.validate <extracted>/lib
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .analyzer import analyze

JSON_TYPES = {str: 'str', bool: 'bool', int: 'int', float: 'float', type(None): 'null', list: 'list', dict: 'dict'}


def run_setup(lib: Path) -> dict:
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump({'ANSIBLE_MODULE_ARGS': {'gather_subset': ['all']}}, f)
    try:
        out = subprocess.run([sys.executable, '-m', 'ansible.modules.setup', f.name], cwd=lib,
                             capture_output=True, text=True, timeout=300, check=True,
                             env={**os.environ, 'PYTHONPATH': str(lib)})
    finally:
        os.unlink(f.name)
    return json.loads(out.stdout)['ansible_facts']


def base_types(node):
    return {t.split('[', 1)[0] for t in node.types}


def check(node, value, path, problems, stats):
    stats['checked'] += 1
    jt = JSON_TYPES.get(type(value), 'any')
    bt = base_types(node)
    if path and 'any' not in bt and jt not in bt and not (jt == 'int' and 'float' in bt):
        problems.append(f'type  {path}: runtime {jt}, documented {" | ".join(sorted(node.types))}')
    if isinstance(value, dict):
        dyn = next((c for c in node.children.values() if c.kind == 'dyn'), None)
        for k, v in value.items():
            child = node.children.get(k)
            if child is None or child.kind == 'dyn':
                child = dyn
            if child is None:
                if node.children or 'any' not in bt:
                    problems.append(f'key   {path}.{k}' if path else f'key   {k}')
                continue
            check(child, v, f'{path}.{child.name if child.kind == "dyn" else k}' if path else
                  (child.name if child.kind == 'dyn' else k), problems, stats)
    elif isinstance(value, list):
        item = node.children.get('[]')
        for v in value:
            if isinstance(v, (dict, list)) and item is not None:
                check(item, v, path + '[]', problems, stats)


def main(argv=None):
    lib = Path((argv or sys.argv[1:])[0]).resolve()
    facts = run_setup(lib)
    root = analyze(lib)['root']
    problems, stats = [], {'checked': 0}
    top = {}
    for k, v in facts.items():
        top[k[len('ansible_'):] if k.startswith('ansible_') else k] = v
    check(root, top, '', problems, stats)
    for p in sorted(set(problems)):
        print(p)
    print(f'{stats["checked"]} runtime values checked, {len(set(problems))} not covered by the documentation')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
