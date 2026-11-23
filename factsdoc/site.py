"""Write the static documentation site."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

STATIC = Path(__file__).parent / 'static'


def _key(minor):
    return tuple(int(x) for x in minor.split('.'))


def write_site(out: Path, docs: list[dict], default_minor: str):
    """``index.html`` + ``assets/`` + one ``data/<X.Y>.js`` per version.

    Data files are scripts rather than JSON so the site also works when opened
    from disk (``file://`` blocks fetch()).
    """
    out.mkdir(parents=True, exist_ok=True)
    data_dir = out / 'data'
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir()
    (out / 'assets').mkdir(exist_ok=True)
    shutil.copy(STATIC / 'index.html', out / 'index.html')
    for name in ('app.js', 'style.css'):
        shutil.copy(STATIC / name, out / 'assets' / name)
    for doc in docs:
        payload = json.dumps(doc, ensure_ascii=False, separators=(',', ':'))
        (data_dir / f'{doc["minor"]}.js').write_text(
            f'window.FACTS_DATA=window.FACTS_DATA||{{}};window.FACTS_DATA[{json.dumps(doc["minor"])}]={payload};\n',
            encoding='utf-8')
    index = {
        'default': default_minor,
        'versions': [{'minor': d['minor'], 'version': d['version']}
                     for d in sorted(docs, key=lambda d: _key(d['minor']), reverse=True)],
    }
    (data_dir / 'versions.js').write_text('window.FACTS_INDEX=' + json.dumps(index) + ';\n', encoding='utf-8')
