# Ansible facts reference

A static site that documents every fact the `setup` module can return, for each
ansible-core release, with a version dropdown. Every fact has its type, a short
description, the gather_subset and platforms that produce it, and the files or
commands its value comes from, with links to the source lines.

Published at <https://oxya-dev.github.io/ansible-facts-docs/>.

## Publishing

`.github/workflows/pages.yml` rebuilds the site and deploys it to GitHub Pages on every
push to `main`. To pick up new ansible-core patch releases without a code change, run
it manually: Actions → *Publish site* → *Run workflow*. To add a minor version, add it
to `config.toml`.

## Build

Requires Python ≥ 3.11 and no other dependencies.

```sh
python3 -m factsdoc                 # versions and default from config.toml
python3 -m factsdoc --versions 2.21,2.22 --default 2.22 --out /tmp/site
python3 -m factsdoc --offline       # only use sdists already in .cache/
```

The output in `site/` is static. You can open `site/index.html` directly or serve it from
any web server. The selected version and the search are kept in the URL hash
(`#v=2.21&q=lvm`).

## How it works

1. `factsdoc/fetch.py` resolves each `X.Y` in `config.toml` to its latest release on
   PyPI and downloads and extracts the sdist into `.cache/`, checking the sha256.
2. `factsdoc/analyzer.py` runs an abstract interpreter over
   `lib/ansible/module_utils/facts`. It does not import or execute anything from ansible.
   It starts from the collector list in `default_collectors.py` and calls each collector's
   `collect()` symbolically. Along the way it records:
   - every key that can reach the returned dict, including nested dicts, list elements
     (`[]`) and runtime keys (`<interface>`, `<device>`, …);
   - the value types inferred from the assigned expressions;
   - the assigning source lines;
   - the files, commands and Python APIs each value is read from.

   Branches are merged and literal loops are unrolled, so the result
   over-approximates. The union of all platforms and code paths is shown, for example
   `<interface>.ipv4` is a dict on Linux and a list on BSD.
3. `factsdoc/describe.py` attaches descriptions. They come from `descriptions.toml` when
   an entry exists; otherwise they are generated from the key name and marked `auto` on the
   site. Comments next to the assigning lines are shown as "source comment".
4. `factsdoc/site.py` writes `index.html`, `assets/` and one `data/<X.Y>.js` per version.

To add or fix a description, edit `descriptions.toml` (the path syntax is described at
the top of the file) and rebuild.

## Checking the analysis

```sh
python3 -m factsdoc.validate .cache/src/2.22.0/lib
```

This runs the real `setup` module from the extracted source on the current machine. It
then reports every returned key or value type that the generated documentation does not
cover.
