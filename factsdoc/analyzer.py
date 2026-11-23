"""Static analysis of the ansible-core fact collectors.

The collectors under ``lib/ansible/module_utils/facts`` build plain dicts. This
module runs a small abstract interpreter over their source -- nothing is
imported or executed -- and records, for every key that can end up in the
facts returned by ``setup``: value types, nested structure, the lines that
assign it, and the files/commands its value is read from.

The interpretation is deliberately approximate (flow-insensitive merging of
branches, single pass over loops unless the loop iterates over a literal), which
is the right trade-off for documentation: it over-approximates the set of keys
and types instead of missing some.
"""
from __future__ import annotations

import ast
import builtins
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path

WILD = '\x00'  # unknown part of a string template
MAX_ENUM = 64  # max distinct strings tracked for one value
MAX_SRC = 12  # max provenance entries kept per value
MAX_DEPTH = 40  # max call depth
MAX_STEPS = 4_000_000  # per collector
MAX_UNROLL_NEST = 2  # nested literal-loop unrolling

ANALYZED_PREFIXES = ('ansible.module_utils.facts', 'ansible.module_utils.common.sys_info')
BUILTIN_NAMES = frozenset(dir(builtins))
MUTATING_METHODS = frozenset({'append', 'add', 'extend', 'insert', 'update', 'setdefault'})
STR_TO_STR = frozenset({
    'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'title', 'capitalize', 'casefold', 'swapcase',
    'replace', 'removeprefix', 'removesuffix', 'zfill', 'center', 'ljust', 'rjust', 'expandtabs',
    'encode', 'decode', 'translate',
})
STR_TO_BOOL = frozenset({
    'startswith', 'endswith', 'isdigit', 'isalpha', 'isalnum', 'isspace', 'islower', 'isupper',
    'isdecimal', 'isnumeric', 'isidentifier', 'istitle', 'isprintable', 'isascii',
})
PCT_RE = re.compile(r'%(?:\([^)]*\))?[-#0 +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlL]?[diouxXeEfFgGcrsa%]')
BRACE_RE = re.compile(r'\{\{|\}\}|\{([^{}]*)\}')


class BudgetExceeded(Exception):
    """Analysis of one collector took too many steps."""


@dataclass(frozen=True, order=True)
class Site:
    file: str
    line: int
    func: str


# --------------------------------------------------------------------------- values


class V:
    """Abstract value: a union of types plus, for containers, their shape.

    Containers are shared by reference exactly like Python objects, so a dict
    mutated after being stored in another dict is seen through both.
    """

    __slots__ = ('types', 'keys', 'dyn', 'dyn_name', 'items', 'strs', 'elts', 'objs', 'src',
                 'ksites', 'dyn_sites', 'item_sites')

    def __init__(self, types=(), strs=None, src=(), objs=()):
        self.types = set(types)
        self.keys = {}  # constant key -> V
        self.dyn = None  # value of keys only known at runtime
        self.dyn_name = None
        self.items = None  # list element
        self.strs = strs  # frozenset of string templates (WILD = unknown part)
        self.elts = None  # positional elements of a literal tuple/list
        self.objs = list(objs)  # non-data payloads: functions, classes, instances...
        self.src = set()
        add_src(self, src)
        self.ksites = {}
        self.dyn_sites = set()
        self.item_sites = set()

    def __repr__(self):  # debugging aid
        bits = [','.join(sorted(self.types)) or '?']
        if self.strs:
            bits.append(repr(sorted(s.replace(WILD, '*') for s in self.strs)[:4]))
        if self.keys:
            bits.append('keys=' + ','.join(sorted(self.keys)[:8]))
        if self.dyn is not None:
            bits.append('dyn')
        if self.objs:
            bits.append('objs=' + ','.join(o[0] for o in self.objs))
        return '<V ' + ' '.join(bits) + '>'


def add_src(v, srcs):
    for s in sorted(srcs):
        if len(v.src) >= MAX_SRC:
            return
        v.src.add(s)


def src_of(*vs):
    out = set()
    for x in vs:
        if x is not None and x is not _REST:
            out |= x.src
    return out


def is_dictish(v):
    return 'dict' in v.types or bool(v.keys) or v.dyn is not None


def is_listish(v):
    return 'list' in v.types or v.items is not None or v.elts is not None


def is_container(v):
    return is_dictish(v) or is_listish(v)


def exact(v):
    """The set of known string values, or None if any part is unknown."""
    s = v.strs
    if s and len(s) <= MAX_ENUM and all(WILD not in x for x in s):
        return s
    return None


def templates(v):
    return v.strs if v.strs else frozenset((WILD,))


def _norm(t):
    return re.sub(WILD + '+', WILD, t)


def _cap(strs):
    strs = frozenset(_norm(s) for s in strs)
    return strs if len(strs) <= MAX_ENUM else frozenset((WILD,))


def concat(a, b):
    return _cap(x + y for x in a for y in b)


def render_template(t):
    return t.replace(WILD, '…')


def cstr(s):
    return V(('str',), frozenset((s,)))


def str_v(tmpls=None, src=(), extra=()):
    return V(('str',) + tuple(extra), frozenset(tmpls) if tmpls else frozenset((WILD,)), src)


def copy_prim(v):
    n = V(v.types, v.strs, v.src, v.objs)
    return n


def seq(elts=None, items=None, src=()):
    v = V(('list',), src=src)
    if elts is not None:
        v.elts = list(elts)
        if v.elts:
            it = V()
            for e in v.elts:
                merge_into(it, e)
            v.items = it
    if items is not None:
        if v.items is None:
            v.items = items
        else:
            merge_into(v.items, items)
    return v


def merge_into(dst, s, seen=None):
    """Union ``s`` into ``dst`` in place; children missing from ``dst`` are shared."""
    if s is None or s is _REST or dst is s:
        return dst
    if seen is None:
        seen = set()
    k = (id(dst), id(s))
    if k in seen:
        return dst
    seen.add(k)
    had_str = 'str' in dst.types or dst.strs is not None
    had_list = is_listish(dst)
    dst.types |= s.types
    if s.strs is not None or 'str' in s.types:
        ss = s.strs if s.strs is not None else frozenset((WILD,))
        if dst.strs is None and not had_str:
            dst.strs = ss
        else:
            dst.strs = _cap((dst.strs or frozenset((WILD,))) | ss)
    for key, sv in s.keys.items():
        if key in dst.keys:
            merge_into(dst.keys[key], sv, seen)
        else:
            dst.keys[key] = sv
        if key in s.ksites:
            dst.ksites.setdefault(key, set()).update(s.ksites[key])
    if s.dyn is not None:
        if dst.dyn is None:
            dst.dyn = s.dyn
            dst.dyn_name = s.dyn_name
        else:
            merge_into(dst.dyn, s.dyn, seen)
        dst.dyn_sites |= s.dyn_sites
    if s.items is not None:
        if dst.items is None:
            dst.items = s.items
        else:
            merge_into(dst.items, s.items, seen)
        dst.item_sites |= s.item_sites
    if s.elts is not None:
        if dst.elts is None:
            if not had_list:
                dst.elts = list(s.elts)
        elif len(dst.elts) == len(s.elts):
            dst.elts = [union(a, b) for a, b in zip(dst.elts, s.elts)]
        else:
            dst.elts = None
    elif dst.elts is not None and is_listish(s):
        dst.elts = None
    for o in s.objs:
        if not any(o is p or o == p for p in dst.objs):
            dst.objs.append(o)
    add_src(dst, s.src)
    return dst


def union(*vs):
    vs = [v for v in vs if v is not None and v is not _REST]
    if not vs:
        return V(('any',))
    first = vs[0]
    if all(v is first for v in vs):
        return first
    out = V()
    for v in vs:
        merge_into(out, v)
    return out


class _Rest:
    """Marks positional arguments of unknown count (``f(*args)``)."""


_REST = _Rest()


# --------------------------------------------------------------------------- code model


class SourceModule:
    def __init__(self, name, path, rel, is_pkg):
        self.name = name
        self.path = path
        self.rel = rel
        self.is_pkg = is_pkg
        self._tree = None
        self._comments = None
        self._lines = None

    @property
    def tree(self):
        if self._tree is None:
            self._tree = ast.parse(self.path.read_text(encoding='utf-8'), filename=str(self.path))
        return self._tree

    @property
    def package(self):
        return self.name if self.is_pkg else self.name.rpartition('.')[0]

    def lines(self):
        if self._lines is None:
            self._lines = self.path.read_text(encoding='utf-8').splitlines()
        return self._lines

    def comments(self):
        """line number -> (comment text, comment is the whole line)."""
        if self._comments is None:
            out = {}
            text = self.path.read_text(encoding='utf-8')
            try:
                for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                    if tok.type == tokenize.COMMENT:
                        full = tok.line.strip().startswith('#')
                        out[tok.start[0]] = (tok.string.lstrip('#').strip(), full)
            except (tokenize.TokenError, SyntaxError):
                pass
            self._comments = out
        return self._comments


class Index:
    """All python modules below ``<lib>/ansible``, addressable by dotted name."""

    def __init__(self, lib: Path):
        self.lib = lib
        self.modules = {}
        self.by_rel = {}
        for p in sorted((lib / 'ansible').rglob('*.py')):
            rel = p.relative_to(lib)
            parts = list(rel.with_suffix('').parts)
            is_pkg = parts[-1] == '__init__'
            if is_pkg:
                parts = parts[:-1]
            mod = SourceModule('.'.join(parts), p, rel.as_posix(), is_pkg)
            self.modules[mod.name] = mod
            self.by_rel[mod.rel] = mod


class FuncInfo:
    __slots__ = ('node', 'module', 'cls', 'qualname', 'kind', 'is_gen')

    def __init__(self, node, module, cls, qualname, kind):
        self.node = node
        self.module = module
        self.cls = cls
        self.qualname = qualname
        self.kind = kind  # func | static | classmethod | property
        self.is_gen = _is_generator(node)

    @property
    def fullname(self):
        return self.module.name + '.' + self.qualname


class ClassInfo:
    __slots__ = ('node', 'module', 'name')

    def __init__(self, node, module):
        self.node = node
        self.module = module
        self.name = node.name


class Inst:
    __slots__ = ('cls', 'attrs')

    def __init__(self, cls):
        self.cls = cls
        self.attrs = {}


def _is_generator(node):
    if isinstance(node, ast.Lambda):
        return False
    stack = list(node.body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))
    return False


class Frame:
    __slots__ = ('module', 'env', 'parent', 'func', 'cls', 'self_v', 'in_class', 'returns', 'yields',
                 'globals', 'nonlocals')

    def __init__(self, module, env, parent=None, func=None, cls=None, self_v=None, in_class=False):
        self.module = module
        self.env = env
        self.parent = parent
        self.func = func
        self.cls = cls
        self.self_v = self_v
        self.in_class = in_class
        self.returns = []
        self.yields = []
        self.globals = set()
        self.nonlocals = set()

    @property
    def qual(self):
        if self.func is not None:
            return self.func.qualname
        if self.in_class and self.cls is not None:
            return self.cls.name
        return '<module>'


# --------------------------------------------------------------------------- externals


def _ns(mapping, default='int'):
    def typer(name):
        return V((mapping.get(name, default),), frozenset((WILD,)) if mapping.get(name) == 'str' else None)
    return typer


_PWD = _ns({'pw_name': 'str', 'pw_passwd': 'str', 'pw_gecos': 'str', 'pw_dir': 'str', 'pw_shell': 'str'})
_GRP = _ns({'gr_name': 'str', 'gr_passwd': 'str', 'gr_mem': 'list'})
_INTS = _ns({})
_SYS_IMPL = _ns({'name': 'str', 'cache_tag': 'str'}, default='any')


def _file_src(v):
    return {'file:' + render_template(t) for t in templates(v) if t != WILD}


def _py_src(q):
    return {'python:' + q + '()'}


def _glob_tmpl(v):
    return frozenset(_norm(re.sub(r'\*|\?|\[[^]]*\]', WILD, t)) for t in templates(v))


def _path_join(args):
    out = frozenset(('',))
    for i, a in enumerate(args):
        parts = templates(a)
        if i == 0:
            out = parts
        else:
            out = _cap(x if y.startswith('/') else (x.rstrip('/') + '/' + y) for x in out for y in parts)
    return out


def _basename(t):
    return t.rstrip('/').rpartition('/')[2] or WILD if '/' in t else t


def _regex_groups(pattern_v, flags_node=None):
    pats = exact(pattern_v)
    if not pats or len(pats) != 1:
        return None
    pat = next(iter(pats))
    flags = 0
    if flags_node is not None and re.search(r'VERBOSE|\bX\b', ast.unparse(flags_node)):
        flags = re.VERBOSE
    try:
        return frozenset(re.compile(pat, flags).groupindex)
    except re.error:
        return None


def _flags_arg(node, pos):
    if node is None:
        return None
    if len(node.args) > pos:
        return node.args[pos]
    for kw in node.keywords:
        if kw.arg == 'flags':
            return kw.value
    return None


def _match_obj(groups, src):
    return V(('any',), src=src, objs=[('match', groups)])


def ext_value(q):
    last = q.rpartition('.')[2]
    if q == 'os.environ':
        v = V(('dict',), src={'env:environment'})
        v.dyn = str_v(src={'env:environment'})
        v.dyn_name = '<variable>'
        return v
    if q == 'sys.version_info':
        return seq([V(('int',)), V(('int',)), V(('int',)), str_v(), V(('int',))], src={'python:sys.version_info'})
    if q in ('sys.executable', 'sys.platform', 'sys.version', 'os.sep', 'os.linesep', 'os.name'):
        return str_v(src={'python:' + q})
    if q == 'sys.implementation':
        return V(('any',), objs=[('ns', _SYS_IMPL)], src={'python:sys.implementation'})
    if q == 'socket.has_ipv6':
        return V(('bool',))
    if q == 'time.tzname':
        return seq([str_v(src={'python:time.tzname'}), str_v(src={'python:time.tzname'})])
    if q in ('time.timezone', 'time.altzone', 'time.daylight'):
        return V(('int',))
    if last.isupper():
        return V(('int',))
    return V(('any',), objs=[('ext', q)])


def ext_call(interp, q, a, kw, node, frame):
    s = src_of(*a, *kw.values())
    first = a[0] if a else V(('any',))
    if q in ('os.path.exists', 'os.path.isdir', 'os.path.isfile', 'os.path.islink', 'os.path.ismount',
             'os.path.lexists', 'os.path.isabs', 'os.path.samefile', 'os.access', 'fnmatch.fnmatch',
             'os.path.isdir'):
        return V(('bool',))
    if q == 'os.path.join':
        return str_v(_path_join(a), s)
    if q == 'os.path.basename':
        return str_v(_cap(_basename(t) for t in templates(first)), s)
    if q == 'os.path.dirname':
        return str_v(_cap(t.rpartition('/')[0] or WILD for t in templates(first)), s)
    if q in ('os.path.realpath', 'os.path.abspath', 'os.path.normpath', 'os.path.expanduser',
             'os.path.expandvars'):
        return str_v(templates(first), s)
    if q == 'os.readlink':
        return str_v(src=_file_src(first) | s)
    if q in ('os.listdir', 'os.scandir'):
        return seq(items=str_v(src=_file_src(first) | s), src=s)
    if q in ('glob.glob', 'glob.iglob'):
        return seq(items=str_v(_glob_tmpl(first), _file_src(first) | s))
    if q in ('os.getuid', 'os.geteuid', 'os.getgid', 'os.getegid', 'os.getpid', 'os.getppid',
             'os.cpu_count', 'os.sysconf', 'os.getpgrp', 'os.path.getsize', 'os.major', 'os.minor'):
        return V(('int',), src=_py_src(q) if q.startswith('os.get') else ())
    if q == 'os.getgroups':
        return seq(items=V(('int',)))
    if q == 'os.getloadavg':
        return seq([V(('float',)), V(('float',)), V(('float',))], src=_py_src(q))
    if q in ('os.stat', 'os.lstat', 'os.statvfs', 'os.fstat', 'os.fstatvfs', 'time.localtime',
             'time.gmtime'):
        return V(('any',), objs=[('ns', _INTS)], src=_file_src(first) if q.startswith('os.') else ())
    if q == 'os.uname':
        return seq(items=str_v(src=_py_src(q)))
    if q in ('os.getcwd',):
        return str_v()
    if q == 'os.getenv':
        return str_v(src={'env:' + t for t in (exact(first) or ())}, extra=('null',))
    if q.startswith('platform.'):
        fn = q.partition('.')[2]
        ps = _py_src(q)
        if fn == 'architecture':
            return seq([str_v(src=ps), str_v(src=ps)])
        if fn == 'libc_ver':
            return seq([str_v(src=ps), str_v(src=ps)])
        if fn == 'mac_ver':
            return seq([str_v(src=ps), seq(items=str_v()), str_v(src=ps)])
        if fn in ('uname', 'dist', 'linux_distribution', 'python_version_tuple'):
            return seq(items=str_v(src=ps))
        return str_v(src=ps)
    if q in ('socket.getfqdn', 'socket.gethostname', 'socket.gethostbyname'):
        return str_v(src=_py_src(q))
    if q in ('socket.inet_ntoa', 'socket.inet_ntop', 'socket.inet_aton', 'socket.inet_pton', 'struct.pack',
             'binascii.hexlify', 'json.dumps', 'base64.b64encode', 'hashlib.sha256'):
        return str_v(src=s)
    if q == 'struct.unpack':
        return seq(items=V(('int',)), src=s)
    if q in ('time.time', 'time.monotonic', 'time.perf_counter'):
        return V(('float',), src=_py_src(q))
    if q == 'time.strftime':
        return str_v(src=_py_src(q))
    if q.startswith('datetime.datetime.') or q.startswith('datetime.date.'):
        return V(('any',), objs=[('dt',)], src=_py_src(q))
    if q == 'getpass.getuser':
        return str_v(src=_py_src(q))
    if q in ('pwd.getpwnam', 'pwd.getpwuid'):
        return V(('any',), objs=[('ns', _PWD)], src=_py_src(q))
    if q in ('grp.getgrgid', 'grp.getgrnam'):
        return V(('any',), objs=[('ns', _GRP)], src=_py_src(q))
    if q in ('json.loads', 'json.load'):
        v = V(('dict',), src=s)
        v.dyn = V(('any',))
        v.dyn_name = '<key>'
        return v
    if q.startswith('ansible.module_utils.distro.'):
        fn = q.rpartition('.')[2]
        ds = {'python:distro.' + fn + '()'}
        if fn in ('os_release_info', 'lsb_release_info', 'distro_release_info', 'uname_info', 'info'):
            v = V(('dict',), src=ds)
            v.dyn = str_v(src=ds)
            v.dyn_name = '<key>'
            return v
        if fn in ('id', 'name', 'version', 'codename', 'like', 'build_number', 'major_version',
                  'minor_version', 'os_release_attr', 'lsb_release_attr', 'distro_release_attr'):
            return str_v(src=ds)
        if fn == 'version_parts':
            return seq([str_v(src=ds), str_v(src=ds), str_v(src=ds)])
    if q in ('ansible.module_utils.six.iteritems', 'ansible.module_utils.six.iterkeys',
             'ansible.module_utils.six.itervalues'):
        method = {'iteritems': 'items', 'iterkeys': 'keys', 'itervalues': 'values'}[q.rpartition('.')[2]]
        return interp.call_method(first, method, [], {}, node, frame)
    if q == 'shlex.split':
        return seq(items=str_v(src=s))
    if q in ('collections.defaultdict', 'collections.OrderedDict'):
        return V(('dict',), src=s)
    if q in ('copy.copy', 'copy.deepcopy'):
        return first
    if q == 're.compile':
        return V(('any',), objs=[('pattern', _regex_groups(first, _flags_arg(node, 1)))])
    if q in ('re.match', 're.search', 're.fullmatch'):
        return _match_obj(_regex_groups(first, _flags_arg(node, 2)), src_of(*a[1:2]))
    if q == 're.finditer':
        return seq(items=_match_obj(_regex_groups(first, _flags_arg(node, 2)), src_of(*a[1:2])))
    if q == 're.findall':
        return seq(items=str_v(src=src_of(*a[1:2])))
    if q == 're.sub':
        return str_v(src=src_of(*a[2:3]))
    if q == 're.split':
        return seq(items=str_v(src=src_of(*a[1:2])))
    if q == 're.escape':
        return str_v(templates(first), s)
    return V(('any',), src=s)


def _special_file_content(interp, a, kw, node, frame):
    path = a[0] if a else kw.get('path', V(('any',)))
    default = a[1] if len(a) > 1 else kw.get('default')
    v = str_v(src=_file_src(path))
    if default is None:
        v.types.add('null')
    else:
        v.types |= default.types - {'any'}
    return v


def _special_file_lines(interp, a, kw, node, frame):
    path = a[0] if a else kw.get('path', V(('any',)))
    return seq(items=str_v(src=_file_src(path)))


def _special_to_text(interp, a, kw, node, frame):
    first = a[0] if a else V(('any',))
    return str_v(templates(first), first.src)


def _special_bin_path(interp, a, kw, node, frame):
    return _bin_path(a)


def _bin_path(a):
    name = exact(a[0]) if a else None
    return V(('str', 'null'), frozenset(name) if name else frozenset((WILD,)))


def _special_str(interp, a, kw, node, frame):
    return str_v()


SPECIALS = {
    'ansible.module_utils.facts.utils.get_file_content': _special_file_content,
    'ansible.module_utils.facts.utils.get_file_lines': _special_file_lines,
    'ansible.module_utils.common.text.converters.to_text': _special_to_text,
    'ansible.module_utils.common.text.converters.to_native': _special_to_text,
    'ansible.module_utils.common.text.converters.to_bytes': _special_to_text,
    'ansible.module_utils._text.to_text': _special_to_text,
    'ansible.module_utils._text.to_native': _special_to_text,
    'ansible.module_utils.common.process.get_bin_path': _special_bin_path,
    'ansible.module_utils.common.locale.get_best_parsable_locale': _special_str,
}


def _cmd_src(v):
    if v.elts is not None:
        parts = []
        for e in v.elts:
            ex = exact(e)
            if ex and len(ex) == 1:
                parts.append(next(iter(ex)))
            elif e.strs and len(e.strs) == 1:
                parts.append(next(iter(e.strs)))
            elif ex:
                parts.append('{' + '|'.join(sorted(ex)) + '}')
            else:
                parts.append(WILD)
        labels = {' '.join(parts)}
    else:
        labels = set(templates(v))
    return {'cmd:' + render_template(_norm(t)) for t in sorted(labels)[:4] if t.strip(WILD + ' ')}


# --------------------------------------------------------------------------- interpreter


class Interp:
    def __init__(self, index: Index):
        self.index = index
        self.menv = {}
        self.classes = {}
        self.cenv = {}
        self.mros = {}
        self.stack = []
        self.steps = 0
        self.unroll = 0
        self.unroll_names = set()

    def tick(self):
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise BudgetExceeded()

    @staticmethod
    def analyzed(modname):
        return modname.startswith(ANALYZED_PREFIXES)

    def site(self, node, frame):
        if node is None or frame is None:
            return Site('', 0, '')
        return Site(frame.module.rel, getattr(node, 'lineno', 0), frame.qual)

    # ---------------------------------------------------------------- modules/classes

    def module_env(self, mod):
        env = self.menv.get(mod.name)
        if env is None:
            env = self.menv[mod.name] = {'__name__': cstr(mod.name)}
            self.exec_block(mod.tree.body, Frame(mod, env))
        return env

    def module_value(self, dotted):
        mod = self.index.modules.get(dotted)
        if mod is not None and self.analyzed(dotted):
            return V(objs=[('pymod', dotted)])
        return V(('any',), objs=[('ext', dotted)])

    def import_from(self, modname, name):
        mod = self.index.modules.get(modname)
        if mod is not None and self.analyzed(modname):
            env = self.module_env(mod)
            if name in env:
                return env[name]
            if modname + '.' + name in self.index.modules:
                return self.module_value(modname + '.' + name)
            return V(('any',))
        if modname + '.' + name in self.index.modules:
            return self.module_value(modname + '.' + name)
        return V(('any',), objs=[('ext', modname + '.' + name)])

    def class_info(self, node, module):
        ci = self.classes.get(id(node))
        if ci is None:
            ci = self.classes[id(node)] = ClassInfo(node, module)
        return ci

    def class_env(self, ci):
        env = self.cenv.get(id(ci))
        if env is None:
            env = self.cenv[id(ci)] = {}
            self.exec_block(ci.node.body, Frame(ci.module, env, cls=ci, in_class=True))
        return env

    def bases(self, ci):
        out = []
        frame = Frame(ci.module, self.module_env(ci.module))
        for b in ci.node.bases:
            for o in self.eval(b, frame).objs:
                if o[0] == 'class':
                    out.append(o[1])
        return out

    def mro(self, ci):
        m = self.mros.get(id(ci))
        if m is None:
            self.mros[id(ci)] = m = [ci]
            for b in self.bases(ci):
                for x in self.mro(b):
                    if x not in m:
                        m.append(x)
        return m

    def find_in_mro(self, ci, name, after=None):
        m = self.mro(ci)
        if after is not None and after in m:
            m = m[m.index(after) + 1:]
        for c in m:
            env = self.class_env(c)
            if name in env:
                return env[name], c
        return None, None

    def bind(self, val, self_v, cls):
        objs = []
        for o in val.objs:
            if o[0] == 'func':
                fi = o[1]
                if fi.kind == 'static':
                    objs.append(o)
                elif fi.kind == 'classmethod':
                    objs.append(('bound', V(objs=[('class', cls)]), fi))
                elif fi.kind == 'property':
                    return self.call_func(fi, self_v, [], {})
                else:
                    objs.append(('bound', self_v, fi))
            else:
                objs.append(o)
        if not objs:
            return val
        out = V(val.types, val.strs, val.src, objs)
        return out

    def instantiate(self, ci, args, kwargs, unknown_missing=False):
        v = V(objs=[('inst', Inst(ci))])
        init, owner = self.find_in_mro(ci, '__init__')
        if init is not None:
            for o in init.objs:
                if o[0] == 'func':
                    self.call_func(o[1], v, args, kwargs, unknown_missing=unknown_missing)
        return v

    # ---------------------------------------------------------------- calls

    def call(self, fv, args, kwargs, node, frame):
        results = []
        for o in list(fv.objs):
            k = o[0]
            if k == 'func':
                results.append(self.call_func(o[1], None, args, kwargs, node=node, frame=frame))
            elif k == 'closure':
                results.append(self.call_func(o[1], None, args, kwargs, closure=o[2], node=node, frame=frame))
            elif k == 'bound':
                results.append(self.call_func(o[2], o[1], args, kwargs, node=node, frame=frame))
            elif k == 'class':
                results.append(self.instantiate(o[1], args, kwargs))
            elif k == 'ext':
                a = [x for x in args if x is not _REST]
                if o[1] in SPECIALS:
                    results.append(SPECIALS[o[1]](self, a, kwargs, node, frame))
                else:
                    results.append(ext_call(self, o[1], a, kwargs, node, frame))
            elif k == 'builtin':
                results.append(self.call_builtin(o[1], args, kwargs, node, frame))
            elif k == 'method':
                results.append(self.call_method(o[1], o[2], args, kwargs, node, frame))
            elif k == 'amod_m':
                results.append(self.call_amod(o[1], args, kwargs))
        if not results:
            return V(('any',), src=src_of(*args, *kwargs.values()))
        return results[0] if len(results) == 1 else union(*results)

    def call_func(self, fi, self_v, args, kwargs, closure=None, unknown_missing=False, node=None, frame=None):
        special = SPECIALS.get(fi.fullname)
        if special is not None:
            return special(self, [x for x in args if x is not _REST], kwargs, node, frame)
        key = id(fi.node)
        if key in self.stack or len(self.stack) >= MAX_DEPTH:
            return V(('any',))
        fnode = fi.node
        a = fnode.args
        env = {}
        fr = Frame(fi.module, env, parent=closure, func=fi, cls=fi.cls, self_v=self_v)
        pos_params = [p.arg for p in a.posonlyargs + a.args]
        defaults = {}
        all_pos = a.posonlyargs + a.args
        for p, d in zip(all_pos[len(all_pos) - len(a.defaults):], a.defaults):
            defaults[p.arg] = d
        for p, d in zip(a.kwonlyargs, a.kw_defaults):
            if d is not None:
                defaults[p.arg] = d
        pos = list(args)
        if self_v is not None and pos_params:
            env[pos_params[0]] = self_v
            pos_params = pos_params[1:]
        rest_unknown = '**' in kwargs
        for p in pos_params:
            if pos and not rest_unknown:
                x = pos.pop(0)
                if x is _REST:
                    rest_unknown = True
                    env[p] = V(('any',))
                else:
                    env[p] = x
            elif p in kwargs:
                env[p] = kwargs[p]
            else:
                env[p] = self._default(p, defaults, fi, unknown_missing or rest_unknown)
        for p in a.kwonlyargs:
            env[p.arg] = kwargs[p.arg] if p.arg in kwargs else self._default(p.arg, defaults, fi, unknown_missing)
        if a.vararg is not None:
            env[a.vararg.arg] = seq(items=union(*pos) if pos else None)
        if a.kwarg is not None:
            kv = V(('dict',))
            known = {p.arg for p in a.posonlyargs + a.args + a.kwonlyargs}
            for k, v in kwargs.items():
                if k != '**' and k not in known:
                    self.put_key(kv, k, v, set())
            env[a.kwarg.arg] = kv
        self.stack.append(key)
        try:
            if isinstance(fnode, ast.Lambda):
                fr.returns.append(self.eval(fnode.body, fr))
            else:
                self.exec_block(fnode.body, fr)
        finally:
            self.stack.pop()
        if fi.is_gen:
            return seq(items=union(*fr.yields) if fr.yields else None)
        if not fr.returns:
            return V(('null',))
        return union(*fr.returns)

    def _default(self, name, defaults, fi, unknown):
        d = defaults.get(name)
        if unknown or d is None:
            return V(('any',))
        return self.eval(d, Frame(fi.module, self.module_env(fi.module)))

    def call_amod(self, name, args, kwargs):
        a = [x for x in args if x is not _REST]
        if name == 'run_command':
            cmd = a[0] if a else kwargs.get('args', V(('any',)))
            cs = _cmd_src(cmd)
            return seq([V(('int',)), str_v(src=cs), str_v(src=cs)])
        if name == 'get_bin_path':
            return _bin_path(a)
        if name in ('warn', 'debug', 'deprecate', 'log', 'fail_json', 'exit_json'):
            return V(('null',))
        return V(('any',))

    def call_builtin(self, name, args, kwargs, node, frame):
        a = [x for x in args if x is not _REST]
        s = src_of(*a, *kwargs.values())
        first = a[0] if a else None
        site = self.site(node, frame)
        if name == 'str':
            if first is None:
                return cstr('')
            return str_v(templates(first) if first.strs is not None else None, first.src)
        if name in ('int', 'float', 'bool'):
            return V((name,), src=s)
        if name in ('len', 'hash', 'id', 'ord', 'sum'):
            return V(('int',), src=s)
        if name == 'round':
            return V(('int',) if len(a) < 2 else ('float',), src=s)
        if name == 'abs':
            return V(first.types if first else ('any',), src=s)
        if name in ('max', 'min'):
            if len(a) == 1:
                return self.item_of(first)
            return union(*(copy_prim(x) for x in a))
        if name in ('list', 'tuple', 'sorted', 'reversed', 'set', 'frozenset'):
            if first is None:
                return V(('list',))
            if first.elts is not None:
                return seq(first.elts, src=s)
            if is_dictish(first):
                if first.keys and first.dyn is None and len(first.keys) <= MAX_ENUM:
                    return seq([cstr(k) for k in first.keys], src=s)
                return seq(items=str_v(src=first.src), src=s)
            if first.items is not None:
                return seq(items=first.items, src=s)
            if 'str' in first.types:
                return seq(items=str_v(src=s), src=s)
            return seq(src=s)
        if name == 'dict':
            out = V(('dict',))
            if first is not None:
                if is_dictish(first):
                    self.dict_update(out, first, site)
                elif is_listish(first):
                    pair = first.items
                    if pair is not None and pair.elts is not None and len(pair.elts) == 2:
                        self.put_dyn(out, pair.elts[1], site, '<key>')
                    else:
                        self.put_dyn(out, V(('any',)), site, '<key>')
            for k, v in kwargs.items():
                if k != '**':
                    self.put_key(out, k, v, site)
            return out
        if name == 'dict.fromkeys':
            out = V(('dict',))
            val = a[1] if len(a) > 1 else V(('null',))
            names = self.enum_strings(first) if first is not None else None
            if names:
                for k in sorted(names):
                    self.put_key(out, k, copy_prim(val) if not is_container(val) else val, site)
            else:
                self.put_dyn(out, val, site, '<key>')
            return out
        if name in ('isinstance', 'issubclass', 'hasattr', 'callable', 'any', 'all'):
            return V(('bool',))
        if name == 'getattr':
            return self.dyn_getattr(a, node, frame)
        if name == 'open':
            return V(('any',), src=_file_src(first) if first is not None else (), objs=[('file',)])
        if name == 'range':
            return seq(items=V(('int',)))
        if name == 'enumerate':
            return seq(items=seq([V(('int',)), self.item_of(first)]))
        if name == 'zip':
            return seq(items=seq([self.item_of(x) for x in a]))
        if name == 'map':
            if len(a) < 2:
                return seq()
            return seq(items=self.call(a[0], [self.item_of(a[1])], {}, node, frame))
        if name == 'filter':
            return seq(items=self.item_of(a[1]) if len(a) > 1 else None)
        if name in ('repr', 'hex', 'oct', 'bin', 'chr', 'format', 'ascii'):
            return str_v(src=s)
        if name == 'iter':
            return first or V(('any',))
        if name == 'next':
            return union(self.item_of(first), *(a[1:2])) if first is not None else V(('any',))
        if name == 'super':
            return self.make_super(a, frame)
        if name == 'vars':
            v = V(('dict',))
            v.dyn = V(('any',))
            return v
        if name == 'divmod':
            return seq([V(('int',)), V(('int',))])
        if name == 'print':
            return V(('null',))
        return V(('any',), src=s)

    def make_super(self, a, frame):
        if frame is None:
            return V(('any',))
        if len(a) >= 2:
            cls = next((o[1] for o in a[0].objs if o[0] == 'class'), None)
            self_v = a[1]
        else:
            cls, self_v = frame.cls, frame.self_v
        if cls is None or self_v is None:
            return V(('any',))
        inst_cls = next((o[1].cls for o in self_v.objs if o[0] == 'inst'), cls)
        return V(objs=[('super', self_v, inst_cls, cls)])

    def dyn_getattr(self, a, node, frame):
        if len(a) < 2:
            return V(('any',))
        obj, nm = a[0], a[1]
        res = []
        names = exact(nm)
        if names:
            for n in sorted(names):
                r = self.get_attr(obj, n, node, frame, missing_ok=True)
                if r is not None:
                    res.append(r)
        elif nm.strs:
            pats = [re.compile('^' + '.*'.join(re.escape(p) for p in t.split(WILD)) + '$') for t in nm.strs]
            for n in sorted(self.attr_names(obj)):
                if any(p.match(n) for p in pats):
                    r = self.get_attr(obj, n, node, frame, missing_ok=True)
                    if r is not None:
                        res.append(r)
        if len(a) > 2:
            res.append(a[2])
        if not res:
            return V(('any',))
        return res[0] if len(res) == 1 else union(*res)

    def attr_names(self, obj):
        out = set()
        for o in obj.objs:
            if o[0] in ('inst', 'class'):
                ci = o[1].cls if o[0] == 'inst' else o[1]
                for c in self.mro(ci):
                    out |= set(self.class_env(c))
                if o[0] == 'inst':
                    out |= set(o[1].attrs)
        return out

    def get_attr(self, base, name, node, frame, missing_ok=False):
        out = []
        for o in base.objs:
            k = o[0]
            if k == 'inst':
                inst = o[1]
                if name in inst.attrs:
                    out.append(inst.attrs[name])
                    continue
                val, owner = self.find_in_mro(inst.cls, name)
                if val is not None:
                    out.append(self.bind(val, base, inst.cls))
                elif name == '__class__':
                    out.append(V(objs=[('class', inst.cls)]))
            elif k == 'class':
                val, owner = self.find_in_mro(o[1], name)
                if val is not None:
                    out.append(self.bind_class(val, o[1]))
            elif k == 'pymod':
                q = o[1] + '.' + name
                env = self.module_env(self.index.modules[o[1]])
                if name in env:
                    out.append(env[name])
                elif q in self.index.modules:
                    out.append(self.module_value(q))
            elif k == 'ext':
                out.append(ext_value(o[1] + '.' + name))
            elif k == 'amod':
                if name == 'params':
                    p = V(('dict',))
                    p.dyn = V(('any',))
                    out.append(p)
                else:
                    out.append(V(objs=[('amod_m', name)]))
            elif k == 'super':
                val, owner = self.find_in_mro(o[2], name, after=o[3])
                if val is not None:
                    out.append(self.bind(val, o[1], o[2]))
            elif k == 'ns':
                r = o[1](name)
                add_src(r, base.src)
                out.append(r)
            elif k == 'builtin' and o[1] == 'dict' and name == 'fromkeys':
                out.append(V(objs=[('builtin', 'dict.fromkeys')]))
        if out:
            return out[0] if len(out) == 1 else union(*out)
        if missing_ok:
            return None
        return V(('any',), src=base.src, objs=[('method', base, name)])

    def bind_class(self, val, ci):
        objs = []
        for o in val.objs:
            if o[0] == 'func' and o[1].kind == 'classmethod':
                objs.append(('bound', V(objs=[('class', ci)]), o[1]))
            else:
                objs.append(o)
        return V(val.types, val.strs, val.src, objs) if objs else val

    # ---------------------------------------------------------------- data methods

    def item_of(self, v):
        if v is None:
            return V(('any',))
        it = self.iter_elements(v)
        if isinstance(it, list):
            return union(*it)
        return it

    def iter_elements(self, v):
        """List of elements when iteration can be unrolled, else one item value."""
        if v.elts is not None and 0 < len(v.elts) <= MAX_ENUM:
            return list(v.elts)
        if is_dictish(v) and v.dyn is None and v.keys and len(v.keys) <= MAX_ENUM:
            return [cstr(k) for k in v.keys]
        if v.items is not None:
            return v.items
        if is_dictish(v):
            return str_v(src=v.src)
        if 'str' in v.types:
            return str_v(src=v.src)
        for o in v.objs:
            if o[0] == 'file':
                return str_v(src=v.src)
        return V(('any',), src=v.src)

    def enum_strings(self, v):
        if v is None:
            return None
        if v.elts is not None:
            out = set()
            for e in v.elts:
                ex = exact(e)
                if not ex:
                    return None
                out |= ex
            return out
        if is_dictish(v) and v.dyn is None and v.keys:
            return set(v.keys)
        if v.items is not None:
            ex = exact(v.items)
            return set(ex) if ex else None
        return None

    def lookup_key(self, base, key):
        ks = exact(key)
        if ks:
            vals = [base.keys[k] for k in sorted(ks) if k in base.keys]
            if base.dyn is not None and len(vals) < len(ks):
                vals.append(base.dyn)
            return union(*vals) if vals else None
        if base.dyn is not None:
            return base.dyn
        if base.keys:
            return union(*base.keys.values())
        return None

    def put_key(self, d, k, val, sites):
        d.types.add('dict')
        stored = val if is_container(val) else copy_prim(val)
        cur = d.keys.get(k)
        if cur is None:
            d.keys[k] = stored
        else:
            merge_into(cur, stored)
        if sites:
            d.ksites.setdefault(k, set()).update(sites if isinstance(sites, set) else {sites})

    def put_dyn(self, d, val, sites, label):
        d.types.add('dict')
        stored = val if is_container(val) else copy_prim(val)
        if d.dyn is None:
            d.dyn = stored
            d.dyn_name = label
        else:
            merge_into(d.dyn, stored)
        if sites:
            d.dyn_sites |= sites if isinstance(sites, set) else {sites}

    def put_item(self, lst, val, site):
        if not is_dictish(lst):
            lst.types.add('list')
        stored = val if is_container(val) else copy_prim(val)
        if lst.items is None:
            lst.items = stored
        else:
            merge_into(lst.items, stored)
        lst.elts = None
        if site:
            lst.item_sites.add(site)

    def dict_update(self, base, x, site):
        if is_dictish(x):
            for k, cv in x.keys.items():
                self.put_key(base, k, cv, set(x.ksites.get(k, ())) or site)
            if x.dyn is not None:
                self.put_dyn(base, x.dyn, set(x.dyn_sites) or site, x.dyn_name)
        elif is_listish(x) and x.items is not None and x.items.elts is not None and len(x.items.elts) == 2:
            self.put_dyn(base, x.items.elts[1], site, '<key>')

    def call_method(self, base, name, args, kwargs, node, frame):
        a = [x for x in args if x is not _REST]
        site = self.site(node, frame)
        s = src_of(base, *a)
        for o in base.objs:
            k = o[0]
            if k == 'match':
                return self.match_method(o[1], name, base)
            if k == 'pattern':
                target = a[0] if a else V(('any',))
                if name in ('match', 'search', 'fullmatch'):
                    return _match_obj(o[1], target.src)
                if name == 'finditer':
                    return seq(items=_match_obj(o[1], target.src))
                if name == 'findall':
                    return seq(items=str_v(src=target.src))
                if name == 'split':
                    return seq(items=str_v(src=target.src))
                if name == 'sub':
                    return str_v(src=src_of(*a[1:2]))
                return V(('any',))
            if k == 'file':
                if name in ('read', 'readline'):
                    return str_v(src=base.src)
                if name == 'readlines':
                    return seq(items=str_v(src=base.src))
                return V(('null',))
            if k == 'dt':
                if name in ('strftime', 'isoformat', 'ctime'):
                    return str_v(src=base.src)
                if name == 'timestamp':
                    return V(('float',))
                return V(('any',), objs=[('dt',)], src=base.src)
        dictish, listish = is_dictish(base), is_listish(base)
        if name in ('append', 'add'):
            if a:
                self.put_item(base, a[0], site)
            return V(('null',))
        if name == 'extend' and not dictish:
            if a:
                self.put_item(base, self.item_of(a[0]), site)
            return V(('null',))
        if name == 'insert' and not dictish:
            if len(a) > 1:
                self.put_item(base, a[1], site)
            return V(('null',))
        if name == 'update':
            if listish and not dictish:
                for x in a:
                    self.put_item(base, self.item_of(x), site)
            else:
                for x in a:
                    self.dict_update(base, x, site)
                for k, v in kwargs.items():
                    if k != '**':
                        self.put_key(base, k, v, site)
            return V(('null',))
        if name == 'setdefault':
            if not a:
                return V(('any',))
            default = a[1] if len(a) > 1 else V(('null',))
            ks = exact(a[0])
            if ks and len(ks) == 1:
                k = next(iter(ks))
                if k not in base.keys:
                    self.put_key(base, k, default, site)
                return base.keys[k]
            self.put_dyn(base, default, site, '<key>')
            return base.dyn
        if name in ('get', 'pop') and (dictish or not listish) and a:
            default = a[1] if len(a) > 1 else (V(('null',)) if name == 'get' else None)
            child = self.lookup_key(base, a[0]) if dictish else None
            if child is None and not dictish:
                child = V(('any',), src=base.src)
            return union(child, default) if default is not None and child is not None else (child or default)
        if name == 'pop' and listish:
            return self.item_of(base)
        if name == 'keys':
            if base.keys and base.dyn is None and len(base.keys) <= MAX_ENUM:
                return seq([cstr(k) for k in base.keys])
            return seq(items=str_v(src=base.src))
        if name == 'values':
            vals = list(base.keys.values()) + ([base.dyn] if base.dyn is not None else [])
            return seq(items=union(*vals) if vals else None)
        if name == 'items':
            vals = list(base.keys.values()) + ([base.dyn] if base.dyn is not None else [])
            keyv = str_v(base.keys if (base.keys and base.dyn is None) else None, base.src)
            pair = seq([keyv, union(*vals) if vals else V(('any',))])
            if base.keys and base.dyn is None and len(base.keys) <= MAX_ENUM:
                out = seq([seq([cstr(k), cv]) for k, cv in base.keys.items()])
                out.items = pair
                return out
            return seq(items=pair)
        if name == 'copy':
            return base
        if name in ('index', 'count', 'find', 'rfind', 'rindex'):
            return V(('int',), src=s)
        if name in STR_TO_STR:
            return str_v(self.str_transform(base, name, a), s)
        if name in ('split', 'rsplit', 'splitlines'):
            return seq(items=str_v(src=s), src=s)
        if name in STR_TO_BOOL:
            return V(('bool',))
        if name in ('partition', 'rpartition'):
            return seq([str_v(src=s), str_v(src=s), str_v(src=s)])
        if name == 'join':
            return str_v(src=s)
        if name == 'format':
            return str_v(self.format_braces(base, a, kwargs), s)
        if name in ('sort', 'reverse', 'clear', 'remove', 'discard', 'close', 'write'):
            return V(('null',))
        return V(('any',), src=s)

    def match_method(self, groups, name, base):
        if name in ('group', '__getitem__'):
            return str_v(src=base.src)
        if name == 'groups':
            return seq(items=str_v(src=base.src))
        if name == 'groupdict':
            d = V(('dict',))
            if groups:
                for g in sorted(groups):
                    self.put_key(d, g, str_v(src=base.src, extra=('null',)), set())
            else:
                self.put_dyn(d, str_v(src=base.src), set(), '<group>')
            return d
        if name in ('start', 'end'):
            return V(('int',))
        if name == 'span':
            return seq([V(('int',)), V(('int',))])
        return V(('any',))

    def str_transform(self, base, name, a):
        if base.strs is None:
            return None
        ex = [exact(x) for x in a]
        args = [next(iter(e)) if e and len(e) == 1 else None for e in ex]
        out = set()
        for t in base.strs:
            if name in ('lower', 'upper', 'title', 'capitalize', 'casefold', 'swapcase'):
                out.add(t if WILD in t and name in ('title', 'capitalize') else getattr(t, name)())
            elif name in ('strip', 'lstrip', 'rstrip'):
                if a and args[0] is None:
                    out.add(t)
                else:
                    out.add(getattr(t, name)(*(args[:1] if a else ())))
            elif name == 'replace' and len(args) >= 2 and None not in args[:2]:
                out.add(t.replace(args[0], args[1]))
            elif name in ('removeprefix', 'removesuffix') and args and args[0] is not None:
                out.add(getattr(t, name)(args[0]))
            elif name in ('encode', 'decode'):
                out.add(t)
            else:
                return None
        return _cap(out)

    def format_percent(self, fmt, args):
        if is_dictish(args):
            parts = None
        elif args.elts is not None:
            parts = args.elts
        else:
            parts = [args]
        out = set()
        for t in sorted(templates(fmt))[:MAX_ENUM]:
            res = {''}
            i = 0
            pos = 0
            for m in PCT_RE.finditer(t):
                lit = t[pos:m.start()]
                pos = m.end()
                if m.group(0) == '%%':
                    res = {r + lit + '%' for r in res}
                    continue
                if parts is None or i >= len(parts):
                    arg_t = {WILD}
                else:
                    p = parts[i]
                    arg_t = p.strs if p.strs is not None and 'str' in p.types else {WILD}
                    i += 1
                res = {r + lit + x for r in res for x in arg_t}
                if len(res) > MAX_ENUM:
                    res = {WILD}
            out |= {r + t[pos:] for r in res}
        return _cap(out)

    def format_braces(self, fmt, a, kwargs):
        out = set()
        for t in sorted(templates(fmt))[:MAX_ENUM]:
            res = {''}
            seq_i = 0
            pos = 0
            for m in BRACE_RE.finditer(t):
                lit = t[pos:m.start()]
                pos = m.end()
                if m.group(0) in ('{{', '}}'):
                    res = {r + lit + m.group(0)[0] for r in res}
                    continue
                field = re.split(r'[!:.\[]', m.group(1), maxsplit=1)[0]
                if field == '':
                    v = a[seq_i] if seq_i < len(a) else None
                    seq_i += 1
                elif field.isdigit():
                    v = a[int(field)] if int(field) < len(a) else None
                else:
                    v = kwargs.get(field)
                arg_t = v.strs if v is not None and v.strs is not None and 'str' in v.types else {WILD}
                res = {r + lit + x for r in res for x in arg_t}
                if len(res) > MAX_ENUM:
                    res = {WILD}
            out |= {r + t[pos:] for r in res}
        return _cap(out)

    def binop(self, op, a, b):
        s = src_of(a, b)
        astr = 'str' in a.types or a.strs is not None
        bstr = 'str' in b.types or b.strs is not None
        if isinstance(op, ast.Add):
            if is_listish(a) or is_listish(b):
                out = seq(a.elts + b.elts if a.elts is not None and b.elts is not None else None, src=s)
                for x in (a, b):
                    it = x.items
                    if it is not None:
                        if out.items is None:
                            out.items = V()
                        merge_into(out.items, it)
                return out
            if astr or bstr:
                return str_v(concat(templates(a), templates(b)), s)
        if isinstance(op, ast.Mod) and astr:
            return str_v(self.format_percent(a, b), s)
        if isinstance(op, ast.Mult) and (astr or bstr):
            return str_v(src=s)
        if isinstance(op, ast.Mult) and (is_listish(a) or is_listish(b)):
            return seq(items=(a if is_listish(a) else b).items, src=s)
        if isinstance(op, (ast.BitOr, ast.BitAnd, ast.BitXor, ast.Sub)) and (is_dictish(a) or is_listish(a)):
            return union(a, b) if isinstance(op, ast.BitOr) else a
        nums = {'int', 'bool'}
        if isinstance(op, ast.Div) or 'float' in a.types or 'float' in b.types:
            return V(('float',), src=s)
        if a.types & nums or b.types & nums:
            return V(('int',), src=s)
        return V(('any',), src=s)

    # ---------------------------------------------------------------- statements

    def exec_block(self, stmts, frame):
        for st in stmts:
            self.exec_stmt(st, frame)

    def exec_stmt(self, node, frame):
        self.tick()
        t = type(node)
        if t is ast.Assign:
            v = self.eval(node.value, frame)
            for tgt in node.targets:
                self.store(tgt, v, frame)
        elif t is ast.AnnAssign:
            if node.value is not None:
                self.store(node.target, self.eval(node.value, frame), frame)
        elif t is ast.AugAssign:
            if isinstance(node.target, ast.Subscript):
                cur = self.eval(node.target, frame)
            else:
                cur = self.eval(node.target, frame) if not isinstance(node.target, ast.Name) else self.lookup(node.target.id, frame)
            self.store(node.target, self.binop(node.op, cur, self.eval(node.value, frame)), frame)
        elif t is ast.Expr:
            self.eval(node.value, frame)
        elif t is ast.Return:
            frame.returns.append(self.eval(node.value, frame) if node.value is not None else V(('null',)))
        elif t is ast.If:
            self.exec_if(node, frame)
        elif t in (ast.For, ast.AsyncFor):
            self.exec_for(node, frame)
        elif t is ast.While:
            self.eval(node.test, frame)
            snap = dict(frame.env)
            self.exec_block(node.body, frame)
            self.exec_block(node.orelse, frame)
            self._set_env(frame, self.join(frame.env, snap))
        elif t in (ast.Try, getattr(ast, 'TryStar', ast.Try)):
            self.exec_block(node.body, frame)
            after_body = dict(frame.env)
            envs = [after_body]
            for h in node.handlers:
                self._set_env(frame, after_body)
                if h.name:
                    frame.env[h.name] = V(('any',))
                self.exec_block(h.body, frame)
                envs.append(dict(frame.env))
            env = envs[0]
            for e in envs[1:]:
                env = self.join(env, e)
            self._set_env(frame, env)
            self.exec_block(node.orelse, frame)
            self.exec_block(node.finalbody, frame)
        elif t in (ast.With, ast.AsyncWith):
            for item in node.items:
                v = self.eval(item.context_expr, frame)
                if item.optional_vars is not None:
                    self.store(item.optional_vars, v, frame, strong=True)
            self.exec_block(node.body, frame)
        elif t in (ast.FunctionDef, ast.AsyncFunctionDef):
            self.def_function(node, frame)
        elif t is ast.ClassDef:
            frame.env[node.name] = V(objs=[('class', self.class_info(node, frame.module))])
        elif t is ast.Import:
            for alias in node.names:
                if alias.asname:
                    frame.env[alias.asname] = self.module_value(alias.name)
                else:
                    top = alias.name.split('.')[0]
                    frame.env[top] = self.module_value(top)
        elif t is ast.ImportFrom:
            modname = self.resolve_from(node, frame.module)
            for alias in node.names:
                if alias.name == '*':
                    continue
                frame.env[alias.asname or alias.name] = self.import_from(modname, alias.name)
        elif t is ast.Global:
            frame.globals.update(node.names)
        elif t is ast.Nonlocal:
            frame.nonlocals.update(node.names)
        elif t is ast.Match:
            self.eval(node.subject, frame)
            snap = dict(frame.env)
            env = snap
            for case in node.cases:
                self._set_env(frame, snap)
                self.exec_block(case.body, frame)
                env = self.join(env, dict(frame.env))
            self._set_env(frame, env)
        # Pass, Break, Continue, Raise, Assert, Delete: no effect on fact shapes

    @staticmethod
    def resolve_from(node, module):
        if not node.level:
            return node.module or ''
        pkg = module.package.split('.')
        base = pkg[:len(pkg) - (node.level - 1)] if node.level > 1 else pkg
        return '.'.join(base + ([node.module] if node.module else []))

    def def_function(self, node, frame):
        kind = 'func'
        for d in node.decorator_list:
            dn = d.id if isinstance(d, ast.Name) else (d.attr if isinstance(d, ast.Attribute) else None)
            if dn in ('staticmethod', 'classmethod', 'property'):
                kind = 'static' if dn == 'staticmethod' else dn
        if frame.func is not None:
            qual = frame.func.qualname + '.' + node.name
        elif frame.in_class:
            qual = frame.cls.name + '.' + node.name
        else:
            qual = node.name
        fi = FuncInfo(node, frame.module, frame.cls, qual, kind)
        if frame.func is None:
            frame.env[node.name] = V(objs=[('func', fi)])
        else:
            frame.env[node.name] = V(objs=[('closure', fi, frame)])

    @staticmethod
    def _set_env(frame, new):
        """Replace a frame's bindings in place (module/class envs are shared dicts)."""
        if new is frame.env:
            return
        new = dict(new)
        frame.env.clear()
        frame.env.update(new)

    def exec_if(self, node, frame):
        self.eval(node.test, frame)
        truth = self.static_truth(node.test, frame)
        if truth is True:
            self.exec_block(node.body, frame)
            return
        if truth is False:
            self.exec_block(node.orelse, frame)
            return
        narrow = self.narrowing(node.test, frame)
        snap = dict(frame.env)
        for name, nv in narrow.items():
            frame.env[name] = nv
        self.exec_block(node.body, frame)
        for name, nv in narrow.items():
            if frame.env.get(name) is nv:
                if name in snap:
                    frame.env[name] = snap[name]
                else:
                    del frame.env[name]
        env1 = dict(frame.env)
        self._set_env(frame, snap)
        self.exec_block(node.orelse, frame)
        self._set_env(frame, self.join(env1, frame.env))

    def static_truth(self, test, frame):
        """Decide ``name ==/!=/in/not in <constant>`` when name holds known strings (unrolled loops)."""
        if isinstance(test, ast.BoolOp):
            vals = [self.static_truth(v, frame) for v in test.values]
            if isinstance(test.op, ast.And):
                return False if False in vals else (True if all(v is True for v in vals) else None)
            return True if True in vals else (False if all(v is False for v in vals) else None)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            t = self.static_truth(test.operand, frame)
            return None if t is None else not t
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name)):
            return None
        if test.left.id not in self.unroll_names:
            return None
        left = exact(self.lookup(test.left.id, frame))
        if not left:
            return None
        op, right = test.ops[0], test.comparators[0]
        if isinstance(op, (ast.Eq, ast.NotEq)):
            r = exact(self.eval(right, frame))
            if not r or not isinstance(right, ast.Constant):
                return None
            eq = left == r if len(left) == 1 else (False if not (left & r) else None)
            if eq is None:
                return None
            return eq if isinstance(op, ast.Eq) else not eq
        if isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
            r = self.enum_strings(self.eval(right, frame))
            if not r:
                return None
            if left <= r:
                res = True
            elif not (left & r):
                res = False
            else:
                return None
            return res if isinstance(op, ast.In) else not res
        return None

    def narrowing(self, test, frame):
        """``if name in CONSTANTS`` / ``if name == 'x'`` bind name to those strings in the body."""
        out = {}
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            for v in test.values:
                out.update(self.narrowing(v, frame))
            return out
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name)):
            return out
        op, right = test.ops[0], test.comparators[0]
        name = test.left.id
        if isinstance(op, ast.In):
            names = self.enum_strings(self.eval(right, frame))
        elif isinstance(op, ast.Eq):
            names = exact(self.eval(right, frame))
        else:
            return out
        if names and len(names) <= MAX_ENUM:
            cur = self.lookup(name, frame)
            out[name] = V(('str',), frozenset(names), cur.src)
        return out

    def join(self, a, b):
        if a is b:
            return a
        out = {}
        for name in a.keys() | b.keys():
            x, y = a.get(name), b.get(name)
            if x is None:
                out[name] = y
            elif y is None or x is y:
                out[name] = x
            elif is_container(x) and is_container(y):
                merge_into(x, y)
                out[name] = x
            else:
                out[name] = union(x, y)
        return out

    def exec_for(self, node, frame):
        it = self.eval(node.iter, frame)
        elems = self.iter_elements(it)
        snap = dict(frame.env)
        if isinstance(elems, list) and self.unroll < MAX_UNROLL_NEST:
            self.unroll += 1
            names = {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
            added = names - self.unroll_names
            self.unroll_names |= added
            try:
                for e in elems:
                    self.store(node.target, e, frame, strong=True)
                    self.exec_block(node.body, frame)
            finally:
                self.unroll -= 1
                self.unroll_names -= added
        else:
            item = union(*elems) if isinstance(elems, list) else elems
            self.store(node.target, item, frame, strong=True)
            self.exec_block(node.body, frame)
        self.exec_block(node.orelse, frame)
        self._set_env(frame, self.join(frame.env, snap))

    # ---------------------------------------------------------------- stores

    def store(self, target, value, frame, strong=False):
        t = type(target)
        if t is ast.Name:
            self.store_name(target.id, value, frame, strong)
        elif t in (ast.Tuple, ast.List):
            elts = target.elts
            if value.elts is not None and len(value.elts) == len(elts) and not any(
                    isinstance(e, ast.Starred) for e in elts):
                for e, v in zip(elts, value.elts):
                    self.store(e, v, frame, strong)
            else:
                item = self.item_of(value)
                for e in elts:
                    if isinstance(e, ast.Starred):
                        self.store(e.value, seq(items=item), frame, strong)
                    else:
                        self.store(e, item, frame, strong)
        elif t is ast.Subscript:
            base = self.eval_container(target.value, frame)
            if isinstance(target.slice, ast.Slice):
                return
            key = self.eval(target.slice, frame)
            self.store_item(base, key, value, self.site(target, frame), target.slice)
        elif t is ast.Attribute:
            base = self.eval(target.value, frame)
            for o in base.objs:
                if o[0] == 'inst':
                    attrs = o[1].attrs
                    old = attrs.get(target.attr)
                    if old is not None and old is not value and is_dictish(old) and is_dictish(value):
                        merge_into(old, value)
                    else:
                        attrs[target.attr] = value
        elif t is ast.Starred:
            self.store(target.value, value, frame, strong)

    def store_name(self, name, value, frame, strong=False):
        env = frame.env
        if name in frame.globals:
            env = self.module_env(frame.module)
        elif name in frame.nonlocals:
            f = frame.parent
            while f is not None and name not in f.env:
                f = f.parent
            if f is not None:
                env = f.env
        old = env.get(name)
        if not strong and old is not None and old is not value and is_dictish(old) and is_dictish(value):
            merge_into(old, value)
            return
        env[name] = value

    def store_item(self, base, key, value, site, key_node):
        if (base.elts is not None or ('list' in base.types and not is_dictish(base))) and \
                ('int' in key.types or 'bool' in key.types):
            self.put_item(base, value, site)
            return
        ks = exact(key)
        if ks is None and isinstance(key_node, ast.Constant) and isinstance(key_node.value, (int, float)):
            ks = {str(key_node.value)}
        if ks:
            for k in sorted(ks):
                self.put_key(base, k, value, site)
        else:
            self.put_dyn(base, value, site, dyn_label(key_node, key))

    def eval_container(self, node, frame):
        """Evaluate the base of a store/mutation, creating missing intermediate containers."""
        if isinstance(node, ast.Subscript) and not isinstance(node.slice, ast.Slice):
            base = self.eval_container(node.value, frame)
            key = self.eval(node.slice, frame)
            if base.elts is not None and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                try:
                    return base.elts[node.slice.value]
                except IndexError:
                    pass
            if is_listish(base) and not is_dictish(base):
                if base.items is None:
                    base.items = V()
                return base.items
            ks = exact(key)
            if ks is None and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, (int, float)):
                ks = {str(node.slice.value)}
            base.types.add('dict')
            if ks:
                k = sorted(ks)[0]
                if k not in base.keys:
                    base.keys[k] = V()
                return base.keys[k]
            if base.dyn is None:
                base.dyn = V()
                base.dyn_name = dyn_label(node.slice, key)
            return base.dyn
        return self.eval(node, frame)

    # ---------------------------------------------------------------- expressions

    def lookup(self, name, frame):
        f = frame
        while f is not None:
            if name in f.env:
                return f.env[name]
            f = f.parent
        menv = self.module_env(frame.module)
        if name in menv:
            return menv[name]
        if name in BUILTIN_NAMES:
            if name in ('True', 'False'):
                return V(('bool',))
            if name == 'None':
                return V(('null',))
            return V(objs=[('builtin', name)])
        return V(('any',))

    def eval(self, node, frame):
        self.tick()
        m = getattr(self, 'e_' + type(node).__name__, None)
        if m is None:
            return V(('any',))
        return m(node, frame)

    def e_Constant(self, node, frame):
        c = node.value
        if isinstance(c, str):
            return cstr(c)
        if isinstance(c, bool):
            return V(('bool',))
        if isinstance(c, int):
            return V(('int',))
        if isinstance(c, float):
            return V(('float',))
        if c is None:
            return V(('null',))
        if isinstance(c, bytes):
            return str_v()
        return V(('any',))

    def e_JoinedStr(self, node, frame):
        res = frozenset(('',))
        s = set()
        for part in node.values:
            if isinstance(part, ast.Constant):
                res = concat(res, {str(part.value)})
            else:
                v = self.eval(part.value, frame)
                s |= v.src
                t = v.strs if v.strs is not None and 'str' in v.types and part.format_spec is None else {WILD}
                res = concat(res, t)
        return str_v(res, s)

    def e_Name(self, node, frame):
        return self.lookup(node.id, frame)

    def e_Attribute(self, node, frame):
        return self.get_attr(self.eval(node.value, frame), node.attr, node, frame)

    def e_Subscript(self, node, frame):
        base = self.eval(node.value, frame)
        if isinstance(node.slice, ast.Slice):
            if 'str' in base.types and not is_listish(base):
                return str_v(src=base.src)
            return seq(items=self.item_of(base), src=base.src) if is_listish(base) else V(('any',), src=base.src)
        key = self.eval(node.slice, frame)
        if base.elts is not None and isinstance(node.slice, (ast.Constant, ast.UnaryOp)):
            try:
                idx = ast.literal_eval(node.slice)
                if isinstance(idx, int):
                    return base.elts[idx]
            except (ValueError, IndexError):
                pass
        for o in base.objs:
            if o[0] == 'match':
                return str_v(src=base.src)
        if is_dictish(base):
            child = self.lookup_key(base, key)
            return child if child is not None else V(('any',), src=base.src)
        if is_listish(base):
            return base.items if base.items is not None else V(('any',), src=base.src)
        if 'str' in base.types:
            return str_v(src=base.src)
        return V(('any',), src=src_of(base, key))

    def e_Call(self, node, frame):
        if isinstance(node.func, ast.Attribute) and node.func.attr in MUTATING_METHODS:
            base = self.eval_container(node.func.value, frame)
            fv = self.get_attr(base, node.func.attr, node.func, frame)
        else:
            fv = self.eval(node.func, frame)
        args = []
        for a in node.args:
            if isinstance(a, ast.Starred):
                sv = self.eval(a.value, frame)
                if sv.elts is not None:
                    args.extend(sv.elts)
                else:
                    args.append(_REST)
            else:
                args.append(self.eval(a, frame))
        kwargs = {}
        for kw in node.keywords:
            v = self.eval(kw.value, frame)
            if kw.arg is None:
                kwargs['**'] = v
                for k, cv in v.keys.items():
                    kwargs.setdefault(k, cv)
            else:
                kwargs[kw.arg] = v
        return self.call(fv, args, kwargs, node, frame)

    def e_Dict(self, node, frame):
        out = V(('dict',))
        for k, vnode in zip(node.keys, node.values):
            val = self.eval(vnode, frame)
            if k is None:
                self.dict_update(out, val, self.site(vnode, frame))
                continue
            kv = self.eval(k, frame)
            site = self.site(k, frame)
            ks = exact(kv)
            if ks is None and isinstance(k, ast.Constant) and isinstance(k.value, (int, float)):
                ks = {str(k.value)}
            if ks:
                for x in sorted(ks):
                    self.put_key(out, x, val, site)
            else:
                self.put_dyn(out, val, site, dyn_label(k, kv))
        return out

    def _seq_literal(self, node, frame):
        elts = []
        known = True
        for e in node.elts:
            if isinstance(e, ast.Starred):
                sv = self.eval(e.value, frame)
                if sv.elts is not None:
                    elts.extend(sv.elts)
                else:
                    known = False
                    elts.append(self.item_of(sv))
            else:
                elts.append(self.eval(e, frame))
        out = seq(elts)
        if not known:
            out.elts = None
        return out

    e_List = e_Tuple = e_Set = _seq_literal

    def _comp_frame(self, generators, frame):
        cf = Frame(frame.module, {}, parent=frame, func=frame.func, cls=frame.cls, self_v=frame.self_v)
        for g in generators:
            it = self.eval(g.iter, cf)
            self.store(g.target, self.item_of(it), cf, strong=True)
            for cond in g.ifs:
                self.eval(cond, cf)
        return cf

    def _comp(self, node, frame):
        cf = self._comp_frame(node.generators, frame)
        el = self.eval(node.elt, cf)
        return seq(items=el, src=el.src)

    e_ListComp = e_SetComp = e_GeneratorExp = _comp

    def e_DictComp(self, node, frame):
        cf = self._comp_frame(node.generators, frame)
        k = self.eval(node.key, cf)
        v = self.eval(node.value, cf)
        out = V(('dict',))
        ks = exact(k)
        site = self.site(node, frame)
        if ks:
            for x in sorted(ks):
                self.put_key(out, x, v, site)
        else:
            self.put_dyn(out, v, site, dyn_label(node.key, k))
        return out

    def e_BinOp(self, node, frame):
        return self.binop(node.op, self.eval(node.left, frame), self.eval(node.right, frame))

    def e_UnaryOp(self, node, frame):
        v = self.eval(node.operand, frame)
        if isinstance(node.op, ast.Not):
            return V(('bool',))
        if isinstance(node.op, ast.Invert):
            return V(('int',), src=v.src)
        return V(v.types & {'int', 'float', 'bool'} or ('any',), src=v.src)

    def e_BoolOp(self, node, frame):
        return union(*(self.eval(v, frame) for v in node.values))

    def e_Compare(self, node, frame):
        self.eval(node.left, frame)
        for c in node.comparators:
            self.eval(c, frame)
        return V(('bool',))

    def e_IfExp(self, node, frame):
        self.eval(node.test, frame)
        return union(self.eval(node.body, frame), self.eval(node.orelse, frame))

    def e_Lambda(self, node, frame):
        fi = FuncInfo(node, frame.module, frame.cls, (frame.qual + '.<lambda>'), 'func')
        return V(objs=[('closure', fi, frame)])

    def e_NamedExpr(self, node, frame):
        v = self.eval(node.value, frame)
        self.store_name(node.target.id, v, frame)
        return v

    def e_Starred(self, node, frame):
        return self.eval(node.value, frame)

    def e_Yield(self, node, frame):
        if node.value is not None:
            frame.yields.append(self.eval(node.value, frame))
        return V(('any',))

    def e_YieldFrom(self, node, frame):
        frame.yields.append(self.item_of(self.eval(node.value, frame)))
        return V(('any',))

    def e_Await(self, node, frame):
        return self.eval(node.value, frame)


def dyn_label(key_node, key_v=None):
    """Human placeholder for a runtime key, from the expression that computes it."""
    name = _label_name(key_node)
    if key_v is not None and key_v.strs and len(key_v.strs) == 1:
        t = next(iter(key_v.strs))
        if t != WILD and WILD in t:
            return t.replace(WILD, '<' + name + '>')
    return '<' + name + '>'


def _label_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            return node.slice.value
        return _label_name(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _label_name(node.func.value)
        for a in node.args:
            return _label_name(a)
    if isinstance(node, (ast.BinOp, ast.JoinedStr)):
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                return n.id
    return 'key'


# --------------------------------------------------------------------------- doc tree


class Node:
    __slots__ = ('name', 'kind', 'types', 'src', 'sites', 'children', 'platforms', 'subsets')

    def __init__(self, name, kind):
        self.name = name
        self.kind = kind  # key | dyn | item
        self.types = set()
        self.src = set()
        self.sites = set()
        self.children = {}
        self.platforms = set()
        self.subsets = set()

    def child(self, name, kind):
        c = self.children.get(name)
        if c is None:
            c = self.children[name] = Node(name, kind)
        return c

    def merge(self, other):
        self.types |= other.types
        self.src |= other.src
        self.sites |= other.sites
        self.platforms |= other.platforms
        self.subsets |= other.subsets
        for n, c in other.children.items():
            if n not in self.children and c.kind == 'dyn':
                existing = next((x for x in self.children.values() if x.kind == 'dyn'), None)
                if existing is not None:
                    existing.merge(c)
                    continue
            if n in self.children:
                self.children[n].merge(c)
            else:
                self.children[n] = c

    def tag(self, platform, subset):
        self.platforms.add(platform)
        self.subsets.add(subset)
        for c in self.children.values():
            c.tag(platform, subset)

    def prune(self):
        for n in list(self.children):
            c = self.children[n]
            c.prune()
            if not c.types and not c.children:
                del self.children[n]
        if self.children and not self.types:
            self.types.add('dict')


def type_names(v, depth=0):
    out = set()
    for x in v.types - {'any'}:
        if x == 'list':
            inner = type_names(v.items, depth + 1) - {'any'} if (v.items is not None and depth < 1) else set()
            out.add('list[' + ' | '.join(sorted(inner)) + ']' if inner else 'list')
        else:
            out.add(x)
    if ('any' in v.types or v.objs) and not (out - {'null'}):
        out.add('any')
    return out


def _has_structure(v, seen=None):
    seen = seen or set()
    if id(v) in seen:
        return False
    seen.add(id(v))
    return bool(v.keys) or v.dyn is not None or (v.items is not None and _has_structure(v.items, seen))


# Placeholder for runtime keys, derived from the parent key (``devices`` -> ``<device>``).
PLACEHOLDER_BY_PARENT = {
    'env': '<variable>', 'cmdline': '<option>', 'proc_cmdline': '<option>', 'local': '<fact_file>',
    'options': '<option>', 'addresses': '<address>', 'device_links': '<link_type>',
}
PLACEHOLDER_BY_LABEL = {'<sect>': '<section>', '<opt>': '<option>', '<k>': '<key>'}


def placeholder(keypath, label):
    parent = keypath[-1] if keypath else ''
    if len(keypath) >= 2 and keypath[-2] == 'device_links':
        return '<device>'
    if parent in PLACEHOLDER_BY_PARENT:
        return PLACEHOLDER_BY_PARENT[parent]
    if parent and parent != '[]' and not parent.startswith('<') and len(parent) > 2:
        if parent.endswith('ies'):
            return '<' + parent[:-3] + 'y>'
        if parent.endswith(('sses', 'xes')):
            return '<' + parent[:-2] + '>'
        if parent.endswith('s'):
            return '<' + parent[:-1] + '>'
    label = label or '<key>'
    if not label.startswith('<'):
        label = '<' + label + '>'
    return PLACEHOLDER_BY_LABEL.get(label, label)


def fill_node(node, v, sites, path, keypath=()):
    node.types |= type_names(v)
    node.src |= v.src
    node.sites |= set(sites)
    if id(v) in path or len(path) > 12:
        return
    path = path | {id(v)}
    for k, cv in v.keys.items():
        fill_node(node.child(k, 'key'), cv, v.ksites.get(k, ()), path, keypath + (k,))
    if v.dyn is not None:
        name = placeholder(keypath, v.dyn_name)
        fill_node(node.child(name, 'dyn'), v.dyn, v.dyn_sites, path, keypath + (name,))
    if v.items is not None and _has_structure(v.items):
        fill_node(node.child('[]', 'item'), v.items, v.item_sites, path, keypath + ('[]',))


# --------------------------------------------------------------------------- entry points


def _class_const(interp, ci, attr):
    val, _ = interp.find_in_mro(ci, attr)
    return val


def _namespace_prefix(interp, ci):
    for c in interp.mro(ci):
        for st in c.node.body:
            if isinstance(st, ast.FunctionDef) and st.name == '__init__':
                for n in ast.walk(st):
                    if isinstance(n, ast.Call) and getattr(n.func, 'id', getattr(n.func, 'attr', '')) == 'PrefixFactNamespace':
                        for kw in n.keywords:
                            if kw.arg == 'prefix' and isinstance(kw.value, ast.Constant):
                                return kw.value.value
    return None


def minimal_gather_subset(index: Index):
    mod = index.modules.get('ansible.modules.setup')
    if mod is None:
        return []
    for n in ast.walk(mod.tree):
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == 'minimal_gather_subset' for t in n.targets):
            try:
                return sorted(ast.literal_eval(n.value.args[0]))
            except (ValueError, AttributeError, IndexError):
                return []
    return []


def discover_collectors(index: Index):
    """(module name, class name) of every collector setup can run, in default order."""
    interp = Interp(index)
    out = []
    env = interp.module_env(index.modules['ansible.module_utils.facts.default_collectors'])
    coll = env.get('collectors')
    classes = []
    if coll is not None and coll.elts is not None:
        for e in coll.elts:
            classes.extend(o[1] for o in e.objs if o[0] == 'class')
    meta_env = interp.module_env(index.modules['ansible.module_utils.facts.ansible_collector'])
    meta = meta_env.get('CollectorMetaDataCollector')
    if meta is not None:
        classes.extend(o[1] for o in meta.objs if o[0] == 'class')
    for ci in classes:
        out.append((ci.module.name, ci.name))
    return out


def analyze_collector(index: Index, modname: str, clsname: str):
    interp = Interp(index)
    cv = interp.import_from(modname, clsname)
    ci = next(o[1] for o in cv.objs if o[0] == 'class')
    name_v = _class_const(interp, ci, 'name')
    plat_v = _class_const(interp, ci, '_platform')
    ids_v = _class_const(interp, ci, '_fact_ids')
    name = next(iter(exact(name_v))) if name_v is not None and exact(name_v) else None
    platform = next(iter(exact(plat_v))) if plat_v is not None and exact(plat_v) else 'Generic'
    fact_ids = sorted(interp.enum_strings(ids_v) or ()) if ids_v is not None else []
    info = {
        'module': modname,
        'class': clsname,
        'file': ci.module.rel,
        'line': ci.node.lineno,
        'name': name,
        'platform': platform,
        'prefix': _namespace_prefix(interp, ci),
        'fact_ids': fact_ids,
        'error': None,
    }
    root = Node('', 'key')
    try:
        inst = interp.instantiate(ci, [], {}, unknown_missing=True)
        collect, _ = interp.find_in_mro(ci, 'collect')
        bound = interp.bind(collect, inst, ci)
        facts_in = V(('dict',))
        facts_in.dyn = V(('any',))
        facts_in.dyn_name = '<fact>'
        result = interp.call(bound, [], {'module': V(objs=[('amod',)]), 'collected_facts': facts_in}, None, None)
        fill_node(root, result, (), frozenset())
    except BudgetExceeded:
        info['error'] = 'analysis budget exceeded'
    root.prune()
    return info, root


def analyze(lib: Path):
    """Analyze one extracted ansible-core tree; returns collectors, root Node, minimal subset."""
    index = Index(lib)
    collectors = []
    root = Node('', 'key')
    for modname, clsname in discover_collectors(index):
        info, tree = analyze_collector(index, modname, clsname)
        collectors.append(info)
        prefix = info['prefix']
        for n, c in tree.children.items():
            if c.kind == 'dyn':
                if prefix:
                    c.name = prefix + '<fact>'
                elif info['name'] == 'network':
                    c.name = '<interface>'
            elif prefix:
                c.name = prefix + n
            c.tag(info['platform'], info['name'])
            if c.name in root.children:
                root.children[c.name].merge(c)
            else:
                root.children[c.name] = c
    return {
        'index': index,
        'collectors': collectors,
        'root': root,
        'minimal_subset': minimal_gather_subset(index),
    }
