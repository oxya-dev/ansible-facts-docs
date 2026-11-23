"""Static analysis of the Windows ``setup`` module (``ansible.windows``: ``plugins/modules/setup.ps1``).

The module is a list of ``@{ Subsets = ...; Code = { ... } }`` entries whose script
blocks assign ``$ansibleFacts.ansible_<name> = <expression>``. This module tokenizes
the PowerShell source, finds those assignments, and infers the type and the data
source of each expression, following local variables, hashtable literals,
``@(...)`` arrays, pipelines, ``if``/``switch`` expressions and the C# helper
classes embedded in the module. Nothing is executed.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .analyzer import Node, Site, V, add_src, fill_node, is_dictish, merge_into, seq, str_v, union

FILE = 'ansible.windows/plugins/modules/setup.ps1'
PLATFORM = 'Windows'

TOKEN_RE = re.compile(r"""
 (?P<cont>`\r?\n)
|(?P<ws>[ \t\f\r]+)
|(?P<nl>\n)
|(?P<bcomment><\#.*?\#>)
|(?P<comment>\#[^\n]*)
|(?P<here>@'\r?\n.*?\r?\n'@|@"\r?\n.*?\r?\n"@)
|(?P<sq>'(?:[^']|'')*')
|(?P<dq>"(?:[^"`]|`.|"")*")
|(?P<sub>\$\()
|(?P<var>\$(?:\{[^}]*\}|[A-Za-z_]\w*(?::\w+)?|_|\?|\$|\^))
|(?P<splat>@[A-Za-z_]\w*)
|(?P<type>\[[A-Za-z_][\w.]*(?:\[[^\[\]]*\])?(?:\[\])?\])
|(?P<num>0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)
|(?P<op>-[A-Za-z]+)
|(?P<word>[A-Za-z_][\w-]*)
|(?P<punct>@\{|@\(|::|\.\.|[-+*/%]=|[{}()\[\],;=|.!&+\-*/%<>:])
""", re.S | re.X)

OPEN = {'{': '}', '(': ')', '[': ']', '@{': '}', '@(': ')', '$(': ')'}
CLOSE = {'}', ')', ']'}
BOOL_OPS = {'-and', '-or', '-xor', '-not', '-eq', '-ne', '-gt', '-ge', '-lt', '-le', '-like', '-notlike',
            '-match', '-notmatch', '-in', '-notin', '-contains', '-notcontains', '-is', '-isnot', '-ceq',
            '-cne', '-ccontains', '-cin', '-ieq', '-clike', '-ilike'}
CASTS = {'string': 'str', 'int': 'int', 'int32': 'int', 'int64': 'int', 'long': 'int', 'uint32': 'int',
         'uint64': 'int', 'bool': 'bool', 'boolean': 'bool', 'double': 'float', 'float': 'float',
         'decimal': 'float'}
STR_METHODS = {'tostring', 'trim', 'trimend', 'trimstart', 'toupper', 'tolower', 'toupperinvariant',
               'tolowerinvariant', 'replace', 'substring', 'padleft', 'padright', 'join', 'format'}
# Members of .NET / WMI / PowerShell objects read by the module (documented framework types).
MEMBER_TYPES = {
    'hostname': 'str', 'domainname': 'str', 'name': 'str', 'description': 'str', 'speed': 'int', 'mtu': 'int',
    'index': 'int', 'thumbprint': 'str', 'prefixlength': 'int', 'caption': 'str', 'osarchitecture': 'str',
    'installationtype': 'str', 'primaryownercontact': 'str', 'numberofcores': 'int',
    'numberoflogicalprocessors': 'int', 'numberofprocessors': 'int', 'major': 'int', 'minor': 'int',
    'count': 'int', 'length': 'int', 'key': 'str', 'ipaddresstostring': 'str', 'dnssuffix': 'str',
    'totalseconds': 'float', 'basename': 'str', 'fullname': 'str', 'extension': 'str',
    'sizestoredinpagingfiles': 'int', 'freespaceinpagingfiles': 'int', 'item1': 'int', 'item2': 'int',
    'id': 'str',
}
DATETIME_METHODS = {'touniversaltime', 'tolocaltime', 'addmilliseconds', 'addseconds', 'adddays', 'addhours'}


class Tok:
    __slots__ = ('kind', 'text', 'line', 'sp')

    def __init__(self, kind, text, line, sp):
        self.kind, self.text, self.line, self.sp = kind, text, line, sp

    def __repr__(self):
        return f'{self.kind}:{self.text!r}@{self.line}'

    @property
    def low(self):
        return self.text.lower()


def tokenize(src):
    toks, comments = [], {}
    line, sp, pos, line_has_code = 1, True, 0, False
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if m is None:  # unknown character: skip it
            pos += 1
            continue
        kind, text = m.lastgroup, m.group()
        pos = m.end()
        if kind in ('ws', 'cont'):
            sp = True
            line += text.count('\n')
            continue
        if kind in ('comment', 'bcomment'):
            if kind == 'comment':
                comments[line] = (text.lstrip('#').strip(), not line_has_code)
            line += text.count('\n')
            sp = True
            continue
        if kind == 'nl':
            toks.append(Tok('nl', '\n', line, sp))
            line += 1
            sp, line_has_code = True, False
            continue
        if kind == 'sub':
            kind, text = 'punct', '$('
        if kind == 'here':
            kind = 'str'
        elif kind in ('sq', 'dq'):
            kind = 'str' if kind == 'sq' else 'dstr'
        toks.append(Tok(kind, text, line, sp))
        line += text.count('\n')
        sp, line_has_code = False, True
    return toks, comments


def unquote(t):
    text = t.text
    if text.startswith("@'") or text.startswith('@"'):
        return text[3:-3]
    return text[1:-1].replace("''", "'") if text.startswith("'") else text[1:-1]


def csharp_members(src):
    """Field/property types of the C# helper classes embedded in the module."""
    classes = {}
    for m in re.finditer(r'public class (\w+)[^{]*\{', src):
        body_start = m.end()
        depth, i = 1, body_start
        while i < len(src) and depth:
            depth += src[i] == '{'
            depth -= src[i] == '}'
            i += 1
        members = {}
        for f in re.finditer(r'public ([\w<>,\[\]? ]+?) (\w+)\s*(?:;|=|\{\s*get)', src[body_start:i]):
            members[f.group(2).lower()] = _cs_type(f.group(1).strip())
        classes[m.group(1)] = members
    return classes


def _cs_type(t):
    t = t.rstrip('?')
    if t in ('string', 'String'):
        return 'str'
    if t in ('bool', 'Boolean'):
        return 'bool'
    if t in ('int', 'uint', 'long', 'ulong', 'short', 'byte', 'Int32', 'UInt32', 'Int64', 'UInt64', 'Int16'):
        return 'int'
    if t in ('double', 'float', 'decimal', 'Double'):
        return 'float'
    if t.startswith('List<') or t.endswith('[]'):
        return 'list'
    if t == 'DateTime':
        return 'datetime'
    return 'any'


def _snake(name):
    return re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', name).lower()


class Script:
    def __init__(self, src):
        self.src = src
        self.toks, self.comments = tokenize(src)
        self.classes = csharp_members(src)
        self.match = self._pairs()

    def _pairs(self):
        match, stack = {}, []
        for i, t in enumerate(self.toks):
            if t.kind == 'punct' and t.text in OPEN:
                stack.append(i)
            elif t.kind == 'punct' and t.text in CLOSE and stack:
                j = stack.pop()
                match[j] = i
                match[i] = j
        return match

    # ------------------------------------------------------------------ token helpers

    def is_p(self, i, *texts):
        t = self.toks[i] if 0 <= i < len(self.toks) else None
        return t is not None and t.kind == 'punct' and t.text in texts

    def skip_nl(self, a, b):
        while a < b and self.toks[a].kind == 'nl':
            a += 1
        while b > a and self.toks[b - 1].kind == 'nl':
            b -= 1
        return a, b

    def statements(self, a, b):
        """Split ``[a, b)`` into statement ranges at newlines/semicolons of depth 0."""
        out, start, i = [], a, a
        toks = self.toks
        while i < b:
            t = toks[i]
            if t.kind == 'punct' and t.text in OPEN and i in self.match:
                i = self.match[i] + 1
                continue
            if t.kind == 'nl' or (t.kind == 'punct' and t.text == ';'):
                prev = self._prev_sig(start, i)
                nxt = self._next_sig(i + 1, b)
                cont = (prev is not None and (self.is_p(prev, '|', ',', '=') or toks[prev].low in BOOL_OPS)) or \
                    (nxt is not None and toks[nxt].kind == 'word' and toks[nxt].low in ('elseif', 'else', 'catch', 'finally'))
                if t.kind == 'nl' and cont:
                    i += 1
                    continue
                s, e = self.skip_nl(start, i)
                if s < e:
                    out.append((s, e))
                start = i + 1
            i += 1
        s, e = self.skip_nl(start, b)
        if s < e:
            out.append((s, e))
        return out

    def _prev_sig(self, a, i):
        i -= 1
        while i >= a and self.toks[i].kind == 'nl':
            i -= 1
        return i if i >= a else None

    def _next_sig(self, i, b):
        while i < b and self.toks[i].kind == 'nl':
            i += 1
        return i if i < b else None

    def split_top(self, a, b, punct):
        parts, start, i = [], a, a
        while i < b:
            t = self.toks[i]
            if t.kind == 'punct' and t.text in OPEN and i in self.match:
                i = self.match[i] + 1
                continue
            if t.kind == 'punct' and t.text == punct:
                parts.append((start, i))
                start = i + 1
            i += 1
        parts.append((start, b))
        return [self.skip_nl(s, e) for s, e in parts]

    def assignment(self, s, e):
        """(target tokens, rhs start) if statement ``[s, e)`` is ``$var[.member...] = rhs``."""
        i = s
        toks = self.toks
        while i < e and toks[i].kind == 'type':
            i += 1
        if i >= e or toks[i].kind != 'var':
            return None
        target = [toks[i]]
        i += 1
        while i + 1 < e and self.is_p(i, '.') and toks[i + 1].kind in ('word', 'str', 'dstr', 'var'):
            target.append(toks[i + 1])
            i += 2
        if i < e and self.is_p(i, '=', '+='):
            return target, i + 1
        return None


class Block:
    """Variables and fact assignments of one ``Code`` script block (or of the whole script)."""

    def __init__(self, script, a, b, subset, parent=None):
        self.s = script
        self.subset = subset
        self.parent = parent
        self.vars = defaultdict(list)  # name -> [('expr', a, b) | ('item', a, b)]
        self.adds = defaultdict(list)  # name -> [(key a, key b, value a, value b, line)]: $h.Add(k, v)
        self.facts = []  # (target tokens, a, b, line)
        self._cache = {}
        self._busy = set()
        self.collect(a, b)

    def collect(self, a, b):
        s = self.s
        for st, en in s.statements(a, b):
            asg = s.assignment(st, en)
            if asg:
                target, rhs = asg
                name = target[0].text[1:].lower()
                if name == 'ansiblefacts' and len(target) > 1:
                    self.facts.append((target[1:], rhs, en, target[0].line))
                elif len(target) == 1 and name != 'null':
                    self.vars[name].append(('expr', rhs, en))
            t = s.toks[st]
            if t.kind == 'var' and s.is_p(st + 1, '.') and st + 3 < en and s.toks[st + 2].low == 'add' \
                    and s.is_p(st + 3, '(') and st + 3 in s.match:
                args = s.split_top(st + 4, s.match[st + 3], ',')
                if len(args) == 2:
                    self.adds[t.text[1:].lower()].append((*args[0], *args[1], t.line))
            if t.kind == 'word' and t.low == 'foreach' and s.is_p(st + 1, '('):
                close = s.match.get(st + 1)
                inner = s.toks[st + 2:close] if close else []
                if len(inner) >= 3 and inner[0].kind == 'var' and inner[1].low == 'in':
                    self.vars[inner[0].text[1:].lower()].append(('item', st + 4, close))
            # nested blocks: if/else bodies, try/catch, foreach bodies, @() arrays, scriptblocks
            i = st
            while i < en:
                if s.is_p(i, '{', '@(', '(', '$(') and i in s.match:
                    self.collect(i + 1, s.match[i])
                    i = s.match[i] + 1
                    continue
                i += 1

    # ------------------------------------------------------------------ inference

    def lookup(self, name):
        if name in self._cache:
            return self._cache[name]
        blk = self
        while blk is not None and name not in blk.vars:
            blk = blk.parent
        if blk is None or name in self._busy:
            return V(('any',))
        self._busy.add(name)
        try:
            vals = []
            for kind, a, b in blk.vars[name]:
                v = blk.infer(a, b)
                vals.append(blk.item_of(v) if kind == 'item' else v)
            out = union(*vals) if vals else V(('any',))
            for ka, kb, va, vb, line in blk.adds.get(name, ()):
                if not is_dictish(out):
                    break
                if out.dyn is None:
                    out.dyn, out.dyn_name = V(), '<key>'
                merge_into(out.dyn, blk.infer(va, vb))
                out.dyn_sites.add(Site(FILE, line, blk.subset))
        finally:
            self._busy.discard(name)
        self._cache[name] = out
        return out

    @staticmethod
    def item_of(v):
        if v.items is not None:
            return v.items
        if v.keys or v.dyn is not None:
            # enumerating a hashtable yields entries with .Key / .Value
            entry = V(('dict',))
            entry.keys['key'] = str_v(frozenset(v.keys) if v.keys else None)
            vals = list(v.keys.values()) + ([v.dyn] if v.dyn is not None else [])
            entry.keys['value'] = union(*vals) if vals else V(('any',))
            return entry
        return V(('any',), src=v.src)

    def infer(self, a, b, depth=0):
        s = self.s
        a, b = s.skip_nl(a, b)
        if a >= b:
            return V(('null',))
        if depth > 25:
            return V(('any',))
        toks = s.toks
        t = toks[a]
        if t.kind == 'word' and t.low in ('if', 'switch', 'foreach', 'try', 'for', 'while'):
            return self.outputs(a, b, depth, as_value=True)
        segs = s.split_top(a, b, '|')
        if len(segs) > 1:
            return self.pipeline(segs, depth)
        if t.kind == 'word' or s.is_p(a, '&'):
            return self.command(a, b, depth)
        return self.expression(a, b, depth)

    def outputs(self, a, b, depth, as_value=False):
        """Union of the values a statement list writes to the pipeline."""
        s = self.s
        vals = []
        for st, en in s.statements(a, b):
            t = s.toks[st]
            if s.assignment(st, en):
                continue
            if t.kind == 'word' and t.low in ('continue', 'break', 'throw', 'param'):
                continue
            if t.kind == 'word' and t.low == 'return':
                if en > st + 1:
                    vals.append(self.infer(st + 1, en, depth + 1))
                continue
            if t.kind == 'word' and t.low in ('if', 'switch', 'foreach', 'try', 'for', 'while'):
                vals.extend(self.branch_values(st, en, t.low, depth, add_null=as_value))
                continue
            vals.append(self.infer(st, en, depth + 1))
        if not vals:
            return V(('null',)) if as_value else V()
        return union(*vals)

    def branch_values(self, st, en, kw, depth, add_null=False):
        s = self.s
        vals, has_else, i = [], False, st
        while i < en:
            tk = s.toks[i]
            if tk.kind == 'word' and tk.low == 'else':
                has_else = True
            if s.is_p(i, '{') and i in s.match:
                close = s.match[i]
                if kw == 'switch' and not vals and s.toks[i - 1].kind != 'word':
                    # switch body: "<pattern> { value }" clauses
                    j = i + 1
                    while j < close:
                        if s.is_p(j, '{') and j in s.match:
                            if s.toks[j - 1].kind == 'word' and s.toks[j - 1].low == 'default':
                                has_else = True
                            v = self.outputs(j + 1, s.match[j], depth + 1)
                            if v.types or v.keys:
                                vals.append(v)
                            j = s.match[j] + 1
                            continue
                        j += 1
                    i = close + 1
                    continue
                v = self.outputs(i + 1, close, depth + 1)
                if v.types or v.keys or v.items is not None:
                    vals.append(v)
                i = close + 1
                continue
            i += 1
        if kw in ('if', 'switch') and not has_else and add_null:
            vals.append(V(('null',)))
        return vals

    def pipeline(self, segs, depth):
        v = self.infer(*segs[0], depth + 1)
        s = self.s
        for a, b in segs[1:]:
            if a >= b:
                continue
            cmd = s.toks[a].low
            args = s.toks[a + 1:b]
            if cmd in ('where-object', 'sort-object', 'where', '?'):
                continue
            if cmd in ('foreach-object', '%', 'foreach'):
                blk = next((j for j in range(a + 1, b) if s.is_p(j, '{')), None)
                if blk is not None and blk in s.match:
                    out = self.outputs(blk + 1, s.match[blk], depth + 1)
                    v = seq(items=out, src=v.src | out.src)
                continue
            if cmd == 'select-object':
                lows = {t.low for t in args}
                hashes = [j for j in range(a + 1, b) if s.is_p(j, '@{')]
                if hashes:
                    item = V(('dict',))
                    for j in hashes:
                        h = self.hashtable(j, depth)
                        keys = {k.lower(): cv for k, cv in h.keys.items()}
                        name = keys.get('n') or keys.get('name') or keys.get('label') or keys.get('l')
                        expr = keys.get('e') or keys.get('expression')
                        if name is not None and name.strs:
                            key = next(iter(name.strs))
                            val = expr if expr is not None else V(('any',))
                            item.keys[key] = val
                            item.ksites[key] = {Site(FILE, s.toks[j].line, self.subset)}
                    # PowerShell unrolls a single result: one object or an array of objects
                    out = seq(items=item, src=v.src)
                    merge_into(out, item)
                    out.types.add('dict')
                    v = out
                elif '-first' in lows or '-last' in lows:
                    v = self.item_of(v) if is_listish(v) else v
                continue
            if cmd == 'convertfrom-json':
                d = V(('dict',), src=v.src)
                d.dyn = V(('any',))
                d.dyn_name = '<key>'
                v = d
                continue
            if cmd == 'out-string':
                v = str_v(src=v.src)
                continue
            v = V(('any',), src=v.src)
        return v

    def command(self, a, b, depth):
        s = self.s
        toks = s.toks
        name = toks[a].low
        lows = [t.low for t in toks[a + 1:b]]
        src = self.sources(a, b)
        if name == 'get-date':
            src = src | {'pwsh:Get-Date'}
            if '-uformat' in lows or '-format' in lows:
                return str_v(src=src)
            return V(('any',), src=src, objs=[('datetime',)])
        if name in ('test-path',):
            return V(('bool',), src=src)
        if name in ('join-path',):
            return str_v(src=src)
        if name in ('get-content',):
            return str_v(src=src)
        if name == 'new-object' and '-typename' in lows:
            tn = ''.join(t.text for t in toks[a + 2 + lows.index('-typename'):b] if t.kind in ('word', 'punct')
                         and t.text not in ('-',)).split('-')[0]
            cls = tn.rsplit('.', 1)[-1]
            if cls in s.classes:
                return V(('any',), src=src, objs=[('cs', cls)])
            if cls == 'TimeSpan' or name == 'new-timespan':
                return V(('any',), src=src)
            return V(('any',), src=src)
        if name == 'new-timespan':
            return V(('any',), src=src, objs=[('cs', '__timespan')])
        return V(('any',), src=src)

    def expression(self, a, b, depth):
        s = self.s
        toks = s.toks
        # lowest precedence binary operators at depth 0
        ops = []
        i = a
        while i < b:
            t = toks[i]
            if t.kind == 'punct' and t.text in OPEN and i in s.match:
                i = s.match[i] + 1
                continue
            if t.kind == 'op' and i > a:
                ops.append((i, t.low))
            elif t.kind == 'punct' and t.text in ('+', '-', '*', '/', '%') and i > a and t.sp:
                ops.append((i, t.text))
            i += 1
        src = self.sources(a, b)
        for i, op in ops:
            if op in ('-and', '-or', '-xor'):
                return V(('bool',), src=src)
        for i, op in ops:
            if op in BOOL_OPS:
                return V(('bool',), src=src)
            if op in ('-replace', '-join', '-f'):
                return str_v(src=src)
            if op == '-split':
                return seq(items=str_v(src=src), src=src)
        arith = [op for _, op in ops if op in ('+', '-', '*', '/', '%')]
        if arith:
            if arith[0] == '+':
                left = self.expression(a, ops[0][0], depth + 1)
                if 'str' in left.types:
                    return str_v(src=src)
            return V(('int', 'float') if '/' in arith else ('int',), src=src)
        t = toks[a]
        if t.kind == 'op' and t.low == '-not' or s.is_p(a, '!'):
            return V(('bool',), src=src)
        # casts: [string]$x, [int]$y
        if t.kind == 'type' and not s.is_p(a + 1, '::'):
            name = t.text[1:-1].lower().split('.')[-1]
            if name in CASTS:
                return V((CASTS[name],), strs=frozenset(('\x00',)) if CASTS[name] == 'str' else None, src=src)
            if name.endswith('[]') or name in ('array',):
                return seq(src=src)
            return self.expression(a + 1, b, depth + 1) if a + 1 < b else V(('any',))
        v, i = self.primary(a, b, depth)
        return self.postfix(v, i, b, depth)

    def primary(self, a, b, depth):
        s = self.s
        toks = s.toks
        t = toks[a]
        if t.kind == 'type' and s.is_p(a + 1, '::') and a + 2 < b:
            tname = t.text[1:-1].split('.')[-1].lower()
            member = toks[a + 2].low
            src = self.sources(a, min(b, a + 3))
            i = a + 3
            args_end = None
            if s.is_p(i, '(') and i in s.match:
                args_end = s.match[i]
            if tname == 'math':
                v = V(('int',), src=self.sources(a, b) | src)
            elif tname == 'datetime' and member == 'now':
                v = V(('any',), src=src, objs=[('datetime',)])
            elif tname == 'datetime':
                v = V(('any',), src=self.sources(a, b), objs=[('datetime',)])
            elif tname == 'string':
                v = V(('bool',)) if member.startswith('is') else str_v(src=src)
            else:
                v = V(('any',), src=src)
            return v, (args_end + 1 if args_end is not None else i)
        if s.is_p(a, '(', '$(') and a in s.match:
            close = s.match[a]
            return self.infer(a + 1, close, depth + 1), close + 1
        if s.is_p(a, '@{') and a in s.match:
            return self.hashtable(a, depth), s.match[a] + 1
        if s.is_p(a, '@(') and a in s.match:
            close = s.match[a]
            out = self.outputs(a + 1, close, depth + 1)
            if 'list' in out.types and out.items is not None:
                # @() flattens what the inner pipelines emit
                flat = V()
                merge_into(flat, out.items)
                for t in out.types - {'list'}:
                    flat.types.add(t)
                out = flat
            return seq(items=out if (out.types or out.keys) else None, src=out.src), close + 1
        if t.kind == 'str':
            return str_v(frozenset((unquote(t),))), a + 1
        if t.kind == 'dstr':
            text = unquote(t)
            v = str_v(frozenset((text,)) if '$' not in text else None, self.sources(a, a + 1))
            return v, a + 1
        if t.kind == 'num':
            return V(('float',) if '.' in t.text else ('int',)), a + 1
        if t.kind == 'var':
            return self.variable(t), a + 1
        return V(('any',), src=self.sources(a, b)), b

    def variable(self, t):
        name = t.text[1:].strip('{}').lower()
        if name in ('true', 'false'):
            return V(('bool',))
        if name == 'null':
            return V(('null',))
        if name.startswith('env:'):
            return str_v(src={'env:' + name[4:].upper()})
        if name == 'psversiontable':
            return V(('any',), src={'pwsh:$PSVersionTable'})
        if name in ('_', 'psitem', 'args', 'this', 'module'):
            return V(('any',))
        return self.lookup(name)

    def postfix(self, v, i, b, depth):
        s = self.s
        toks = s.toks
        while i < b:
            t = toks[i]
            if s.is_p(i, '.') and not t.sp and i + 1 < b and toks[i + 1].kind in ('word', 'str', 'dstr', 'var'):
                name = toks[i + 1].text if toks[i + 1].kind == 'word' else None
                i += 2
                call = s.is_p(i, '(') and not toks[i].sp and i in s.match
                args_end = s.match[i] if call else None
                v = self.member(v, name, call)
                if call:
                    i = args_end + 1
                continue
            if s.is_p(i, '[') and not t.sp and i in s.match:
                v = self.item_of(v) if is_listish(v) else V(('any',), src=v.src)
                i = s.match[i] + 1
                continue
            break
        return v

    def member(self, v, name, call):
        if name is None:
            return V(('any',), src=v.src)
        low = name.lower()
        out = None
        if not call:
            for k, cv in v.keys.items():
                if k.lower() == low:
                    out = cv
                    break
            for o in v.objs:
                if o[0] == 'cs':
                    t = self.s.classes.get(o[1], {}).get(low)
                    if t is not None:
                        out = union(out, _typed(t)) if out is not None else _typed(t)
        if out is None:
            if call and low in STR_METHODS:
                out = str_v()
            elif call and low == 'split':
                out = seq(items=str_v())
            elif call and (low.startswith('is') or low in ('contains', 'startswith', 'endswith', 'equals')):
                out = V(('bool',))
            elif call and low in ('getenumerator',):
                return v
            elif call and low in DATETIME_METHODS:
                out = V(('any',), objs=[('datetime',)])
            elif low in MEMBER_TYPES:
                out = _typed(MEMBER_TYPES[low])
            else:
                out = V(('any',))
        res = V()
        merge_into(res, out)
        add_src(res, v.src)
        return res

    def hashtable(self, a, depth):
        s = self.s
        close = s.match[a]
        out = V(('dict',))
        for st, en in s.statements(a + 1, close):
            eq = next((j for j in range(st, en) if s.is_p(j, '=')), None)
            if eq is None or eq == st:
                continue
            key_tok = s.toks[st]
            if key_tok.kind == 'word':
                key = key_tok.text
            elif key_tok.kind in ('str', 'dstr'):
                key = unquote(key_tok)
            elif key_tok.kind == 'num':
                key = key_tok.text
            else:
                key = None
            val = self.infer(eq + 1, en, depth + 1)
            site = Site(FILE, key_tok.line, self.subset)
            if key is None or '$' in key:
                out.dyn = merge_into(out.dyn, val) if out.dyn is not None else val
                out.dyn_name = '<key>'
                out.dyn_sites.add(site)
            else:
                out.keys[key] = val
                out.ksites.setdefault(key, set()).add(site)
        return out

    def sources(self, a, b, depth=0, seen=None):
        """Data sources referenced by tokens ``[a, b)``, following variables."""
        s = self.s
        toks = s.toks
        seen = seen if seen is not None else set()
        out = set()
        for i in range(a, min(b, len(toks))):
            t = toks[i]
            if t.kind in ('str', 'dstr'):
                val = unquote(t)
                if re.match(r'(?i)(HKLM|HKCU|HKEY_[A-Z_]+):', val):
                    out.add('registry:' + val)
                elif re.match(r'(?i)(WSMan|Cert):', val):
                    out.add('provider:' + val)
            elif t.kind == 'op' and t.low == '-classname' and i + 1 < b and toks[i + 1].kind == 'word':
                out.add('wmi:' + toks[i + 1].text)
            elif t.kind == 'op' and t.low == '-typename' and i + 1 < b:
                j, parts = i + 1, []
                while j < b and (toks[j].kind == 'word' or (s.is_p(j, '.') and not toks[j].sp)):
                    parts.append(toks[j].text)
                    j += 1
                tn = ''.join(parts)
                if tn.startswith('Ansible.Windows.Setup.'):
                    out.add('native:' + tn.rsplit('.', 1)[-1])
            elif t.kind == 'type' and s.is_p(i + 1, '::') and i + 2 < b:
                tname = t.text[1:-1].split('.')[-1]
                if tname.lower() not in ('math', 'string', 'int', 'datetimekind', 'cultureinfo') and \
                        not tname.endswith('[]') and \
                        not tname.startswith('Ansible'):
                    member = toks[i + 2].text
                    call = '()' if s.is_p(i + 3, '(') else ''
                    out.add('dotnet:' + tname + '.' + member + call)
                elif t.text.startswith('[Ansible.Windows'):
                    out.add('native:' + toks[i + 2].text)
            elif t.kind == 'var':
                name = t.text[1:].strip('{}').lower()
                if name.startswith('env:'):
                    out.add('env:' + name[4:].upper())
                elif name == 'psversiontable':
                    out.add('pwsh:$PSVersionTable')
                elif depth < 4 and name not in seen and name not in ('module', 'ps'):
                    seen.add(name)
                    for blk, kind, va, vb in self._defs(name):
                        out |= blk.sources(va, vb, depth + 1, seen)
            elif t.kind == 'splat':
                name = t.text[1:].lower()
                if depth < 4 and name not in seen:
                    seen.add(name)
                    for blk, kind, va, vb in self._defs(name):
                        out |= blk.sources(va, vb, depth + 1, seen)
            elif s.is_p(i, '&') and i + 1 < b and toks[i + 1].kind == 'var':
                exe = set()
                for blk, kind, va, vb in self._defs(toks[i + 1].text[1:].lower()):
                    exe |= {unquote(x) for x in toks[va:vb] if x.kind == 'str' and unquote(x).lower().endswith('.exe')}
                    exe |= {x.text for x in toks[va:vb] if x.kind == 'word' and x.low.endswith('.exe')}
                rest = ' '.join(x.text for x in toks[i + 2:b] if x.kind in ('op', 'word'))
                for e in sorted(exe) or ['…']:
                    out.add(('cmd:' + e + ' ' + rest).strip())
        return out

    def _chain(self):
        blk = self
        while blk is not None:
            yield blk
            blk = blk.parent

    def _defs(self, name):
        """Definitions of a variable in the innermost block that assigns it."""
        for blk in self._chain():
            if name in blk.vars:
                return [(blk, kind, a, b) for kind, a, b in blk.vars[name]]
        return []


def is_listish(v):
    return 'list' in v.types or v.items is not None


def _typed(t):
    if t == 'str':
        return str_v()
    if t == 'datetime':
        return V(('any',), objs=[('datetime',)])
    if t == 'list':
        return seq()
    return V((t,))


# ---------------------------------------------------------------------- entry point


def _meta_entries(script):
    """(subsets, code start, code end) for each entry of ``$factMeta = @(...)``."""
    toks = script.toks
    out = []
    for i, t in enumerate(toks):
        if t.kind == 'var' and t.low == '$factmeta' and script.is_p(i + 1, '=') and script.is_p(i + 2, '@('):
            close = script.match[i + 2]
            j = i + 3
            while j < close:
                if script.is_p(j, '@{'):
                    end = script.match[j]
                    subsets, code = [], None
                    for st, en in script.statements(j + 1, end):
                        key = toks[st].low
                        if key == 'subsets':
                            subsets = [unquote(x) for x in toks[st + 2:en] if x.kind in ('str', 'dstr')]
                        elif key == 'code' and script.is_p(st + 2, '{'):
                            code = (st + 3, script.match[st + 2])
                    if code:
                        out.append((subsets, code[0], code[1]))
                    j = end + 1
                    continue
                j += 1
            break
    return out


def _grouped_subsets(script):
    toks = script.toks
    groups = {}
    for i, t in enumerate(toks):
        if t.kind == 'var' and t.low == '$groupedsubsets' and script.is_p(i + 1, '=') and script.is_p(i + 2, '@{'):
            for st, en in script.statements(i + 3, script.match[i + 2]):
                if toks[st].kind == 'word':
                    groups[toks[st].text] = [unquote(x) for x in toks[st:en] if x.kind == 'str']
            break
    return groups


def _fact_name(target, block):
    """Name of the top-level fact (without ``ansible_``) and the nested member path."""
    first = target[0]
    if first.kind == 'word':
        name = first.text
    elif first.kind in ('str', 'dstr'):
        name = re.sub(r'\$\(\$(\w+)\.\w+\)|\$(\w+)', lambda m: '<' + _snake(m.group(1) or m.group(2)) + '>',
                      unquote(first))
    else:
        name = '<' + _snake(first.text[1:]) + '>'
    if name.startswith('ansible_'):
        name = name[len('ansible_'):]
    rest = []
    for t in target[1:]:
        rest.append(t.text if t.kind == 'word' else '<' + _snake(t.text.lstrip('$')) + '>')
    return name, rest


class Comments:
    def __init__(self, comments):
        self._c = comments

    def comments(self):
        return self._c


def analyze(path: Path):
    """Analyze ``setup.ps1``; returns the Windows fact tree and module metadata."""
    src = path.read_text(encoding='utf-8-sig')
    script = Script(src)
    top = Block(script, 0, len(script.toks), 'setup')
    root = Node('', 'key')
    entries = _meta_entries(script)
    code_ranges = [(a, b) for _, a, b in entries]

    def add(facts, block, subsets):
        tree = V(('dict',))
        for target, a, b, line in facts:
            name, rest = _fact_name(target, block)
            val = block.infer(a, b)
            add_src(val, block.sources(a, b))
            site = Site(FILE, line, ', '.join(subsets))
            node = tree
            for seg in ([name] + rest)[:-1]:
                if seg.startswith('<'):
                    if node.dyn is None:
                        node.dyn, node.dyn_name = V(('dict',)), seg
                    node = node.dyn
                else:
                    node = node.keys.setdefault(seg, V(('dict',)))
            last = ([name] + rest)[-1]
            if last.startswith('<') and rest:
                node.dyn = merge_into(node.dyn, val) if node.dyn is not None else val
                node.dyn_name = last
                node.dyn_sites.add(site)
            elif last.startswith('<') or ('<' in last and not rest):
                key = last
                cur = node.keys.get(key)
                node.keys[key] = merge_into(cur, val) if cur is not None else val
                node.ksites.setdefault(key, set()).add(site)
            else:
                cur = node.keys.get(last)
                node.keys[last] = merge_into(cur, val) if cur is not None else val
                node.ksites.setdefault(last, set()).add(site)
        sub = Node('', 'key')
        fill_node(sub, tree, (), frozenset())
        sub.prune()
        for n, c in sub.children.items():
            if '<' in n:
                c.kind = 'dyn'
            for subset in subsets:
                c.tag(PLATFORM, subset)
            if n in root.children:
                root.children[n].merge(c)
            else:
                root.children[n] = c

    for subsets, a, b in entries:
        blk = Block(script, a, b, ', '.join(subsets), parent=top)
        add(blk.facts, blk, subsets)
    # facts set outside the Code blocks: gather_subset, module_setup, measure_info
    outside = [f for f in top.facts if not any(a <= f[1] < b for a, b in code_ranges)]
    # $ansibleFacts = @{ gather_subset = ...; module_setup = $true }
    for kind, a, b in top.vars.get('ansiblefacts', ()):
        a, _ = script.skip_nl(a, b)
        if script.is_p(a, '@{') and a in script.match:
            for st, en in script.statements(a + 1, script.match[a]):
                eq = next((j for j in range(st, en) if script.is_p(j, '=')), None)
                if eq is not None and script.toks[st].kind == 'word':
                    outside.append(([script.toks[st]], eq + 1, en, script.toks[st].line))
    add(outside, top, ['gather_subset'])
    groups = _grouped_subsets(script)
    return {
        'root': root,
        'minimal_subset': sorted(groups.get('min', [])),
        'groups': {k: sorted(v) for k, v in groups.items()},
        'sources': {FILE: Comments(script.comments)},
    }


def merge(result, win):
    """Add the Windows facts to an analyzed ansible-core tree."""
    root = result['root']
    for name, node in win['root'].children.items():
        if name in root.children:
            root.children[name].merge(node)
        else:
            root.children[name] = node
    result['sources'].update(win['sources'])
