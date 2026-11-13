/* ------------------------------------------------------------------------- *
 * A linear-time regular-expression engine.
 *
 * This runs the vendored GuardVibe patterns in place of V8's own engine,
 * because V8 backtracks: on the inputs these rules meet in real repositories,
 * several went from milliseconds to minutes. It knows nothing about GuardVibe,
 * about scanning, or about this project's rule set -- it takes an arbitrary
 * `RegExp` and runs it without super-linear blowup, and `matcherFor` falls back
 * to V8 for the patterns it cannot compile.
 *
 * Extracted from `community.ts` as a Rule 26 step 7 refactor (2026-11-13). It
 * was 1,356 of that file's 2,973 lines and shared nothing with the rest of it
 * but three names, which is what makes it a separate responsibility: the
 * scanner decides *what to look for*, this decides *how to look*.
 *
 * The parts, in the order they run. `parsePattern` reads the pattern source
 * into a `ReNode` tree; `collapseRuns` rewrites the shapes that make V8
 * backtrack into single `RUN` instructions; `compilePattern` emits the
 * instruction program; `LinearMatcher` executes it, memoising
 * (state, position) pairs so no pair is ever tried twice, which is what bounds
 * the work. `LinearMatcher.steps` counts executed instructions so the ReDoS
 * tests can assert on work done rather than on elapsed milliseconds -- see
 * `test/redos-overrides.test.js`.
 * ------------------------------------------------------------------------- */

import { commentStyleFor } from '../utils/spans.js';

class UnsupportedPattern extends Error {}

type ReNode =
  | { t: 'alt'; alts: ReNode[]; raw: string }
  | { t: 'seq'; items: ReNode[]; raw: string }
  | { t: 'char'; raw: string }
  | { t: 'assert'; kind: string; raw: string }
  | { t: 'group'; body: ReNode; raw: string }
  | { t: 'look'; behind: boolean; neg: boolean; body: ReNode; raw: string }
  | { t: 'quant'; min: number; max: number; lazy: boolean; body: ReNode; raw: string };

type AltNode = Extract<ReNode, { t: 'alt' }>;

/**
 * A parse of the regex syntax the vendored patterns use (no `u` or `v` flag).
 * Anything else — a backreference, a quantified assertion — throws
 * UnsupportedPattern, and that pattern is left to V8.
 */
function parsePattern(src: string): ReNode {
  let i = 0;
  const at = (s: string) => src.startsWith(s, i);
  function alt(): AltNode {
    const start = i;
    const alts = [seq()];
    while (src[i] === '|') {
      i++;
      alts.push(seq());
    }
    return { t: 'alt', alts, raw: src.slice(start, i) };
  }
  function seq(): ReNode {
    const start = i;
    const items: ReNode[] = [];
    while (i < src.length && src[i] !== '|' && src[i] !== ')') items.push(term());
    return { t: 'seq', items, raw: src.slice(start, i) };
  }
  function quantifier(): [number, number, number] | null {
    const c = src[i];
    if (c === '*') return [0, Infinity, 1];
    if (c === '+') return [1, Infinity, 1];
    if (c === '?') return [0, 1, 1];
    if (c !== '{') return null;
    const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i, i + 24));
    if (!m) return null; // Annex B: a `{` that is not a quantifier is a literal.
    const min = Number(m[1]);
    const max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
    return [min, max, m[0].length];
  }
  function term(): ReNode {
    const start = i;
    const c = src[i]!;
    let atom: ReNode;
    if (c === '^' || c === '$') {
      i++;
      atom = { t: 'assert', kind: c, raw: c };
    } else if (c === '(') {
      let kind = 'group';
      if (at('(?:')) i += 3;
      else if (at('(?=')) (kind = 'ahead'), (i += 3);
      else if (at('(?!')) (kind = 'nahead'), (i += 3);
      else if (at('(?<=')) (kind = 'behind'), (i += 4);
      else if (at('(?<!')) (kind = 'nbehind'), (i += 4);
      else if (at('(?<')) i = src.indexOf('>', i) + 1;
      else i += 1;
      const body = alt();
      if (src[i] !== ')') throw new UnsupportedPattern('unbalanced group');
      i++;
      const raw = src.slice(start, i);
      atom =
        kind === 'group'
          ? { t: 'group', body, raw }
          : { t: 'look', behind: kind.endsWith('behind'), neg: kind.startsWith('n'), body, raw };
    } else if (c === '[') {
      let j = i + 1;
      if (src[j] === '^') j++;
      while (j < src.length && src[j] !== ']') j += src[j] === '\\' ? 2 : 1;
      if (j >= src.length) throw new UnsupportedPattern('unterminated class');
      i = j + 1;
      atom = { t: 'char', raw: src.slice(start, i) };
    } else if (c === '\\') {
      const d = src[i + 1] ?? '';
      if (d === 'b' || d === 'B') {
        i += 2;
        atom = { t: 'assert', kind: d, raw: src.slice(start, i) };
      } else if (/[1-9kpP]/.test(d)) {
        throw new UnsupportedPattern(`\\${d}`);
      } else {
        if (d === 'x' && /^[0-9a-fA-F]{2}$/.test(src.slice(i + 2, i + 4))) i += 4;
        else if (d === 'u' && /^[0-9a-fA-F]{4}$/.test(src.slice(i + 2, i + 6))) i += 6;
        else if (d === 'c' && /^[A-Za-z]$/.test(src[i + 2] ?? '')) i += 3;
        else i += 2;
        atom = { t: 'char', raw: src.slice(start, i) };
      }
    } else {
      i++;
      atom = { t: 'char', raw: c };
    }
    const q = quantifier();
    if (!q) return atom;
    if (atom.t === 'assert' || atom.t === 'look') throw new UnsupportedPattern('quantified assertion');
    i += q[2];
    const lazy = src[i] === '?';
    if (lazy) i++;
    return { t: 'quant', min: q[0], max: q[1], lazy, body: atom, raw: src.slice(start, i) };
  }
  const ast = alt();
  if (i !== src.length) throw new UnsupportedPattern('unbalanced group');
  return ast;
}

/** A code-unit table for one single-character atom, filled on demand by V8's own verdict. */
interface CharMap {
  key: string;
  map: Uint8Array; // 0 unknown, 1 in, 2 out
  re: RegExp;
}

const CHAR_MAPS = new Map<string, CharMap>();

function charMap(raw: string, flags: string): CharMap {
  const key = flags + '\u0000' + raw;
  let cm = CHAR_MAPS.get(key);
  if (!cm) {
    cm = { key, map: new Uint8Array(65536), re: new RegExp('^(?:' + raw + ')$', flags) };
    CHAR_MAPS.set(key, cm);
  }
  return cm;
}

function inMap(cm: CharMap, c: number): boolean {
  let v = cm.map[c]!;
  if (v === 0) cm.map[c] = v = cm.re.test(String.fromCharCode(c)) ? 1 : 2;
  return v === 1;
}

let ALL_CODE_UNITS: string | null = null;
const DISJOINT = new Map<string, boolean>();

/**
 * The code units a single literal character atom (`a`, `\(`) matches: itself,
 * and its other case under `i` — which, without the `u` flag, only ever folds
 * ASCII to ASCII. Null for anything else.
 */
function literalUnits(raw: string, flags: string): string[] | null {
  let ch: string;
  if (raw.length === 1 && !'.^$|?*+()[]{}\\'.includes(raw)) ch = raw;
  else if (raw.length === 2 && raw[0] === '\\' && /[^A-Za-z0-9]/.test(raw[1]!)) ch = raw[1]!;
  else return null;
  const re = new RegExp('^(?:' + raw + ')$', flags);
  return [...new Set([ch, ch.toLowerCase(), ch.toUpperCase()])].filter((c) => c.length === 1 && re.test(c));
}

/** Whether no code unit matches both `raw` and one of `others` — asked of V8. */
function disjoint(raw: string, others: readonly string[], flags: string): boolean {
  const key = flags + '\u0000' + raw + '\u0000' + others.join('\u0001');
  let v = DISJOINT.get(key);
  if (v !== undefined) return v;
  // Mostly one side is a literal character: then only its few code units need asking about.
  const mine = literalUnits(raw, flags);
  const theirs = others.map((o) => literalUnits(o, flags));
  if (mine !== null) {
    const re = new RegExp('^(?:' + others.join('|') + ')$', flags);
    v = !mine.some((c) => re.test(c));
  } else if (theirs.every((t) => t !== null)) {
    const re = new RegExp('^(?:' + raw + ')$', flags);
    v = !theirs.some((t) => t!.some((c) => re.test(c)));
  }
  if (v === undefined) {
    if (ALL_CODE_UNITS === null) {
      const units: string[] = [];
      for (let c = 0; c < 65536; c++) units.push(String.fromCharCode(c));
      ALL_CODE_UNITS = units.join('');
    }
    v = !new RegExp('(?=' + raw + ')(?:' + others.join('|') + ')', flags).test(ALL_CODE_UNITS);
  }
  DISJOINT.set(key, v);
  return v;
}

function nullable(n: ReNode): boolean {
  switch (n.t) {
    case 'alt':
      return n.alts.some(nullable);
    case 'seq':
      return n.items.every(nullable);
    case 'char':
      return false;
    case 'group':
      return nullable(n.body);
    case 'look':
    case 'assert':
      return true;
    case 'quant':
      return n.min === 0 || nullable(n.body);
  }
}

/**
 * Whether V8 can evaluate `n` at every position of a text in linear total
 * time. Every quantifier has to be small, except a run of one class C fenced
 * on both sides by characters outside C: the character before it anchors each
 * attempt that reads the run (and cannot occur inside it, so no attempt starts
 * part-way along), and the one after gives the run exactly one place to end.
 * A run like that is read by a bounded number of attempts however long it is.
 * `readFile\s*\(` passes; `readFile\s*\([^)]*req\.` does not — every `(` in
 * a run of them starts its own read of the rest.
 */
function evaluatesLinearly(n: ReNode, flags: string): boolean {
  const outside = (x: ReNode, raw: string) => x.t === 'char' && disjoint(x.raw, [raw], flags);
  const endsOutside = (x: ReNode, raw: string): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => endsOutside(a, raw));
      case 'seq':
        return x.items.length > 0 && endsOutside(x.items[x.items.length - 1]!, raw);
      case 'group':
        return endsOutside(x.body, raw);
      default:
        return outside(x, raw);
    }
  };
  const startsOutside = (x: ReNode, raw: string): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => startsOutside(a, raw));
      case 'seq':
        return x.items.length > 0 && startsOutside(x.items[0]!, raw);
      case 'group':
        return startsOutside(x.body, raw);
      case 'quant':
        return x.min >= 1 && startsOutside(x.body, raw);
      default:
        return outside(x, raw);
    }
  };
  const ok = (x: ReNode, atEnd: boolean): boolean => {
    switch (x.t) {
      case 'alt':
        return x.alts.every((a) => ok(a, atEnd));
      case 'seq':
        return x.items.every((it, i) => {
          if (it.t === 'quant' && it.max > 16) {
            if (it.body.t !== 'char') return false;
            const prev = x.items[i - 1];
            const next = x.items[i + 1];
            if (prev === undefined || !endsOutside(prev, it.body.raw)) return false;
            return next === undefined ? atEnd : startsOutside(next, it.body.raw);
          }
          return ok(it, atEnd && i === x.items.length - 1);
        });
      case 'group':
        return ok(x.body, atEnd);
      case 'char':
      case 'assert':
        return true;
      case 'look':
        return ok(x.body, true);
      case 'quant':
        return x.max <= 16 && ok(x.body, false);
    }
  };
  return ok(n, true);
}

// --- Filters -----------------------------------------------------------------
//
// Cheap, necessary conditions, run by V8: a match can only start where
// `prefixOf` matches, and a gap can only end where what follows it can start.

const SMALL = 16;

function cheap(n: ReNode): boolean {
  switch (n.t) {
    case 'alt':
      return n.alts.every(cheap);
    case 'seq':
      return n.items.every(cheap);
    case 'group':
      return cheap(n.body);
    case 'char':
    case 'assert':
      return true;
    case 'look':
      return false;
    case 'quant':
      return n.max <= SMALL && cheap(n.body);
  }
}

/** [source, complete]: a cheap regex that matches wherever `n` can start a match. */
function prefixOf(n: ReNode): [string, boolean] {
  switch (n.t) {
    case 'alt': {
      const parts = n.alts.map(prefixOf);
      if (parts.some((p) => p[0] === '')) return ['', false];
      return ['(?:' + parts.map((p) => p[0]).join('|') + ')', parts.every((p) => p[1])];
    }
    case 'seq': {
      let s = '';
      for (let i = 0; i < n.items.length; i++) {
        const it = n.items[i]!;
        const [p, complete] = prefixOf(it);
        if (complete) {
          s += p;
          continue;
        }
        // An optional item that is not cheap: either it starts here or what
        // follows it does.
        if (it.t === 'quant' && it.min === 0 && p === '') {
          const [a] = prefixOf(it.body);
          const [b] = prefixOf({ t: 'seq', items: n.items.slice(i + 1), raw: '' });
          if (a !== '' && b !== '' && a.length + b.length < 600) return [s + '(?:' + a + '|' + b + ')', false];
        }
        return [s + p, false];
      }
      return [s, true];
    }
    case 'group': {
      const [p, complete] = prefixOf(n.body);
      return [p === '' ? '' : '(?:' + p + ')', complete];
    }
    case 'char':
    case 'assert':
      return [n.raw, true];
    case 'look':
      return ['', true]; // dropped: a weaker condition, still a necessary one
    case 'quant':
      return n.max <= SMALL && cheap(n.body) ? [n.raw, true] : ['', false];
  }
}

/** [source, score]: a regex matching somewhere inside every match, scored by its literal characters. */
function requiredText(n: ReNode): [string, number] | null {
  const literal = (x: ReNode) => x.t === 'char' && !/^(?:\[|\.$|\\[dDsSwWbBtnrvf0-9xuc])/.test(x.raw);
  switch (n.t) {
    case 'char':
      return [n.raw, literal(n) ? 1 : 0];
    case 'group':
      return requiredText(n.body);
    case 'quant':
      return n.min >= 1 ? requiredText(n.body) : null;
    case 'alt': {
      const parts = n.alts.map(requiredText);
      if (parts.some((p) => p === null)) return null;
      const all = parts as [string, number][];
      if (all.length === 1) return all[0]!;
      return ['(?:' + all.map((p) => p[0]).join('|') + ')', Math.min(...all.map((p) => p[1]))];
    }
    case 'seq': {
      let best: [string, number] | null = null;
      let run = '';
      let score = 0;
      const close = () => {
        if (run !== '' && (best === null || score > best[1])) best = [run, score];
        run = '';
        score = 0;
      };
      for (const it of n.items) {
        if (it.t === 'char') {
          run += it.raw;
          score += literal(it) ? 1 : 0;
          continue;
        }
        close();
        const r = requiredText(it);
        if (r !== null && (best === null || r[1] > best[1])) best = r;
      }
      close();
      return best;
    }
    default:
      return null;
  }
}

/** The single-character atoms `n` can begin with (null: unknown), and whether it can match empty. */
function firstAtoms(n: ReNode): { atoms: string[] | null; empty: boolean } {
  switch (n.t) {
    case 'char':
      return { atoms: [n.raw], empty: false };
    case 'assert':
    case 'look':
      return { atoms: [], empty: true };
    case 'group':
      return firstAtoms(n.body);
    case 'quant': {
      const f = firstAtoms(n.body);
      return { atoms: f.atoms, empty: f.empty || n.min === 0 };
    }
    case 'alt': {
      const fs = n.alts.map(firstAtoms);
      const empty = fs.some((f) => f.empty);
      if (fs.some((f) => f.atoms === null)) return { atoms: null, empty };
      return { atoms: [...new Set(fs.flatMap((f) => f.atoms!))], empty };
    }
    case 'seq': {
      const atoms = new Set<string>();
      for (const it of n.items) {
        const f = firstAtoms(it);
        if (f.atoms === null) return { atoms: null, empty: false };
        for (const a of f.atoms) atoms.add(a);
        if (!f.empty) return { atoms: [...atoms], empty: false };
      }
      return { atoms: [...atoms], empty: true };
    }
  }
}

/** What must follow a point in the pattern: its prefix, and the atoms it can start with (null: anything, or nothing). */
interface Continuation {
  src: string;
  complete: boolean;
  first: string[] | null;
}

const PATTERN_END: Continuation = { src: '', complete: true, first: null };

function precede(item: ReNode, cont: Continuation): Continuation {
  const f = firstAtoms(item);
  let first: string[] | null;
  if (!f.empty) first = f.atoms;
  else if (cont.first === null || f.atoms === null) first = null;
  else first = [...new Set([...f.atoms, ...cont.first])];
  if (first !== null && first.length > 64) first = null;
  const [s, complete] = prefixOf(item);
  if (!complete || s.length + cont.src.length > 400) return { src: s, complete: false, first };
  return { src: s + cont.src, complete: cont.complete, first };
}

/** A leading atom that matches most characters filters nothing. */
const BROAD = /^(?:\[\^|\.|\\[SWD]|\[\\[sSwWdD]\\[sSwWdD]\])/;

/** Classes that match every code unit. */
const UNIVERSAL = new Set(['[\\s\\S]', '[\\S\\s]', '[^]', '[\\w\\W]', '[\\W\\w]', '[\\d\\D]', '[\\D\\d]']);

interface FirstMap {
  cms: CharMap[];
  map: Uint8Array;
}

const FIRST_MAPS = new Map<string, FirstMap>();

function firstMap(atoms: string[] | null, flags: string): FirstMap | null {
  if (atoms === null || atoms.length === 0 || atoms.some((a) => BROAD.test(a))) return null;
  const key = flags + '\u0000' + atoms.join('\u0001');
  let f = FIRST_MAPS.get(key);
  if (f === undefined) {
    f = { cms: atoms.map((a) => charMap(a, flags)), map: new Uint8Array(65536) };
    FIRST_MAPS.set(key, f);
  }
  return f;
}

function inFirst(f: FirstMap, c: number): boolean {
  let v = f.map[c]!;
  if (v === 0) f.map[c] = v = f.cms.some((cm) => inMap(cm, c)) ? 1 : 2;
  return v === 1;
}

// --- Program -----------------------------------------------------------------

const CHAR = 0;
const SPLIT = 1;
const ASSERT = 2;
const LOOK = 3;
/** A run of one class (`\s*`, `[^)]{0,200}?`, a tempered `(?:(?!x)[\s\S])*`) with a choice of ends. */
const GAP = 4;
const MATCH = 5;
/** A gap whose only viable end is where its run ends: what follows cannot start inside it. */
const RUN = 6;

/** A zero-width regex for where a continuation can start: its prefix, or else its first atoms. */
function seekFor(cont: Continuation, flags: string): RegExp | null {
  let src: string | null = null;
  if (cont.src !== '' && !BROAD.test(cont.src)) src = cont.src;
  else if (cont.first !== null && cont.first.length > 0 && !cont.first.some((a) => BROAD.test(a))) src = cont.first.join('|');
  return src === null ? null : new RegExp('(?=(?:' + src + '))', flags + 'g');
}

/** Every instruction has one shape, so the matcher's property reads stay monomorphic. */
interface Ins {
  op: number;
  next: number;
  /** SPLIT: preferred and fallback branches; memoized when it heads a loop. */
  x: number;
  y: number;
  memo: boolean;
  /** SPLIT: the atom the preferred branch must open with, to skip it without a frame. */
  xFirst: CharMap | null;
  /** SPLIT: no other branch can start where this one's first atom matches. */
  commit: boolean;
  cm: CharMap | null;
  kind: string;
  /** LOOK: evaluated by V8 (lookbehinds, and lookaheads it evaluates linearly). */
  re: RegExp | null;
  neg: boolean;
  /** LOOK: subprogram, when V8 cannot be trusted with it. */
  sub: number;
  /** GAP/RUN (tempered): the forbidden-word subprogram, or V8's regex for it. */
  forbid: number;
  forbidRe: RegExp | null;
  forbidKey: string;
  min: number;
  max: number;
  lazy: boolean;
  /** GAP: the atoms the continuation can start with. */
  first: FirstMap | null;
  /** GAP: a zero-width regex V8 can use to find the next place the continuation can start. */
  seek: RegExp | null;
  universal: boolean;
  // Per-text caches: the break and forbidden-word lists, the last run end asked for.
  listGen: number;
  forbidList: Positions | null;
  breakList: Positions | null;
  lastGen: number;
  lastQ: number;
  lastEnd: number;
}

function instruction(o: Partial<Ins> & { op: number }): Ins {
  return {
    op: o.op,
    next: o.next ?? -1,
    x: o.x ?? -1,
    y: o.y ?? -1,
    memo: o.memo ?? false,
    xFirst: o.xFirst ?? null,
    commit: o.commit ?? false,
    cm: o.cm ?? null,
    kind: o.kind ?? '',
    re: o.re ?? null,
    neg: o.neg ?? false,
    sub: o.sub ?? -1,
    forbid: o.forbid ?? -1,
    forbidRe: o.forbidRe ?? null,
    forbidKey: o.forbidKey ?? '',
    min: o.min ?? 0,
    max: o.max ?? 0,
    lazy: o.lazy ?? false,
    first: o.first ?? null,
    seek: o.seek ?? null,
    universal: o.universal ?? false,
    listGen: 0,
    forbidList: null,
    breakList: null,
    lastGen: 0,
    lastQ: 0,
    lastEnd: 0,
  };
}

/**
 * `\s*\{?\s*` as `\s*(?:\{\s*)?`. Whenever the optional item is skipped, the
 * second run can only re-read what the first, greedy, already consumed and
 * gave back — and since the optional item cannot start inside the run, it is
 * skipped everywhere but the run's end. Both spellings then try what follows
 * at the run's end first and one position further back each time; the second
 * does it without re-entering a second gap at every position, which halves
 * the work on a long run of whitespace in the patterns that are full of these.
 */
function collapseRuns(n: ReNode, flags: string): ReNode {
  switch (n.t) {
    case 'alt':
      return { ...n, alts: n.alts.map((a) => collapseRuns(a, flags)) };
    case 'group':
    case 'look':
    case 'quant':
      return { ...n, body: collapseRuns(n.body, flags) } as ReNode;
    case 'seq': {
      const items = n.items.map((it) => collapseRuns(it, flags));
      const greedyRun = (x: ReNode | undefined): x is Extract<ReNode, { t: 'quant' }> =>
        x !== undefined && x.t === 'quant' && x.body.t === 'char' && x.max === Infinity && !x.lazy;
      // `\s*[^,]+` as `[^,]+`: two greedy runs side by side, one optional and
      // its class inside the other's. Together they consume exactly what the
      // wider one alone does, and try what follows at the same ends in the
      // same order (furthest first), so the narrower one only costs time.
      const within = (a: string, b: string) => disjoint(a, ['(?!' + b + ')[\\s\\S]'], flags);
      for (let i = 0; i + 1 < items.length; ) {
        const [a, b] = [items[i], items[i + 1]];
        if (greedyRun(a) && greedyRun(b)) {
          if (a.min === 0 && within(a.body.raw, b.body.raw)) {
            items.splice(i, 1);
            continue;
          }
          if (b.min === 0 && within(b.body.raw, a.body.raw)) {
            items.splice(i + 1, 1);
            continue;
          }
        }
        i++;
      }
      for (let i = 0; i + 2 < items.length; i++) {
        const [g1, o, g2] = [items[i], items[i + 1]!, items[i + 2]];
        if (!greedyRun(g1) || !greedyRun(g2) || g2.min !== 0 || g1.body.raw !== g2.body.raw) continue;
        if (o.t !== 'quant' || o.min !== 0 || o.max !== 1 || o.lazy || nullable(o.body)) continue;
        const f = firstAtoms(o.body);
        if (f.atoms === null || f.atoms.length === 0 || !disjoint(g1.body.raw, f.atoms, flags)) continue;
        const raw = '(?:' + o.body.raw + g2.raw + ')';
        const body: ReNode = {
          t: 'group',
          raw,
          body: { t: 'alt', raw: raw.slice(3, -1), alts: [{ t: 'seq', raw: raw.slice(3, -1), items: [o.body, g2] }] },
        };
        items.splice(i + 1, 2, { t: 'quant', min: 0, max: 1, lazy: false, body, raw: raw + '?' });
      }
      return { ...n, items };
    }
    default:
      return n;
  }
}

/** Compiles to a program whose paths, taken in order, are the paths V8 takes. */
function compilePattern(ast: ReNode, flags: string): { prog: Ins[]; start: number } {
  const prog: Ins[] = [];
  const cflags = flags.replace(/[gy]/g, '');
  const sflags = cflags.replace('m', '');
  const emit = (o: Partial<Ins> & { op: number }) => (prog.push(instruction(o)), prog.length - 1);
  const match = emit({ op: MATCH });
  const sticky = (n: ReNode) => new RegExp('(?:' + n.raw + ')', cflags + 'y');
  const firstOf = (pc: number) => (prog[pc]!.op === CHAR ? prog[pc]!.cm : null);

  const tempered = (b: ReNode) => {
    if (b.t !== 'group' || b.body.t !== 'alt' || b.body.alts.length !== 1) return null;
    const only = b.body.alts[0]!;
    if (only.t !== 'seq' || only.items.length !== 2) return null;
    const [look, ch] = only.items as [ReNode, ReNode];
    return look.t === 'look' && !look.behind && look.neg && ch.t === 'char' ? { look, ch } : null;
  };

  function unroll(n: Extract<ReNode, { t: 'quant' }>, next: number, cont: Continuation): number {
    const b = n.body;
    if (nullable(b)) throw new UnsupportedPattern('quantified body can match empty');
    let pc: number;
    if (n.max === Infinity) {
      const loop = emit({ op: SPLIT, memo: true });
      const body = c(b, loop, PATTERN_END);
      prog[loop]!.x = n.lazy ? next : body;
      prog[loop]!.y = n.lazy ? body : next;
      pc = loop;
    } else {
      if (n.max - n.min > 20) throw new UnsupportedPattern('large bounded quantifier');
      pc = next;
      for (let j = 0; j < n.max - n.min; j++) {
        const body = c(b, pc, PATTERN_END);
        const xFirst = firstOf(body);
        // What follows cannot start with the body's first character: where
        // that character is here, skipping the body cannot succeed.
        const commit =
          !n.lazy && xFirst !== null && cont.first !== null && cont.first.length > 0 &&
          disjoint(xFirst.re.source.slice(4, -2), cont.first, sflags);
        pc = n.lazy
          ? emit({ op: SPLIT, x: next, y: body, xFirst: firstOf(next) })
          : emit({ op: SPLIT, x: body, y: next, xFirst, commit });
      }
    }
    if (n.min > 20) throw new UnsupportedPattern('large bounded quantifier');
    for (let j = 0; j < n.min; j++) pc = c(b, pc, PATTERN_END);
    return pc;
  }

  function c(n: ReNode, next: number, cont: Continuation): number {
    switch (n.t) {
      case 'seq': {
        let pc = next;
        let k = cont;
        for (let j = n.items.length - 1; j >= 0; j--) {
          pc = c(n.items[j]!, pc, k);
          k = precede(n.items[j]!, k);
        }
        return pc;
      }
      case 'alt': {
        const entries = n.alts.map((a) => c(a, next, cont));
        let pc = entries[entries.length - 1]!;
        // The atoms the alternatives after j can open with, when all of them must open with one.
        let rest: string[] | null = [];
        for (let j = entries.length - 2; j >= 0; j--) {
          const f = firstAtoms(n.alts[j + 1]!);
          rest = rest === null || f.empty || f.atoms === null ? null : [...rest, ...f.atoms];
          const xFirst = firstOf(entries[j]!);
          // Where this branch's first character is here, no later one can
          // start here at all, so it is taken without keeping the others open.
          const commit = xFirst !== null && rest !== null && rest.length > 0 && disjoint(xFirst.re.source.slice(4, -2), rest, sflags);
          pc = emit({ op: SPLIT, x: entries[j]!, y: pc, xFirst, commit });
        }
        return pc;
      }
      case 'group':
        return c(n.body, next, cont);
      case 'char':
        return emit({ op: CHAR, cm: charMap(n.raw, cflags), next });
      case 'assert':
        return emit({ op: ASSERT, kind: n.kind, next });
      case 'look':
        // cleartoship-ignore VG126: `n.raw` is a slice of a vendored rule's own
        // pattern, compiled once per rule — never text from a scanned repo.
        if (n.behind) return emit({ op: LOOK, re: new RegExp(n.raw, cflags + 'y'), next });
        if (evaluatesLinearly(n.body, sflags)) return emit({ op: LOOK, re: sticky(n.body), neg: n.neg, next });
        return emit({ op: LOOK, sub: c(n.body, match, PATTERN_END), neg: n.neg, next });
      case 'quant': {
        const t = n.body.t === 'char' ? null : tempered(n.body);
        const atom = n.body.t === 'char' ? n.body : t?.ch;
        if (atom === undefined) return unroll(n, next, cont);
        // When what follows can never start with a character this run
        // consumes, the run can only end where it stops: every earlier end
        // fails on its next character, in greedy order or lazy.
        const run = cont.first !== null && cont.first.length > 0 && disjoint(atom.raw, cont.first, sflags);
        // A short one (`['"]?`, `\d{2}`) is cheaper spelled out.
        if (!run && t === null && n.max <= 4) return unroll(n, next, cont);
        let forbid = -1;
        let forbidRe: RegExp | null = null;
        if (t !== null) {
          if (evaluatesLinearly(t.look.body, sflags)) forbidRe = sticky(t.look.body);
          else forbid = c(t.look.body, match, PATTERN_END);
        }
        return emit({
          op: run ? RUN : GAP,
          cm: charMap(atom.raw, cflags),
          forbid,
          forbidRe,
          forbidKey: forbidRe ? cflags + '\u0000' + forbidRe.source : '',
          min: n.min,
          max: n.max,
          lazy: n.lazy,
          next,
          first: firstMap(cont.first, cflags),
          seek: seekFor(cont, cflags),
          universal: UNIVERSAL.has(atom.raw),
        });
      }
    }
  }

  return { prog, start: c(ast, match, PATTERN_END) };
}

// --- Per-text state ----------------------------------------------------------

const isWordUnit = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const isLineTerminator = (c: number) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;

/** The sorted positions where a zero-width regex matches, listed lazily left to right. */
class Positions {
  private readonly list: number[] = [];
  private frontier = 0; // every match before this is listed
  private hint = 0;
  constructor(
    private readonly re: RegExp,
    private readonly text: string,
  ) {}

  private extendTo(q: number): void {
    const n = this.text.length;
    while (this.frontier <= q && this.frontier <= n) {
      this.re.lastIndex = this.frontier;
      if (!this.re.test(this.text)) {
        this.frontier = n + 1;
        return;
      }
      const at = this.re.lastIndex;
      this.list.push(at);
      this.frontier = at + 1;
    }
  }

  private lowerBound(q: number): number {
    const l = this.list;
    const h = this.hint;
    if (h < l.length && l[h]! >= q && (h === 0 || l[h - 1]! < q)) return h;
    let a = 0;
    let b = l.length;
    while (a < b) {
      const mid = (a + b) >> 1;
      if (l[mid]! < q) a = mid + 1;
      else b = mid;
    }
    return (this.hint = a);
  }

  /** The first position at or after q, or the text's length + 1. */
  next(q: number): number {
    const l = this.list;
    for (;;) {
      if (l.length > 0 && l[l.length - 1]! >= q) return l[this.lowerBound(q)]!;
      if (this.frontier > this.text.length) return this.text.length + 1;
      this.extendTo(Math.max(q, this.frontier));
    }
  }
}

/**
 * Where a gap's continuation can start, with a union-find over the positions
 * known to fail from there, so that a gap entered again skips all of them in
 * near-constant time. That skip is what makes the matcher linear: without it,
 * each entry walks every failure the last one found.
 */
class Candidates {
  // 0: not known to fail; otherwise (the next position that might not) + 1.
  private up: Int32Array | null = null;
  // 0: no pointer, the next is x - 1; otherwise (the next that might not) + 2.
  private down: Int32Array | null = null;
  constructor(
    private readonly first: FirstMap | null,
    /** Where V8 finds the continuation can start next, listed once per text. */
    private readonly seek: Positions | null,
    private readonly text: string,
  ) {}

  markFailed(x: number): void {
    if (this.up === null) {
      this.up = new Int32Array(this.text.length + 2);
      this.down = new Int32Array(this.text.length + 2);
    }
    if (this.up[x] === 0) this.up[x] = x + 2;
  }

  private viable(x: number): boolean {
    return this.first === null || (x < this.text.length && inFirst(this.first, this.text.charCodeAt(x)));
  }

  private findUp(i: number): number {
    const u = this.up;
    if (u === null) return i;
    let x = i;
    let j: number;
    while ((j = u[x]!) !== 0) x = j - 1;
    for (let y = i; y !== x; y = j) {
      j = u[y]! - 1;
      u[y] = x + 1;
    }
    return x;
  }

  private findDown(i: number): number {
    const u = this.up;
    const d = this.down;
    if (u === null || d === null) return i;
    let x = i;
    while (x >= 0 && u[x] !== 0) {
      const j = d[x]!;
      x = j === 0 ? x - 1 : j - 2;
    }
    for (let y = i; y > x; ) {
      const j = d[y]!;
      d[y] = x + 2;
      y = j === 0 ? y - 1 : j - 2;
    }
    return x;
  }

  /** The first position in [i, hi] not known to fail, or -1. */
  upFrom(i: number, hi: number): number {
    let walked = 0;
    for (let x = this.findUp(i); x <= hi; x = this.findUp(x + 1)) {
      if (this.viable(x)) return x;
      this.markFailed(x);
      // A long stretch where nothing can follow: let V8 find the next place
      // something can, and point past the stretch in one step.
      if (++walked === 16 && this.seek !== null) {
        walked = 0;
        const next = this.seek.next(x + 1);
        // Everything strictly between x and next is known not to be viable.
        if (next > x + 1) this.up![x + 1] = next + 1;
      }
    }
    return -1;
  }

  /** The last position in [lo, i] not known to fail, or -1. */
  downFrom(i: number, lo: number): number {
    for (let x = this.findDown(i); x >= lo; x = this.findDown(x - 1)) {
      if (this.viable(x)) return x;
      this.markFailed(x);
    }
    return -1;
  }
}

// Run breaks and forbidden-word positions depend only on the text and the
// class, so every pattern reading the same text shares them.
let sharedText: string | null = null;
let sharedLists = new Map<string, Positions>();
let generation = 0;

function sharedFor(text: string): Map<string, Positions> {
  if (text !== sharedText) {
    sharedText = text;
    sharedLists = new Map();
  }
  return sharedLists;
}

/** The subset of RegExp the scanner uses. */
export interface Matcher {
  lastIndex: number;
  readonly global: boolean;
  readonly multiline: boolean;
  readonly source: string;
  readonly flags: string;
  exec(text: string): RegExpExecArray | null;
}

/**
 * A vendored pattern run by the memoizing matcher. Behaves as its RegExp does
 * under `exec` with `lastIndex`: same matches, same order, same `m[0]`.
 */
export class LinearMatcher implements Matcher {
  lastIndex = 0;
  readonly global: boolean;
  readonly multiline: boolean;
  readonly source: string;
  readonly flags: string;
  private readonly prog: Ins[];
  private readonly start: number;
  private readonly prefilter: RegExp | null;
  private readonly required: RegExp | null;

  /** Instructions executed, cumulative. Lets the ReDoS tests assert on work
   * done instead of elapsed milliseconds; see `test/redos-overrides.test.js`. */
  steps = 0;

  private text: string | null = null;
  private n = 0;
  private gen = 0;
  private shared = new Map<string, Positions>();
  private requiredAt = -1;
  /** Where the previous search on this text started; see exec(). */
  private lastFrom = -1;
  // Indexed by instruction: failed (state, position) pairs, candidate sets,
  // lookahead verdicts, forbidden-word verdicts, run ends.
  private memo: (Uint8Array | undefined)[] = [];
  private cands: (Candidates | undefined)[] = [];
  private looks: (Uint8Array | undefined)[] = [];
  private forbids: (Uint8Array | undefined)[] = [];
  private runs: (Int32Array | undefined)[] = [];
  // Backtracking frames, five numbers each (see `run`).
  private stack: Int32Array = new Int32Array(1024);
  private sp = 0;

  constructor(re: RegExp) {
    this.global = re.global;
    this.multiline = re.multiline;
    this.source = re.source;
    this.flags = re.flags;
    const ast = collapseRuns(parsePattern(re.source), re.flags.replace(/[gmy]/g, ''));
    const { prog, start } = compilePattern(ast, re.flags);
    this.prog = prog;
    this.start = start;
    const flags = re.flags.replace(/[gy]/g, '');
    const top = precede(ast, PATTERN_END);
    const p0 = top.src !== '' && !BROAD.test(top.src) ? top.src : null;
    const f0 = firstMap(top.first, flags) !== null ? '(?:' + top.first!.join('|') + ')' : null;
    const filter = p0 ?? f0;
    this.prefilter = filter === null ? null : new RegExp('(?=' + filter + ')', flags + 'g');
    const req = requiredText(ast);
    this.required = req !== null && req[1] >= 3 ? new RegExp(req[0], flags + 'g') : null;
  }

  /** Drops the per-text tables, which hold a few bytes per character per state. */
  release(): void {
    this.text = null;
    this.memo = [];
    this.cands = [];
    this.looks = [];
    this.forbids = [];
    this.runs = [];
  }

  private reset(text: string): void {
    this.text = text;
    this.n = text.length;
    this.gen = ++generation;
    this.shared = sharedFor(text);
    this.requiredAt = -1;
    const len = this.prog.length;
    this.memo = new Array(len);
    this.cands = new Array(len);
    this.looks = new Array(len);
    this.forbids = new Array(len);
    this.runs = new Array(len);
  }

  private grow(sp: number): Int32Array {
    const bigger = new Int32Array(Math.max(this.stack.length * 2, sp + 1024));
    bigger.set(this.stack.subarray(0, sp));
    return (this.stack = bigger);
  }

  private fail(pc: number, q: number): void {
    let t = this.memo[pc];
    if (t === undefined) t = this.memo[pc] = new Uint8Array(this.n + 2);
    t[q] = 1;
  }

  private candidatesFor(ins: Ins): Candidates {
    let c = this.cands[ins.next];
    if (c === undefined) {
      const seek = ins.seek === null ? null : this.positions('S' + ins.seek.flags + ins.seek.source, ins.seek.source, ins.seek.flags);
      c = this.cands[ins.next] = new Candidates(ins.first, seek, this.text!);
    }
    return c;
  }

  private forbidden(pc: number, ins: Ins, q: number): boolean {
    if (ins.forbidRe !== null) {
      ins.forbidRe.lastIndex = q;
      return ins.forbidRe.test(this.text!);
    }
    if (ins.forbid < 0) return false;
    let t = this.forbids[pc];
    if (t === undefined) t = this.forbids[pc] = new Uint8Array(this.n + 2);
    let v = t[q]!;
    if (v === 0) t[q] = v = this.run(ins.forbid, q) >= 0 ? 1 : 2;
    return v === 1;
  }

  private positions(key: string, source: string, flags: string): Positions {
    let p = this.shared.get(key);
    if (p === undefined) {
      // cleartoship-ignore VG126: `source` is derived from a vendored rule's
      // pattern, not from the scanned text it is run over.
      p = new Positions(new RegExp(source, flags), this.text!);
      this.shared.set(key, p);
    }
    return p;
  }

  /** Where the run a gap may consume from q ends: the first character out of its class, or forbidden word. */
  private runEnd(pc: number, ins: Ins, q: number): number {
    const text = this.text!;
    const n = this.n;
    const cm = ins.cm!;
    let x = q;
    if (ins.forbid < 0) {
      if (ins.lastGen === this.gen && q >= ins.lastQ && q <= ins.lastEnd) return ins.lastEnd;
      if (ins.listGen !== this.gen) {
        ins.listGen = this.gen;
        ins.forbidList = null;
        ins.breakList = null;
      }
      let limit = n;
      if (ins.forbidRe !== null) {
        if (ins.forbidList === null) {
          const flags = ins.forbidRe.flags.replace('y', '') + 'g';
          ins.forbidList = this.positions('F' + ins.forbidKey, '(?=' + ins.forbidRe.source + ')', flags);
        }
        limit = Math.min(n, ins.forbidList.next(q));
      }
      let end: number;
      if (ins.universal) end = limit;
      else {
        // Short runs are walked. A greedy gap asks from right to left, so a
        // walk that reaches the run asked about last ends where that one does.
        // A long run is finished from the class's break positions, sparse
        // exactly when runs are long.
        const joins = ins.lastGen === this.gen && q < ins.lastQ && ins.lastQ - q <= 64;
        const stop = Math.min(limit, joins ? ins.lastQ : q + 24);
        while (x < stop && inMap(cm, text.charCodeAt(x))) x++;
        if (x < stop || x === limit) end = x;
        else if (joins) end = Math.min(ins.lastEnd, limit);
        else {
          if (ins.breakList === null) {
            const cls = cm.re.source.slice(4, -2); // `^(?:` … `)$`
            ins.breakList = this.positions('B' + cm.key, '(?!' + cls + ')(?=[\\s\\S])', cm.re.flags + 'g');
          }
          end = Math.min(limit, ins.breakList.next(x));
        }
      }
      ins.lastGen = this.gen;
      ins.lastQ = q;
      ins.lastEnd = end;
      return end;
    }
    // Forbidden words only the matcher can evaluate: walk, remembering run ends.
    let t = this.runs[pc];
    if (t === undefined) t = this.runs[pc] = new Int32Array(n + 2);
    const walked: number[] = [];
    let end: number;
    for (;;) {
      const cached = t[x]!;
      if (cached !== 0) {
        end = cached - 1;
        break;
      }
      if (x >= n || !inMap(cm, text.charCodeAt(x)) || this.forbidden(pc, ins, x)) {
        end = x;
        break;
      }
      walked.push(x);
      x++;
    }
    for (const w of walked) t[w] = end + 1;
    return end;
  }

  private look(pc: number, ins: Ins, q: number): boolean {
    if (ins.re !== null) {
      ins.re.lastIndex = q;
      return ins.re.test(this.text!) !== ins.neg;
    }
    let t = this.looks[pc];
    if (t === undefined) t = this.looks[pc] = new Uint8Array(this.n + 2);
    let v = t[q]!;
    if (v === 0) t[q] = v = this.run(ins.sub, q) >= 0 ? 1 : 2;
    return (v === 1) !== ins.neg;
  }

  /**
   * Where the first path from (pc0, pos0) that V8 would take reaches the
   * end, or -1. Frames are five numbers: [0, pc, pos] marks a memoized state
   * to record as failed once everything above it has; [1, pc, pos] is a
   * branch still to try; [2, gap pc, candidate, hi, lo] is a gap's place in
   * its list of ends.
   */
  private run(pc0: number, pos0: number): number {
    const prog = this.prog;
    const text = this.text!;
    const n = this.n;
    const memo = this.memo;
    // One stack for every nested run (lookaheads, forbidden words): this
    // run's frames start at `base`, and a nested run restores `sp` on return.
    let stack: Int32Array = this.stack;
    const base = this.sp;
    let sp = base;
    let pc = pc0;
    let pos = pos0;
    for (;;) {
      let ok = true;
      this.steps++;
      const ins = prog[pc]!;
      if (sp + 10 > stack.length) stack = this.grow(sp);
      switch (ins.op) {
        case CHAR: {
          if (pos < n) {
            const c = text.charCodeAt(pos);
            const v = ins.cm!.map[c];
            if (v === 1 || (v === 0 && inMap(ins.cm!, c))) {
              pos++;
              pc = ins.next;
              break;
            }
          }
          ok = false;
          break;
        }
        case ASSERT: {
          let r: boolean;
          if (ins.kind === '^') r = pos === 0 || (this.multiline && isLineTerminator(text.charCodeAt(pos - 1)));
          else if (ins.kind === '$') r = pos === n || (this.multiline && isLineTerminator(text.charCodeAt(pos)));
          else {
            const a = pos > 0 && isWordUnit(text.charCodeAt(pos - 1));
            const b = pos < n && isWordUnit(text.charCodeAt(pos));
            r = ins.kind === 'b' ? a !== b : a === b;
          }
          if (r) pc = ins.next;
          else ok = false;
          break;
        }
        case LOOK:
          this.sp = sp;
          ok = this.look(pc, ins, pos);
          stack = this.stack;
          if (ok) pc = ins.next;
          break;
        case SPLIT: {
          // A branch that must open with a character that is not here.
          if (ins.xFirst !== null && (pos >= n || !inMap(ins.xFirst, text.charCodeAt(pos)))) {
            pc = ins.y;
            break;
          }
          if (ins.commit) {
            pc = ins.x;
            break;
          }
          if (ins.memo) {
            const t = memo[pc];
            if (t !== undefined && t[pos] === 1) {
              ok = false;
              break;
            }
            stack[sp] = 0;
            stack[sp + 1] = pc;
            stack[sp + 2] = pos;
            sp += 5;
          }
          stack[sp] = 1;
          stack[sp + 1] = ins.y;
          stack[sp + 2] = pos;
          sp += 5;
          pc = ins.x;
          break;
        }
        case GAP: {
          const t = memo[pc];
          if (t !== undefined && t[pos] === 1) {
            ok = false;
            break;
          }
          const lo = pos + ins.min;
          const cap = ins.max === Infinity ? n : Math.min(n, pos + ins.max);
          if (lo <= cap) {
            this.sp = sp;
            const hi = Math.min(cap, this.runEnd(pc, ins, pos));
            stack = this.stack;
            if (lo <= hi) {
              const cands = this.candidatesFor(ins);
              const x = ins.lazy ? cands.upFrom(lo, hi) : cands.downFrom(hi, lo);
              if (x >= 0) {
                stack[sp] = 0;
                stack[sp + 1] = pc;
                stack[sp + 2] = pos;
                stack[sp + 5] = 2;
                stack[sp + 6] = pc;
                stack[sp + 7] = x;
                stack[sp + 8] = hi;
                stack[sp + 9] = lo;
                sp += 10;
                pc = ins.next;
                pos = x;
                break;
              }
            }
          }
          this.fail(pc, pos);
          ok = false;
          break;
        }
        case RUN: {
          let e: number;
          if (ins.max <= 4 && ins.forbid < 0 && ins.forbidRe === null) {
            e = pos;
            const stop = Math.min(n, pos + ins.max + 1);
            while (e < stop && inMap(ins.cm!, text.charCodeAt(e))) e++;
          } else {
            this.sp = sp;
            e = this.runEnd(pc, ins, pos);
            stack = this.stack;
          }
          if (e - pos >= ins.min && e - pos <= ins.max) {
            pos = e;
            pc = ins.next;
          } else ok = false;
          break;
        }
        case MATCH:
          this.sp = base;
          return pos;
      }
      if (ok) continue;
      // Backtrack to the most recent choice still open.
      for (;;) {
        if (sp === base) {
          this.sp = base;
          return -1;
        }
        const kind = stack[sp - 5]!;
        if (kind === 2) {
          const gap = prog[stack[sp - 4]!]!;
          const tried = stack[sp - 3]!;
          const cands = this.cands[gap.next]!;
          cands.markFailed(tried);
          const x = gap.lazy ? cands.upFrom(tried + 1, stack[sp - 2]!) : cands.downFrom(tried - 1, stack[sp - 1]!);
          if (x < 0) {
            sp -= 5;
            continue;
          }
          stack[sp - 3] = x;
          pc = gap.next;
          pos = x;
          break;
        }
        sp -= 5;
        if (kind === 0) {
          this.fail(stack[sp + 1]!, stack[sp + 2]!);
          continue;
        }
        pc = stack[sp + 1]!;
        pos = stack[sp + 2]!;
        break;
      }
    }
  }

  exec(text: string): RegExpExecArray | null {
    let from = this.global ? this.lastIndex : 0;
    // The per-text tables assume searches move forward. Searching the same
    // text again from an earlier position — a second file with identical
    // content, or the same file in a later scan in one process — used to reuse
    // `requiredAt` from the finished search, which said nothing was left, so
    // every match was lost. Start over whenever the search moves backwards.
    if (text !== this.text || from < this.lastFrom) this.reset(text);
    this.lastFrom = from;
    const n = this.n;
    for (;;) {
      if (from > n) break;
      // Nothing from here on holds the text every match must: no match.
      if (this.required !== null && this.requiredAt < from) {
        this.required.lastIndex = from;
        const r = this.required.exec(text);
        this.requiredAt = r === null ? n + 1 : r.index;
      }
      if (this.requiredAt > n) break;
      let p = from;
      if (this.prefilter !== null) {
        this.prefilter.lastIndex = from;
        if (!this.prefilter.test(text)) break;
        p = this.prefilter.lastIndex;
      }
      this.sp = 0;
      const end = this.run(this.start, p);
      if (end >= 0) {
        const m = Object.assign([text.slice(p, end)], { index: p, input: text, groups: undefined });
        if (this.global) this.lastIndex = end;
        return m as RegExpExecArray;
      }
      from = p + 1;
    }
    if (this.global) this.lastIndex = 0;
    return null;
  }
}

/** Whether V8 already searches `re` in linear time, so it is best left to V8. */
export function linearInIrregexp(re: RegExp): boolean {
  try {
    return evaluatesLinearly(parsePattern(re.source), re.flags.replace(/[gmy]/g, ''));
  } catch (err) {
    if (err instanceof UnsupportedPattern) return false;
    throw err;
  }
}

const MATCHERS = new WeakMap<RegExp, Matcher>();

/**
 * What the scanner runs for a pattern: the pattern itself when V8 already
 * searches it in linear time (or it uses syntax the matcher does not handle,
 * which is one rule, VG1094's backreference), and a LinearMatcher otherwise.
 */
export function matcherFor(re: RegExp): Matcher {
  let m = MATCHERS.get(re);
  if (m === undefined) {
    m = re;
    if (!linearInIrregexp(re)) {
      try {
        m = new LinearMatcher(re);
      } catch (err) {
        if (!(err instanceof UnsupportedPattern)) throw err;
      }
    }
    MATCHERS.set(re, m);
  }
  return m;
}

