/**
 * Where the strings and comments are in a file.
 *
 * A regex ruleset has no idea whether it matched code, a sentence about code,
 * or a URL — and the difference decides whether a finding is real. Our own
 * source proved it: a comment reading "merely calling `jwt.verify(token,
 * secret)`" was reported as a JWT vulnerability, and a rule *description*
 * quoting `eval()` was reported as dynamic code execution.
 *
 * The naive fix — treat everything after `//` as a comment — is worse than the
 * bug, because `"https://api.example.com"` would silence every finding on that
 * line. So this walks the file once, tracking quotes as it goes, and both
 * answers come out correct.
 */

export interface Span {
  start: number;
  end: number;
  kind: 'string' | 'comment';
}

export interface CommentStyle {
  /** `//` line comments and `/* *\/` blocks. */
  slashes: boolean;
  /** `#` line comments: shell, Python, Ruby, YAML, Terraform, Dockerfile. */
  hash: boolean;
  /** `--` line comments: SQL. */
  dashes: boolean;
}

export function commentStyleFor(languages: readonly string[]): CommentStyle {
  const has = (l: string) => languages.includes(l);
  return {
    slashes:
      has('javascript') || has('typescript') || has('go') || has('php') || has('sql'),
    hash:
      has('python') ||
      has('shell') ||
      has('ruby') ||
      has('yaml') ||
      has('terraform') ||
      has('dockerfile'),
    dashes: has('sql'),
  };
}

/** Files past this size are skipped by the caller anyway; this is belt and braces. */
const MAX_SOURCE = 1_000_000;

export function lexSpans(source: string, style: CommentStyle): Span[] {
  const spans: Span[] = [];
  if (source.length > MAX_SOURCE) return spans;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!;

    // Strings. A template literal is taken whole, interpolations included —
    // nothing here needs to reason about what is inside one.
    if (ch === '"' || ch === "'" || ch === '`') {
      const start = i;
      const quote = ch;
      i++;
      while (i < source.length) {
        const c = source[i]!;
        if (c === '\\') {
          i += 2;
          continue;
        }
        if (c === quote) break;
        // An unterminated single- or double-quoted string ends at the newline,
        // which is what an apostrophe in a comment looks like.
        if (c === '\n' && quote !== '`') break;
        i++;
      }
      spans.push({ start, end: Math.min(i, source.length - 1), kind: 'string' });
      continue;
    }

    const two = source.slice(i, i + 2);

    if (style.slashes && two === '/*') {
      const end = source.indexOf('*/', i + 2);
      const close = end === -1 ? source.length - 1 : end + 1;
      spans.push({ start: i, end: close, kind: 'comment' });
      i = close;
      continue;
    }

    const lineComment =
      (style.slashes && two === '//') ||
      (style.dashes && two === '--') ||
      (style.hash && ch === '#');
    if (lineComment) {
      const newline = source.indexOf('\n', i);
      const close = newline === -1 ? source.length - 1 : newline - 1;
      spans.push({ start: i, end: close, kind: 'comment' });
      i = close;
      continue;
    }
  }

  return spans;
}

/** Binary search: is `index` inside a span of this kind? */
export function spanAt(spans: readonly Span[], index: number): Span | null {
  let low = 0;
  let high = spans.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const span = spans[mid]!;
    if (index < span.start) high = mid - 1;
    else if (index > span.end) low = mid + 1;
    else return span;
  }
  return null;
}

export function isInside(spans: readonly Span[], index: number, kind: Span['kind']): boolean {
  return spanAt(spans, index)?.kind === kind;
}
