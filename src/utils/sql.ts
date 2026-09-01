/**
 * Minimal PostgreSQL statement splitter. Deliberately not a full parser: it
 * only needs to know where one statement ends, which means respecting string
 * literals, dollar-quoted function bodies and both comment styles.
 */
export interface SqlStatement {
  text: string;
  /** 1-indexed line where the statement starts. */
  line: number;
}

export function splitStatements(source: string): SqlStatement[] {
  const out: SqlStatement[] = [];
  let buf = '';
  let line = 1;
  let startLine = 1;
  let pendingStart = true;
  let i = 0;

  // Statements are separated by blank lines and comments, so the recorded line
  // has to be the first line carrying an actual token.
  const emit = (text: string) => {
    if (pendingStart && text.trim()) {
      startLine = line;
      pendingStart = false;
    }
    buf += text;
  };

  const flush = () => {
    if (buf.trim()) out.push({ text: buf.trim(), line: startLine });
    buf = '';
    pendingStart = true;
  };

  while (i < source.length) {
    const ch = source[i]!;
    const next = source[i + 1];

    if (ch === '-' && next === '-') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') line++;
        i++;
      }
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"') {
      const quote = ch;
      emit(ch);
      i++;
      while (i < source.length) {
        if (source[i] === '\n') line++;
        if (source[i] === quote) {
          if (source[i + 1] === quote) {
            emit(quote + quote);
            i += 2;
            continue;
          }
          emit(quote);
          i++;
          break;
        }
        emit(source[i]!);
        i++;
      }
      continue;
    }
    if (ch === '$') {
      const tag = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(source.slice(i));
      if (tag) {
        const marker = tag[0];
        const end = source.indexOf(marker, i + marker.length);
        const chunk = end === -1 ? source.slice(i) : source.slice(i, end + marker.length);
        emit(chunk);
        for (const c of chunk) if (c === '\n') line++;
        i += chunk.length;
        continue;
      }
    }
    if (ch === ';') {
      flush();
      i++;
      continue;
    }
    if (ch === '\n') {
      emit(ch);
      line++;
      i++;
      continue;
    }
    emit(ch);
    i++;
  }
  flush();
  return out;
}

/** Reads a parenthesised group starting at `open` (index of the `(`). */
export function readBalanced(text: string, open: number): string | null {
  if (text[open] !== '(') return null;
  let depth = 0;
  let inString: string | null = null;
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (inString) {
      if (ch === inString) {
        if (text[i + 1] === inString) { i++; continue; }
        inString = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return null;
}

/** Grabs the expression after a keyword such as USING or WITH CHECK. */
export function clauseAfter(text: string, keyword: RegExp): string | null {
  const m = keyword.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length;
  while (i < text.length && /\s/.test(text[i]!)) i++;
  return readBalanced(text, i);
}

/** Normalises `"public"."posts"` / `public.posts` / `posts` to `public.posts`. */
export function normaliseTable(raw: string): string {
  const parts = raw
    .trim()
    .split('.')
    .map((p) => p.replace(/^"(.*)"$/, '$1').trim())
    .filter(Boolean);
  if (parts.length === 0) return '';
  if (parts.length === 1) return `public.${parts[0]}`;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

const IDENT = `(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)`;
export const QUALIFIED_NAME = `${IDENT}(?:\\s*\\.\\s*${IDENT})*`;

/** True when a policy predicate lets everything through. */
export function isAlwaysTrue(expr: string | null): boolean {
  if (expr === null) return false;
  const cleaned = expr.replace(/\s+/g, ' ').replace(/[()]/g, ' ').trim().toLowerCase();
  return cleaned === 'true' || cleaned === '1' || cleaned === 'true::boolean';
}
