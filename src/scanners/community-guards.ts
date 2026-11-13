/* ------------------------------------------------------------------------- *
 * Calibration guards for the vendored rules.
 *
 * A `MATCH_GUARDS` entry is a second opinion on a match the vendored pattern
 * already made: it is handed the matched text, the whole source, the offset and
 * the lexed string/comment spans, and returns false to withdraw the finding.
 * That is the mechanism for the false positives a pattern cannot avoid without
 * understanding the code around it -- a `curl … | sh` inside an `echo`, a
 * parameterised query that looks concatenated, an origin that resolves to a
 * literal host.
 *
 * Everything above `MATCH_GUARDS` exists to serve it, which is why the two
 * moved together: the helpers read a statement, a call's arguments, an
 * enclosing function body or an assigned expression out of raw source, and
 * nothing else in the scanner uses any of them.
 *
 * Extracted from `community.ts` 2026-11-13, a second Rule 26 step 7 pass after
 * the matcher engine came out the same day. The division that leaves is the one
 * worth having: the scanner walks files and reports, the engine matches, and
 * this decides whether a match survives contact with its context.
 *
 * Guards are the *narrow* instrument. A rule whose wording is wrong is fixed in
 * `community-text.ts`, a rule whose pattern is wrong in `community-patterns.ts`,
 * and a rule that cannot apply at all is withheld in `community.ts`. A guard
 * that is really a pattern bug hides the bug and keeps the cost.
 * ------------------------------------------------------------------------- */

import { isInside } from '../utils/spans.js';
import type { Span } from '../utils/spans.js';

/** SQL verbs strong enough that the call is about a database by itself. */
const SQL_VERBS = /^(query|execute|raw|sql|prepare|QueryRow|QueryContext)$/i;

/** Words that make a string a query rather than a sentence. */
const SQL_KEYWORDS = /\b(select|insert\s+into|update|delete\s+from|from|where|values|set)\b/i;

/** Placeholder values that exist to be replaced, not to authenticate. */
const PLACEHOLDER =
  /^(your|my|the|a|change|changeme|replace|example|placeholder|dummy|sample|test|todo|none|null|undefined|x{3,}|\.{3}|<.*>|\$\{.*\}|process\.env)/i;

/**
 * Whether the quoted value in a `name = "value"` match reads as a credential.
 * Prose is not: three or more words, or a trailing full stop, is a sentence.
 */
function looksLikeSecretValue(match: string): boolean {
  const value = /['"]([^'"\n]*)['"]\s*$/.exec(match)?.[1];
  if (value === undefined) return true;
  const trimmed = value.trim();
  if (trimmed === '' || PLACEHOLDER.test(trimmed)) return false;
  if (trimmed.split(/\s+/).length >= 3) return false;
  if (/[.!?]$/.test(trimmed) && trimmed.includes(' ')) return false;
  // `password="[REDACTED]"` is what a log *sanitizer* writes — this fired on
  // the replacement string of a redaction helper, reported critical.
  if (/^\[[^[\]]+\]$/.test(trimmed)) return false;
  if (/\b(?:REDACTED|MASKED|FILTERED|SANITIZED|CENSORED)\b/.test(trimmed)) return false;
  // A password hash is a verifier, not a credential: presenting it does not
  // authenticate anybody. `DUMMY_PASSWORD_HASH = '$2b$12$…'` — the standard
  // timing-equalization idiom on a login route — was a critical.
  if (/^\$(?:2[abxy]?\$\d{1,2}\$|argon2(?:id|i|d)?\$|scrypt\$|pbkdf2)/.test(trimmed)) return false;
  // Documentation samples: a token whose body is the keyboard walk
  // `1234567890abcdef`, or that ends in an ellipsis because the author cut it.
  if (/1234567890abcdef/i.test(trimmed)) return false;
  if (/(?:\.\.\.|…)$/.test(trimmed)) return false;
  return true;
}

/** Bind placeholders: `?`, `$1`, `:name`, `@name`, anywhere a value may go. */
const BIND_PLACEHOLDER = /[\s(,=]\?(?=[\s,)`;]|$)|\$\d+\b|[\s(,=]:[A-Za-z_]\w*|[\s(,=]@[A-Za-z_]\w*/;

/** `${...}` expressions that read straight from the request. */
const INTERPOLATES_REQUEST =
  /\$\{[^}]*\b(req|request|body|params|query|searchParams|argv|input|formData|payload)\b/i;

/**
 * The whole statement a match sits in. Both SQL rules stop matching at the first
 * `${`, so the bind placeholders that decide the question are usually *past* the
 * end of the match — `prepare(\`UPDATE ${table} SET csv_data = ? WHERE id = ?\`)`
 * matches only as far as `UPDATE ${`.
 */
function statementAround(source: string, index: number): string {
  const open = source.indexOf('`', index);
  if (open !== -1 && open - index < 120) {
    for (let i = open + 1; i < source.length && i < open + 800; i++) {
      if (source[i] === '\\') {
        i++;
        continue;
      }
      // A little past the closing backtick, so the chained `.bind(...)` that
      // decides whether the values are parameterized is inside the window.
      if (source[i] === '`') return source.slice(index, i + 121);
    }
  }
  return source.slice(index, index + 400);
}

/**
 * Whether the statement passes its values as bound parameters. Interpolating a
 * table name into an otherwise parameterized query is ordinary; interpolating
 * `${req.query.id}` is the bug, and a query doing both still fails this test.
 */
function isParameterized(statement: string): boolean {
  if (INTERPOLATES_REQUEST.test(statement)) return false;
  // Handing the statement to `.bind(...)` is the parameterizing itself, and it
  // covers the idioms a placeholder scan cannot see: `IN (${ids.map(() =>
  // '?').join(',')})`, or a constant SQL fragment interpolated beside binds.
  if (/\.\s*bind\s*\(\s*[^)\s]/.test(statement)) return true;
  // The other calling convention: the values follow the query.
  // `$executeRawUnsafe(\`… VALUES ${placeholders}\`, ...params)`,
  // `db.query(sql, [id])`. A closing backtick with an argument after it.
  if (/`\s*,\s*[^)\s]/.test(statement)) return true;
  // An interpolation that builds placeholders is parameterizing too:
  // `chunk.map(() => "(?, ?, ?)").join(", ")`.
  if (/\$\{[^}]*['"][^'"]*\?[^'"]*['"]/.test(statement)) return true;
  // Otherwise look for the placeholders themselves — with interpolations
  // dropped first, so a JavaScript ternary is not read as a `?` parameter.
  return BIND_PLACEHOLDER.test(statement.replace(/\$\{[^}]*\}/g, ' '));
}

/**
 * The template literal a SQL match points into: its constant text with every
 * `${…}` hole blanked, and each hole's own expression. Null when no template
 * starts near the match or it does not close within the bound.
 */
function templateParts(source: string, index: number): { text: string; holes: string[] } | null {
  const open = source.indexOf('`', index);
  if (open === -1 || open - index > 160) return null;
  let text = '';
  const holes: string[] = [];
  for (let i = open + 1; i < source.length && i < open + 2000; i++) {
    const ch = source[i]!;
    if (ch === '\\') {
      text += ' ';
      i++;
      continue;
    }
    if (ch === '`') return { text, holes };
    if (ch === '$' && source[i + 1] === '{') {
      let depth = 1;
      let j = i + 2;
      for (; j < source.length && j < i + 600 && depth > 0; j++) {
        if (source[j] === '{') depth++;
        else if (source[j] === '}') depth--;
      }
      holes.push(source.slice(i + 2, j - 1));
      text += ' ';
      i = j - 1;
      continue;
    }
    text += ch;
  }
  return null;
}

/**
 * An interpolation that is itself a call to a SQL quoting helper —
 * `${quoteIdent(table)}`, `${escapeId(col)}`, `${mysql.escape(v)}` — is the
 * escaping the rule asks for, written inline where the guard can see it. The
 * HTML/URL escapers are excluded: `escapeHtml(v)` in a SQL string is still the
 * bug. A bare identifier that merely *holds* a quoted value stays reported,
 * because proving that is dataflow — the same line VG012 draws.
 */
const SQL_QUOTE_CALL = /^[\w$.]*(?:quote|escape|esc)[\w$]*\s*\(/i;
const NOT_SQL_ESCAPER = /html|xml|attr|ur[il]|regex/i;

/** The verb has to be a SQL verb, and the statement must not be parameterized. */
function sqlGuard(match: string, source: string, index: number): boolean {
  const verb = /^[A-Za-z_]+/.exec(match)?.[0] ?? '';
  if (!SQL_VERBS.test(verb) && !SQL_KEYWORDS.test(match)) return false;
  const tpl = templateParts(source, index);
  if (tpl) {
    // MAXRESULTS and STARTPOSITION are QuickBooks Query Language, which exists
    // only as a URL parameter to Intuit's HTTP API: no SQL driver ever parses
    // this string, and that API has no parameterized form to recommend. Three
    // criticals titled "SQL injection" on a QuickBooks integration's queries.
    if (/\b(?:MAXRESULTS|STARTPOSITION)\b/.test(tpl.text)) return false;
    if (
      tpl.holes.length > 0 &&
      tpl.holes.every((h) => {
        const hole = h.trim();
        return SQL_QUOTE_CALL.test(hole) && !NOT_SQL_ESCAPER.test(hole);
      })
    ) {
      return false;
    }
  }
  return !isParameterized(statementAround(source, index));
}

/**
 * A ceiling on what one model call or agent loop may spend, in any of the names
 * the SDKs actually use. `stopWhen` is the current Vercel AI SDK spelling of the
 * step cap; `maxSteps` is its predecessor.
 */
const HAS_STEP_CAP =
  /\b(stopWhen|stop_when|stopConditions|maxSteps|max_steps|max_iterations|maxIterations|maxTokens|max_tokens|maxOutputTokens|max_output_tokens)\b/;

/**
 * The real argument list of a call whose name starts at `index`: counts parens
 * from the call's own `(` to its matching `)`, so a nested call inside an
 * argument does not look like the end of the outer one. Bounded, since this
 * only ever runs on the handful of matches one rule produces per file.
 */
function callArgs(source: string, index: number): string {
  const open = source.indexOf('(', index);
  if (open === -1) return '';
  let depth = 0;
  for (let i = open; i < source.length && i < open + 4000; i++) {
    if (source[i] === '(') depth++;
    else if (source[i] === ')') {
      depth--;
      if (depth === 0) return source.slice(open + 1, i);
    }
  }
  return source.slice(open + 1, open + 4000);
}

/**
 * Per-rule filters for a match shape the upstream regex cannot exclude on its
 * own. Given the matched text plus where it sat, so a guard can look around it.
 */
/**
 * The function body a match sits in, back to that function's own opening brace.
 *
 * A guard that asks "is the check above this line?" must ask it of the scope
 * the line is in. Reading the whole file (which VG1025's guard does) credits a
 * check written in a different function; reading a fixed window backwards cuts
 * through the function header. So the walk goes backwards over balanced braces
 * and stops at the first unbalanced `{` that a function or arrow header opened,
 * climbing out of the `if`/`try`/`for` blocks on the way.
 */
export function enclosingBody(source: string, index: number, limit = 4000): string {
  const floor = Math.max(0, index - limit);
  let start = floor;
  let depth = 0;
  let climbs = 0;
  for (let i = index - 1; i >= floor; i--) {
    const c = source[i];
    if (c === '}') {
      depth++;
      continue;
    }
    if (c !== '{') continue;
    if (depth > 0) {
      depth--;
      continue;
    }
    start = i + 1;
    const header = source.slice(Math.max(floor, i - 80), i);
    const block = /\b(?:if|for|while|switch|try|catch|else|do)\s*(?:\([^()]*\))?\s*$/.test(header);
    const fn = /(?:function\b[^(){}]*\([^()]*\)|=>|\)\s*(?::\s*[\w<>[\].|,? ]+)?)\s*$/.test(header);
    if (fn && !block) break;
    if (++climbs >= 3) break;
  }
  return source.slice(start, index);
}

/**
 * The expression assigned at an `x.innerHTML = …` match: from the `=` to the
 * end of the statement, bounded, with nesting respected so a `}` inside a
 * callback does not end it early.
 */
function assignedExpression(source: string, index: number, limit = 1200): string {
  const at = /[=:]/.exec(source.slice(index, index + 40));
  if (!at) return '';
  const eq = index + at.index;
  let depth = 0;
  const end = Math.min(source.length, eq + limit);
  for (let i = eq + 1; i < end; i++) {
    const c = source[i]!;
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (depth === 0) return source.slice(eq + 1, i);
      depth--;
    } else if (depth === 0 && c === ';') {
      return source.slice(eq + 1, i);
    } else if (depth === 0 && c === '\n') {
      // A newline ends the expression only when nothing continues it. A
      // multi-line ternary of two string literals read as the bare condition
      // on the first line, which looks dynamic when the value cannot be.
      const before = source.slice(eq + 1, i).trimEnd();
      const after = source.slice(i + 1, i + 40).trimStart();
      const continues = /[?:+,.|&([{=-]$/.test(before) || /^[?:+.,|&)\]}]/.test(after);
      if (!continues) return source.slice(eq + 1, i);
    }
  }
  return source.slice(eq + 1, end);
}

/** Calls whose output is HTML-safe by the time it is assigned. */
const ESCAPES_HTML =
  /\b(?:esc|escape|htmlEsc|sanitiz|sanitis|purif|xss|encodeURI)[A-Za-z]*\s*\(|\bDOMPurify\b/i;

/**
 * Whether an expression carries anything that is not a literal.
 *
 * Deliberately conservative: a bare identifier counts. Proving that the string
 * behind one is a module constant rather than a request parameter is dataflow
 * work (what CTS084 does for model output), and a guard that assumed "bare
 * name = safe" would drop `el.innerHTML = untrustedHtml`, which is the finding.
 */
function hasDynamicPart(expr: string): boolean {
  // In `showing ? '<path …/>' : '<path …/>'` — an icon swap, and 1 of the 7
  // findings the first HTML-reading scan produced — the condition is a name and
  // both values are literals. Only the values reach the sink, so only they are
  // read: a `?` that opens a conditional, never `?.` or `??`, and never one
  // inside a string.
  const conditional = /^[^?'"`]*\?(?![.?])/.exec(expr);
  const body = conditional ? expr.slice(conditional[0].length) : expr;
  // Every string literal, template literal and number taken out: what is left
  // of `'<b>' + 'x'` is operators and whitespace, and of `'<b>' + name` is a name.
  const rest = body
    .replace(/`(?:[^`\\]|\\.)*`/g, ' ')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, ' ')
    .replace(/"(?:[^"\\\n]|\\.)*"/g, ' ')
    .replace(/\b\d+(?:\.\d+)?\b/g, ' ')
    .replace(/\b(?:true|false|null|undefined)\b/g, ' ');
  // A template literal with an interpolation is dynamic whatever is around it.
  if (/`(?:[^`\\]|\\.)*\$\{/.test(body)) return true;
  return /[A-Za-z_$]/.test(rest);
}

/**
 * A call that establishes a URL is safe to fetch before it is fetched — an
 * allowlist check, a private-IP rejection, a URL parser used as a gate. This is
 * the SSRF equivalent of `ESCAPES_HTML`, and the same judgement: a call whose
 * name says it validates the URL is credited, because the alternative is to
 * report the mitigation.
 */
const SSRF_VALIDATED =
  /\b(?:assert|validate|check|ensure|guard|is)[A-Za-z]*(?:Url|URL|Uri|URI|Host|Origin|Fetchable|Address)[A-Za-z]*\s*\(/;

/** An origin no caller can move: an absolute literal, or one read from the environment. */
const LITERAL_ORIGIN = /^\s*['"`]https?:\/\/[^\s'"`$]/;
const ENV_ORIGIN =
  /^\s*(?:process\.env\b|Deno\.env\.get\s*\(|import\.meta\.env\b|(?:context\.|c\.)?env\.[A-Z_]\w*)/;
/**
 * A quoted hostname with no scheme — `const SHOP = "shop.myshopify.com"`, used
 * as `` `https://${SHOP}/admin/api/2026-04` ``. The scheme is in the template
 * and the host is this literal, so the origin is still fixed.
 */
// Written without a nested quantifier on purpose: `[\w-]+(?:\.[\w-]+)+` is the
// shape VG153 exists to find, and this project's own self-scan reported it the
// moment it was written. One character class plus a "has a dot" test says the
// same thing with nothing to backtrack over.
const LITERAL_HOST = /^\s*(['"])([\w.-]+)\1\s*$/;

function isLiteralHost(expr: string): boolean {
  const m = LITERAL_HOST.exec(expr);
  return m !== null && m[2]!.includes('.') && !m[2]!.startsWith('.') && !m[2]!.endsWith('.');
}

/**
 * Split a conditional expression at its top-level `?` and `:`, ignoring any
 * inside quotes. A regex cannot: both branches of
 * `sandbox ? "https://a.example" : "https://b.example"` contain the `:` of
 * their own scheme, which is how the first version of this guard reported two
 * QuickBooks callers it had cleared one line earlier.
 */
function splitTernary(expr: string): [string, string] | null {
  let quote = '';
  let depth = 0;
  let q = -1;
  let colon = -1;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i]!;
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (depth === 0 && c === '?' && expr[i + 1] !== '.' && expr[i + 1] !== '?' && q === -1) q = i;
    else if (depth === 0 && c === ':' && q !== -1 && colon === -1) colon = i;
  }
  if (q === -1 || colon === -1) return null;
  return [expr.slice(q + 1, colon), expr.slice(colon + 1)];
}

/**
 * Is the URL handed to `fetch` built on an origin that is fixed by the code?
 *
 * The scheme and host are what SSRF turns on: a path or query appended to a
 * constant base cannot send the request to 169.254.169.254 or to localhost, no
 * matter who supplies the path. So the identifier is followed back through its
 * assignment — at most `depth` hops, which covers the two shapes that actually
 * occur (`const url = `${base}/v3/…`` over `const base = useSandbox ? A : B`) —
 * and the first segment of whatever it was assigned has to be a literal
 * `https://…`, an environment read, or another identifier that resolves to one.
 * A ternary has to resolve on both branches. Anything else is unknown, and
 * unknown stays reported.
 */
function hasKnownOrigin(name: string, source: string, index: number, depth: number): boolean {
  if (depth <= 0) return false;
  // `name` came out of the scanned repository and is about to be interpolated
  // into a pattern. Every caller already constrains it to an identifier, which
  // is why nothing can reach here with a metacharacter in it — checked anyway,
  // because a guard that depends on its callers staying careful is one edit
  // away from not holding.
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return false;
  // The nearest assignment at or above the use, so a later rebinding of the
  // same name in another function is not what gets credited.
  const assign = new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'g');
  let value: string | null = null;
  for (const m of source.slice(0, index).matchAll(assign)) value = m[1]!;
  if (value === null) {
    // A parameter or an import: unknown here. A *module-level* const declared
    // below the use is still in scope, so look forward — but only at column 0.
    // Without that anchor a `const url = new URL(request.url)` in some later
    // function credited an earlier function's `fetch(url)` on a bare
    // parameter, which is the opposite of what this guard is for.
    const later = new RegExp(
      `^(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`,
      'm',
    ).exec(source.slice(index));
    if (!later) return false;
    value = later[1]!;
  }
  return resolvesToOrigin(value, source, index, depth - 1);
}

/**
 * Does this expression carry an origin the caller cannot move?
 *
 * The hop budget is spent only on following a name to its assignment; reading a
 * ternary or a template literal is free, because `const base = sandbox ? A : B`
 * and `const url = `${base}/v3/…`` are one idiom written across three lines,
 * and charging each line would run out before reaching the literal.
 */
function resolvesToOrigin(expr: string, source: string, index: number, depth: number): boolean {
  const e = expr.trim();
  if (ENV_ORIGIN.test(e)) return true;
  if (LITERAL_ORIGIN.test(e)) return true;
  const tpl = /^`([^`]*?)(?:\$\{([^{}]{0,160})\}|`)/.exec(e);
  if (tpl) {
    const prefix = tpl[1] ?? '';
    // `https://${host}/path` is NOT a fixed origin: the host is the hole, and
    // the host is the whole of SSRF. The prefix has to reach past the `//` into
    // a hostname before the first interpolation, or the hole itself has to
    // resolve to an origin.
    if (/^https?:\/\/[^\s/$]+/.test(prefix)) return true;
    const hole = tpl[2]?.trim();
    if (hole && /^https?:\/\/$|^$/.test(prefix)) {
      // With the scheme already written, the hole only has to carry the host.
      if (prefix !== '' && isFixedHost(hole, source, index, depth)) return true;
      return resolvesToOrigin(hole, source, index, depth);
    }
    return false;
  }
  const ternary = splitTernary(e);
  if (ternary) {
    return (
      resolvesToOrigin(ternary[0], source, index, depth) &&
      resolvesToOrigin(ternary[1], source, index, depth)
    );
  }
  // A concatenation is its first operand's origin.
  const concat = /^([^+]{1,200}?)\s*\+/.exec(e);
  if (concat) return resolvesToOrigin(concat[1]!, source, index, depth);
  if (/^[A-Za-z_$]\w*$/.test(e)) return hasKnownOrigin(e, source, index, depth);
  return false;
}

/**
 * How many arguments the call at `index` is passed, counting only top-level
 * commas so an object literal, an array or a nested call counts as one. Returns
 * 0 when no argument list is found within a bounded window.
 */
function argumentList(source: string, index: number): { arity: number; after: string } | null {
  const open = source.indexOf('(', index);
  if (open === -1 || open > index + 40) return null;
  let depth = 0;
  let quote = '';
  let args = 1;
  const end = Math.min(source.length, open + 4000);
  for (let i = open; i < end; i++) {
    const c = source[i]!;
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) return { arity: args, after: source.slice(i + 1, i + 80) };
    } else if (depth === 1 && c === ',') args++;
  }
  return null;
}

/** The host half of a `https://${…}/…` template: a literal hostname, an env read, or a name for one. */
function isFixedHost(expr: string, source: string, index: number, depth: number): boolean {
  const e = expr.trim();
  if (isLiteralHost(e) || ENV_ORIGIN.test(e)) return true;
  const ternary = splitTernary(e);
  if (ternary) {
    return (
      isFixedHost(ternary[0], source, index, depth) && isFixedHost(ternary[1], source, index, depth)
    );
  }
  if (!/^[A-Za-z_$][\w$]*$/.test(e) || depth <= 0) return false;
  // Before the use, else a module-level declaration at column 0 — the same rule
  // as `hasKnownOrigin`, so a later local of the same name cannot be credited.
  const assign = new RegExp(`\\b(?:const|let|var)\\s+${e}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'g');
  let value: string | null = null;
  for (const m of source.slice(0, index).matchAll(assign)) value = m[1]!;
  if (value === null) {
    const later = new RegExp(`^(?:const|let|var)\\s+${e}\\s*(?::[^=\\n]{0,60})?=\\s*([^;\\n]{0,400})`, 'm').exec(
      source.slice(index),
    );
    value = later ? later[1]! : null;
  }
  return value === null ? false : isFixedHost(value, source, index, depth - 1);
}

/**
 * A `<style>` element's own text. `<style dangerouslySetInnerHTML={{ __html:
 * css }} />` is how React injects a stylesheet, and it was 7 of the 14 real
 * VG012 findings across the dogfooding repos — reported `high` as cross-site
 * scripting, on the idiom this project's own README calls "a regex, not a
 * finding" when CTS084 was written. CSS text in a style tag is not an HTML sink.
 */
function inStyleElement(source: string, index: number): boolean {
  const before = source.slice(Math.max(0, index - 200), index);
  const open = before.lastIndexOf('<');
  return open !== -1 && /^<style\b[^<>]*$/i.test(before.slice(open));
}

/**
 * An authorization decision — not merely an authentication one. A named guard,
 * the caller's own role / admin flag / permission being tested, or the refusal
 * that only an authorization check returns.
 *
 * Deliberately excludes a bare `auth()` / `getUser()` / 401: "any authenticated
 * user can promote themselves" is the bug VG1008 is about, so a signed-in check
 * alone must not clear it.
 */
const AUTHORIZATION_CHECK = new RegExp(
  [
    String.raw`\b(?:require|assert|ensure|check|verify)(?:Admin|Role|Owner|Permission|Permissions|Authori[sz]ation|Authori[sz]ed|Access)\w*\s*\(`,
    String.raw`\b(?:hasRole|hasPermission|hasAnyRole|canAccess|isAuthorized|isAuthorised|authorize|authorise|requirePermission|checkAdmin)\s*\(`,
    String.raw`[!(&|,]\s*[\w$.?[\]'"]*\b(?:is_?admin|isSuperAdmin|is_?owner|role|roles|permission|permissions)\b`,
    String.raw`\b(?:is_?admin|isSuperAdmin|role|roles|permission|permissions)\b[^\n]{0,60}(?:===|!==|==|!=|\bin\b|\.includes\s*\()`,
    String.raw`\b403\b|\bForbidden\b|\bFORBIDDEN\b|\bPERMISSION_DENIED\b`,
  ].join('|'),
);

/**
 * A shell builtin that writes its argument out instead of running it, as the
 * last command before the string the match sits in. `[^;&|()]*$` is what makes
 * it the *last* one: `echo done && bash -c "curl … | bash"` really does run it,
 * and the `&&` between stops this from matching.
 */
const SHELL_PRINTS = /(?:^|[;&|(])\s*(?:echo|printf|print)\b[^;&|()]*$/;

export const MATCH_GUARDS: Record<
  string,
  (
    match: string,
    source: string,
    index: number,
    spans: readonly Span[],
    /** Path relative to the scan root, for the guards that are about where a file sits. */
    relPath?: string,
  ) => boolean
> = {
  // A `"link": true` entry is a workspace or pnpm symlink resolved to a path on
  // disk rather than a tarball, so it has no integrity hash by design. Thirty of
  // them in one pnpm-managed lockfile, every one reported as a false critical.
  VG870: (match) => !/"link"\s*:\s*true/.test(match),

  // Two bugs stacked on one real app. First: the bare-identifier alternative
  // `verifyToken` matches the literal text "verifyToken(" wherever it appears —
  // including the function's own DECLARATION, `export function verifyToken(token:
  // string): JwtPayload | null {`, which is not a call at all. `function`
  // immediately before the name is the tell; a declaration's own body then reads
  // as if it were the call's arguments. Second, even at a genuine call, the "no
  // `algorithms` option" branch trusts its own `\s*\)` to mark where the call
  // ends — but the second argument is often itself a call,
  // `jwt.verify(token, getJwtSecret(), { algorithms: ["HS256"] })`, and the regex
  // backtracks onto getJwtSecret()'s own closing paren rather than reading past
  // it: it matches only `jwt.verify(token, getJwtSecret()` and never sees the
  // real options object. Re-find the call's actual matching paren by counting
  // braces instead of trusting where the regex gave up, and keep the finding
  // only when algorithms is truly absent from what is inside it. The other
  // alternative this rule matches — a literal `algorithms: ["none"]` — needs
  // neither check: it is unambiguous wherever it appears.
  VG105: (match, source, index) => {
    if (!/^(?:jwt\.verify|jwtVerify|verifyToken)/i.test(match)) return true;
    const before = source.slice(Math.max(0, index - 20), index);
    if (/(?:^|[\s;{}])(?:async\s+)?function\s*$/.test(before)) {
      // The match is anchored on the declaration, which swallowed everything up
      // to wherever the real call inside the function body happened to close —
      // not necessarily that call's own true end. What decides the question is
      // the genuine `jwt.verify`/`jwtVerify` call inside the body, wherever it
      // is, found by searching from the real source rather than trusting the
      // span the outer, wrong match already committed to.
      const inner = /(?:jwt\.verify|jwtVerify)\s*\(/.exec(match);
      if (!inner) return false;
      return !/algorithms\s*:/.test(callArgs(source, index + inner.index));
    }
    return !/algorithms\s*:/.test(callArgs(source, index));
  },

  // The verb list has no word boundary in front of it and includes `all`, `get`
  // and `run`, so `querySelectorAll(\`[name="${CSS.escape(k)}"]\`)` reads as a
  // SQL call. Weak verbs have to be backed by something that looks like SQL;
  // `query`, `execute` and friends stand on their own. A real interpolated
  // `exec(\`INSERT INTO ...\`)` still matches — checked against one.

  // `(?:child_process|cp)[\s\S]*?(?:exec|spawn…)` lets the bridge run to the end
  // of the file: one match measured 3,608 characters and 109 lines, pairing an
  // `import … from "node:child_process"` with an `exec(` far below it and
  // reporting the import as a critical. A real one is a single statement.
  VG011: (match) => (match.match(/\n/g)?.length ?? 0) <= 1,

  // `sk-[A-Za-z0-9-_]{20,}` has no boundary in front of it, so the slug
  // `best-disk-space-analyzer-mac-2026` contains an "OpenAI key" — the `sk-` in
  // "di*sk-*space...". Real keys start at a token boundary; substrings of a word
  // do not.
  VG003: (_match, source, index) => index === 0 || !/[A-Za-z0-9_-]/.test(source[index - 1]!),

  // Both rules key off a *name* — anything called password, secret, apiKey — and
  // accept any string as its value, so UI copy lands as a critical:
  // `password: "That password didn't match. Try again."` was one. A credential
  // is an opaque token, not a sentence and not a placeholder.
  VG001: (match) => looksLikeSecretValue(match),
  VG062: (match) => looksLikeSecretValue(match),

  // A statement whose values go through bind placeholders is parameterized:
  // `db.prepare(\`UPDATE ${table} SET csv_data = ? WHERE id = ?\`).bind(...)`
  // interpolates an identifier, not user input, and both rules read that as
  // injection. Held to two conditions, so a query that binds one value and
  // concatenates another still fires: there must be a placeholder, and no
  // interpolated expression may read from the request.
  // The string check: a `db.query(\`SELECT …${v}\`)` that sits inside a string
  // literal is example code being *described* — a rule-definition file's own
  // `description:` field carried two criticals. Code in a string is data.
  VG010: (match, source, index, spans) =>
    !isInside(spans, index, 'string') && sqlGuard(match, source, index),

  // The "base64 payload" test is a run of 20+ characters from the base64
  // alphabet, which any long camelCase identifier satisfies:
  // `description: \`${pct(clusteredAroundMedian, …)}\`` matched on the
  // identifier. Interpolated expressions are code, not the description text,
  // and real encoded content is not purely alphabetic.
  VG881: (match) => {
    const text = match.replace(/\$\{[^}]*\}/g, ' ');
    if (/(?:\\x[0-9a-f]{2}){4,}|(?:\\u[0-9a-f]{4}){4,}|(?:&#\d{2,4};){4,}/i.test(text)) return true;
    const run = /[A-Za-z0-9+/]{20,}={0,2}/.exec(text)?.[0];
    // A slash is not evidence: "new/used/refurbished" is twenty characters of
    // the base64 alphabet and a sentence. Real encoded content carries digits
    // or padding.
    return run !== undefined && /[0-9+=]/.test(run);
  },

  // `eval("require")` is the documented escape hatch for keeping a bundler from
  // statically resolving a require — a constant the author typed, with no input
  // reaching it. Dynamic code execution is about the dynamic part.
  VG014: (match, source, index, spans) => {
    if (isInside(spans, index, 'string')) return false;
    const after = source.slice(index, index + 60);
    return !/^(?:eval|new\s+Function)\s*\(\s*(['"])[A-Za-z_$][\w$]*\1\s*\)/.test(after);
  },

  // `$executeRawUnsafe` is named for who builds the SQL string, not for whether
  // values can be bound — Prisma takes positional parameters after the query.
  // `$executeRawUnsafe(\`INSERT … VALUES ${placeholders}\`, ...params)`, where
  // `placeholders` is `chunk.map(() => "(?, ?)").join(",")`, binds every value.
  VG433: (_match, source, index) => !isParameterized(statementAround(source, index)),

  // The rule's own fix text is "add an auth check at the top of every Server
  // Action that calls a paid LLM provider" — but the pattern only sees a
  // `'use server'` module that constructs a provider and exports a function. It
  // cannot tell whether the auth check is already there, and CTS001 can:
  // matching on the module's own vocabulary keeps this from contradicting it.
  VG1025: (_match, source) =>
    !/\b(auth\.getUser|getServerSession|getServerAuthSession|requireUser|requireAuth|requireUserId|currentUser|handleSessionToken|verifyRequest|getSession)\s*\(/.test(
      source,
    ),

  // `jwt.sign(payload, getJwtSecret(), { expiresIn: TOKEN_EXPIRY })` was
  // reported as a token without expiry: the pattern's `[^)]` scan for
  // `expiresIn` stops at the first `)`, which here belongs to `getJwtSecret()`.
  // Read the whole call before saying the option is absent.
  VG061: (_match, source, index) =>
    !/\b(expiresIn|exp\s*:|setExpirationTime)\b/.test(source.slice(index, index + 300)),

  // `console.log("[App] Got idToken, running audit...")` is a progress message,
  // not a logged credential: "idToken," satisfies the rule's `token` + delimiter
  // because both sit inside the string. What matters is whether the *value* is
  // being logged, and CTS070 checks that against the AST.
  VG080: (match, source, index, spans) => !isInside(spans, index + match.length - 1, 'string'),

  // The "sink" half of the upload rule matched the word *upload* inside a
  // sentence — "Please upload a CSV file exported from Shopify". A filename
  // reaching a string is not a filename reaching a filesystem.
  VG993: (match, source, index, spans) => !isInside(spans, index + match.length - 1, 'string'),

  // A login endpoint is server code. This fired on `<Link href="/login">Back to
  // sign in</Link>` in a client page, where "verify" and "login" are words in
  // markup rather than a password comparison behind an HTTP handler.
  VG148: (match, source) =>
    !/^\s*(['"])use client\1/m.test(source.slice(0, 400)) &&
    /(bcrypt\.compare|argon2\.verify|\b(compare|verify|verifyPassword)\s*\()/.test(match),

  // SSRF is a *server* being made to fetch a URL it should not. A module marked
  // `'use client'` runs in the browser, where the request leaves the user's own
  // machine and crosses no trust boundary of yours.
  //
  // Three more things the pattern cannot tell apart, all of them on the corpus.
  // The rule's own name is "SSRF via User-Controlled URL" and its description
  // says "user-controlled input is passed directly to fetch()", but what it
  // matches is `fetch(` followed by any bare identifier — the same gap between
  // a rule's name and its pattern that VG1008 had.
  //
  // 1. A *definition* is not a call. `export default { fetch(request, env, ctx)
  //    { … } }` is the Cloudflare Workers entry point — the most common shape
  //    there is — and `fetch(request, env, ctx)` one line below it delegates
  //    the same Request object to the next handler. Neither takes a URL at all;
  //    WHATWG `fetch` has two parameters, so a three-argument one is never it.
  //    VG105 was fixed for reading a declaration as a call in 0.13.10; this is
  //    the same mistake in another rule.
  // 2. SSRF is about controlling the *host*. The pattern already refuses
  //    `fetch("https://…")` and `fetch(`${process.env.X}/…`)` written inline;
  //    one `const` in between defeats it, which is how it is normally written.
  //    `const endpoint = "https://biz.dataly.us/api/cron/run-schedules"` and
  //    `const url = `${baseUrl}/v3/company/${realmId}/query?…`` over a
  //    literal or env-derived base are not URLs an attacker can point
  //    anywhere, whatever the path says. So the origin is resolved up to two
  //    assignments back; a bare identifier whose origin cannot be established
  //    stays reported, the line VG012 draws.
  // 3. A URL that went through an SSRF validator is the fix, not the bug.
  //    app E's `fetchNoOpenRedirect` calls `assertFetchableImageUrl(startUrl)`,
  //    sets `redirect: 'manual'`, bounds the chain at three hops and
  //    re-validates every `Location` — it implements what this rule's own
  //    `fix` text asks for, and was reported `high` for it.
  VG120: (match, source, index) => {
    if (/^\s*(['"])use client\1/m.test(source.slice(0, 400))) return false;
    const arg = /([A-Za-z_$]\w*)\s*[,)]\s*$/.exec(match)?.[1];
    const args = argumentList(source, index);
    // A method shorthand or function declaration: `fetch(request, env, ctx) {`
    // — its *own* argument list is followed by the body's brace. Read off the
    // matching close paren, not a regex: `[^)]{0,120}\)\s*\{` found the next
    // `if (…) {` after an ordinary call and cleared it, which is how an
    // app B edge function's `fetch(imageUrl)` went quiet.
    if (
      args &&
      /^\s*(?::\s*[\w<>[\].|,? ]+\s*)?\{/.test(args.after) &&
      /^\s*(?:async\s+)?(?:function\s*\*?\s*)?fetch\s*\(/.test(match)
    ) {
      return false;
    }
    // `fetch(request, env, ctx)` — three arguments is never WHATWG fetch, which
    // takes two. This is a Workers handler, or a delegation to one.
    //
    // Counted by walking the argument list, not by regex: the first version of
    // this used `[^(),]{1,40},\s*[^(),]{1,40},` and a character class does not
    // stop at an object literal, so `fetch(url, { method, headers })` — the
    // commonest shape there is — read as three arguments and was cleared.
    // app G's `fetch(url, { ...opts, signal: controller.signal })` is how
    // that turned up, on a `url` that is a bare parameter.
    if (args && args.arity >= 3) return false;
    if (!arg) return true;
    const scope = enclosingBody(source, index);
    // A function that returns before the fetch when there is no `window` runs
    // only in a browser, where the request crosses no trust boundary of yours —
    // the same judgement as the `'use client'` check above, for an isomorphic
    // module that states it at the top of the function instead of the file.
    // Read from a bounded window rather than `scope`, because the fetch is
    // normally a few frames in (`srcs.map(async (url) => { … fetch(url) })`)
    // and the guard sits at the top of the function that owns the map.
    if (
      /typeof\s+window\s*===?\s*(['"])undefined\1[^;\n]{0,80}\breturn\b/.test(
        source.slice(Math.max(0, index - 1500), index),
      )
    ) {
      return false;
    }
    if (
      /^[A-Za-z_$][\w$]*$/.test(arg) &&
      (SSRF_VALIDATED.test(scope) || SSRF_VALIDATED.test(source.slice(0, index)))
    ) {
      // Credited only when the validated value is the one being fetched, or is
      // what it was assigned from.
      if (new RegExp(`\\b${arg}\\b\\s*=[^;\\n]{0,200}?${SSRF_VALIDATED.source}`).test(source)) {
        return false;
      }
    }
    return !hasKnownOrigin(arg, source, index, 4);
  },

  // Both of these learned an API name that moved. The Vercel AI SDK replaced
  // `maxSteps` with `stopWhen`, and across a corpus of real agent apps
  // (vercel/ai-chatbot, assistant-ui, the MCP reference servers) `stopWhen` is
  // now the *more* common of the two — 21 files to 14. VG1033 looks only for
  // `maxSteps` / `max_iterations`, and VG999 does not count a step cap at all,
  // so between them they report every correctly-bounded agent loop written
  // against the current SDK. `stopWhen: stepCountIs(5)` is the fix these rules
  // are asking for, and it was being reported as the bug.
  //
  // Read from the whole call, not just the matched head: the regexes stop at
  // the opening brace, so the option that answers them sits past the match.
  VG1033: (_match, source, index) => !HAS_STEP_CAP.test(source.slice(index, index + 1200)),
  VG999: (_match, source, index) => !HAS_STEP_CAP.test(source.slice(index, index + 1200)),

  // The negative lookahead in this rule can never fire: its tempered run may be
  // empty, so any `)` within 500 characters of the call's `(` completes a
  // match, and `new ApolloServer({ introspection: false })` — the fix the rule
  // asks for, and the rule's own `fixCode` — was reported as the problem. Read
  // the call's real argument list for the setting instead.
  VG974: (_match, source, index) =>
    !/\bintrospection\s*:\s*(?:false\b|[^,}\n]*(?:NODE_ENV|production|isProd|isDev))|useDisableIntrospection/.test(
      callArgs(source, index),
    ),

  // The rule is named "Weak *password* hashing" and its pattern is any md5 or
  // sha1 use at all, so `hashlib.md5(hostname + mac)` — deriving a stable
  // device id, with nothing secret in sight — was two criticals on one app.
  // MD5 is only this finding when a password is what goes in, so a password
  // has to be somewhere near the call. An etag, cache key or machine id is not
  // weakly hashed; it is not a secret at all.
  VG060: (_match, source, index) =>
    /\b(?:password|passwd|pwd|passphrase)\b/i.test(
      source.slice(Math.max(0, index - 400), index + 400),
    ),

  // The name list is prefix-matched with `\w*` after it, so `hashPage === 'x'`
  // and `tokenCount === 3` read as secret comparisons. A timing attack needs the
  // *secret itself* on one side, so the identifier has to be one of those words,
  // not merely start with one.
  VG106: (match) => {
    const identifier = /^[A-Za-z_$][\w$]*/.exec(match)?.[0] ?? '';
    return /(secret|token|apikey|api_key|signature|hmac|hash|digest|webhook)$/i.test(identifier);
  },

  // "An attacker can request the entire table" is the rule's premise, and a
  // query filtered to the caller's own rows does not let them. An unbounded
  // fetch of your own data is a scalability question, not a security finding.
  VG955: (match) =>
    !/\bwhere\b[\s\S]{0,200}?\b(userId|user_id|ownerId|owner_id|orgId|org_id|organizationId|tenantId|tenant_id|workspaceId|workspace_id|accountId|account_id|teamId|team_id|shop|shopDomain|storeId|store_id)\b/i.test(
      match,
    ),

  // The rule's own name is "…Without Authorization Check", and its pattern
  // contains no notion of one: it matches `.update({ is_admin: true })` and
  // reports critical whatever sits above it. So a route that reads the caller's
  // own admin flag, returns 403 when it is not set, and only then promotes
  // somebody — the shape the rule's `fixCode` asks for — was reported as the
  // bug, while CTS001 read the same function and (correctly) said nothing. Two
  // criticals on correct code is the worst failure this project has, and the
  // same contradiction CTS001 already settles for VG1025 above.
  VG1008: (_match, source, index) => !AUTHORIZATION_CHECK.test(enclosingBody(source, index)),

  // The rule is about a *tool schema's* enum list being computed at runtime, so
  // its JSON-Schema branch looks for `"enum":` followed by a lowercase name.
  // `case "enum": return "≡";` is that, character for character — a switch over
  // a JSON-Schema type name, mapping it to an icon or a badge colour. Seven
  // findings across app C's query builder and type-colour table, every one
  // a switch label; the `case` keyword in front and the `return` behind it are
  // both visible from the match. A statement keyword can never be a schema's
  // enum values, and a `case` label is not an object property.
  VG1021: (match, source, index) => {
    if (/^["']enum["']/.test(match)) {
      if (/\bcase\s*$/.test(source.slice(Math.max(0, index - 12), index))) return false;
      if (/^["']enum["']\s*:\s*(?:return|break|continue|throw|yield|await|new|typeof|delete|void|in|instanceof)\b/.test(match)) {
        return false;
      }
    }
    return true;
  },

  // "Server-Only Module Missing in Sensitive File": a module that reads a
  // secret and imports from `next` but never marks itself `server-only` could
  // be pulled into a client component, taking the secret into the bundle. A
  // route handler cannot be. `app/**/route.ts` is a route entry point that Next
  // invokes on the server — it is not importable from a client component, which
  // is the whole hazard the rule exists for, and `server-only` in one would
  // guard nothing. Six of the seven findings on the corpus were route handlers
  // (`api/cron/run-schedules`, `api/shopify/callback`, `auth/quickbooks/callback`
  // …), reported `high` on line 1, at the import. The seventh is a shared
  // `src/lib/session.js` that really is importable from both sides, and stays.
  // Pages and layouts are server components by default in the App Router and
  // are equally not importable, so they are credited the same way.
  VG964: (_match, _source, _index, _spans, relPath) =>
    !/(?:^|\/)app\/.*\/(?:route|page|layout|template|default|error|loading|not-found)\.[cm]?[jt]sx?$/.test(
      relPath ?? '',
    ) && !/(?:^|\/)pages\/api\/.*\.[cm]?[jt]sx?$/.test(relPath ?? ''),

  // `select('*', { count: 'exact', head: true })` is Supabase's own documented
  // way to count rows: `head: true` sends the request with `Prefer: head=true`
  // and returns **no rows at all**, only the count header. The rule's pattern
  // stops at the `'*'` and never reads the second argument, so a query that
  // returns zero columns was reported as "Exposes All Columns" — three of
  // app F's eleven, all of them rate-limit counters in edge functions.
  // Without `head: true` the rows do come back alongside the count, so that
  // stays reported; the other eight are real `select('*')` fetches and are
  // untouched.
  VG1006: (_match, source, index) => {
    const call = source.slice(index, index + 220);
    return !/\.select\s*\(\s*(?:["']\*["']|)\s*,[^)]*\bhead\s*:\s*true\b/.test(call);
  },

  // "XSS via innerHTML" is about untrusted data reaching the sink, and the
  // pattern is `innerHTML\s*=\s*` with a lookahead for a quoted `<` — so
  // anything that is not a literal starting with a tag is a high finding. This
  // project's own landing page was the proof, the moment HTML files started
  // being read at all: `out.innerHTML = LINES.map(l => '<span>' + esc(l[1]) +
  // '</span>').join('\n')` — a hardcoded constant, escaped on the way in,
  // reported as cross-site scripting. An expression with no dynamic part, or
  // whose dynamic parts go through an escaper, is not this; `el.innerHTML = '<b>'
  // + data.name` still is.
  VG012: (_match, source, index) => {
    if (inStyleElement(source, index)) return false;
    const expr = assignedExpression(source, index);
    if (ESCAPES_HTML.test(expr)) return false;
    return hasDynamicPart(expr);
  },

  // Check-then-act is a race when the value checked is the value written — the
  // credits balance of the rule's own example. An access-control gate has the
  // same shape and is not: `select('is_admin').single()` → `if (!admin) return
  // 403` → `update(...)` is how an admin endpoint is supposed to be written,
  // and no amount of concurrency makes the caller an admin. Reported critical
  // on exactly that, beside VG1008, on the same correct route.
  //
  // Two more shapes with the same select-if-write outline and no race worth the
  // word, all four of this rule's hits in the sweep:
  // — the select and the write touch *different tables*: a profile page that
  //   counts the user's posts and later saves their notification prefs is
  //   load-then-save, not check-then-act — nothing read is what gets written.
  // — a count-based guard clause that *rejects* and otherwise appends the very
  //   row being counted (`if (count >= 5) return 429` → `.insert(…)`) is how
  //   every soft rate limiter is written; concurrency can overshoot the limit
  //   by the number of in-flight requests, which is the accepted property of
  //   the pattern, not a critical.
  // The credits race keeps both its tables the same and its write an update,
  // and stays reported — pinned by its regression test.
  VG154: (match) => {
    if (AUTHORIZATION_CHECK.test(match)) return false;
    const act = /\.(update|insert|delete|upsert)\s*\(/.exec(
      match.slice(match.search(/\bif\s*\(/) + 1),
    );
    const actIndex = act ? match.search(/\bif\s*\(/) + 1 + act.index : -1;
    if (act && actIndex !== -1) {
      const tables = [...match.matchAll(/\.from\s*\(\s*["']([^"']+)["']\s*\)/g)];
      const checked = tables[0]?.[1];
      const actedOn = tables.filter((t) => t.index! < actIndex).at(-1)?.[1];
      if (checked && actedOn && checked !== actedOn) return false;
      if (act[1] === 'insert') {
        // The first `if` body: reject-and-return, then an append, is a rate
        // limiter or dedupe, not a lost update. `[^{;]` lets the condition
        // carry its own nested parens (`if ((count ?? 0) >= 5)`).
        const cond = /\bif\s*\([^{;]{0,300}?\)\s*\{?\s*(return|throw)\b/.exec(match);
        if (cond) return false;
      }
    }
    return true;
  },

  // What is left of VG530 once `PATTERN_FIXES` has stopped its span crossing
  // lines: an install command *printed* rather than run. A build script whose
  // job is to tell a human how to install the thing ends with
  // `echo "   curl -fsSL https://…/install.sh | bash"`, and emitting that line
  // is not executing it. Code in a string is data — the same line VG010 and
  // VG014 draw — but only where the string is being written out, because
  // `bash -c "curl … | bash"` and `ssh host "curl … | bash"` are strings too
  // and both really do fetch and run it.
  VG530: (_match, source, index, spans) => {
    if (!isInside(spans, index, 'string')) return true;
    const lineStart = source.lastIndexOf('\n', index) + 1;
    return !SHELL_PRINTS.test(source.slice(lineStart, index));
  },

};
