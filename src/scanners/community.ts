import { performance } from 'node:perf_hooks';
import { read, rel, languagesFor } from '../utils/files.js';
import { LineIndex, clip } from '../utils/line-index.js';
import { redactCredential } from '../utils/entropy.js';
import { Suppressions } from '../utils/suppress.js';
import { adjustForPath } from '../utils/paths.js';
import { TEXT_FIXES, effectiveText } from './community-text.js';
import { PATTERN_FIXES, PATTERN_OVERRIDES, effectivePattern } from './community-patterns.js';
export { PATTERN_FIXES, PATTERN_OVERRIDES, effectivePattern };
import { commentStyleFor, lexSpans, isInside } from '../utils/spans.js';
// The matcher engine lives in its own file; re-exported because the ReDoS
// and override tests import these from here.
import { MATCH_GUARDS } from './community-guards.js';
import { SEVERITY_ADJUSTERS } from './community-severity.js';
import { LinearMatcher, linearInIrregexp, matcherFor } from './linear-regex.js';
import type { Matcher } from './linear-regex.js';
export { LinearMatcher, linearInIrregexp, matcherFor };
export type { Matcher };
import type { Span } from '../utils/spans.js';
import {
  GUARDVIBE_RULES,
  GUARDVIBE_ATTRIBUTION,
  GUARDVIBE_REACT_NATIVE_RULE_IDS,
  GUARDVIBE_CVE_RULE_IDS,
} from '../vendor/guardvibe/index.js';
import { emptyResult } from '../types.js';
import type { ProjectContext, ScanResult, Scanner, Severity } from '../types.js';

/**
 * Upstream rules that restate a check ClearToShip already performs against the
 * AST or the parsed schema. The AST version reasons about a whole function body
 * instead of a fixed character window, so it is both more accurate and better
 * located — running both would double-report and import the weaker result.
 *
 * These are disabled here rather than deleted from the vendored files, so those
 * stay a faithful copy of upstream and re-vendoring is a straight overwrite.
 *
 * Those marked inline are superseded by the RLS and Server Actions scanners
 * (`rls.ts`, `server-actions.ts`). They stay suppressed on purpose: standing the
 * vendored versions up as fallback coverage reported `VG1010` — critical — on
 * `clean-app`'s `updateProfile`, a Server Action proven safe by the fixture's own
 * doc comment (an explicit field list, no caller-controlled columns). The vendored
 * version is "the weaker result" for a reason: it is a no-schema-library-detected
 * pattern match, not real argument-flow analysis, and running it would trade the
 * precise first-party result for a false "critical" on correct code — worse for a
 * tool whose whole trust model is "a true positive a developer will act on, not
 * coverage for its own sake."
 */
const SUPERSEDED = new Map<string, string>([
  ['VG400', 'CTS033/CTS040'],
  ['VG401', 'CTS002'], // Server Actions suite
  ['VG402', 'CTS001'], // Server Actions suite
  ['VG411', 'CTS031'],
  ['VG420', 'CTS001'], // Server Actions suite
  ['VG427', 'CTS041'], // Server Actions suite
  ['VG439', 'CTS016'], // RLS suite
  ['VG604', 'CTS031'],
  ['VG627', 'CTS031'],
  ['VG631', 'CTS031'],
  ['VG655', 'CTS031'],
  ['VG656', 'CTS030'],
  ['VG657', 'CTS030'],
  ['VG665', 'CTS030'],
  ['VG671', 'CTS031'],
  ['VG708', 'CTS030'],
  ['VG754', 'CTS031'],
  ['VG953', 'CTS043'], // Server Actions suite
  ['VG998', 'CTS045'],
  ['VG437', 'CTS033'],
  ['VG860', 'CTS028'],
  ['VG874', 'CTS028'],
  ['VG876', 'CTS031'],
  ['VG952', 'CTS001'], // Server Actions suite
  ['VG960', 'CTS044'], // Server Actions suite
  ['VG1007', 'CTS003'], // Server Actions suite
  ['VG1010', 'CTS002'], // Server Actions suite
  // Same defect, same line, twice: CTS081 reads the call's own option keys for
  // `max_tokens` / `maxTokens` / `maxOutputTokens` off the AST, and only where
  // the call is reachable from a request — which is the calibration, not an
  // omission. A model call in a build script with no ceiling is not a bill
  // anyone else can run up.
  ['VG999', 'CTS081'], // LLM & agent suite
  // Every callee VG123 names (`query`, `execute`, `prepare`, `db.run`…) is in
  // VG010's own verb list, followed by the same backtick-plus-`${` shape, so the
  // two reported the same line twice across the sweep (24 of 24 VG123 findings).
  // Upstream agrees — its own test comments call VG010 "the concat rule (which
  // dedup-takes-over)". What VG123 added beyond the duplicates was only the
  // matches VG010's guard had dropped for not being SQL at all
  // (`querySelectorAll`-class verbs with no SQL keyword in the statement).
  ['VG123', 'VG010'],
  // VG408 matches `dangerouslySetInnerHTML={{ __html:` and VG012 matches
  // `innerHTML` followed by `=` or `:` — and `dangerouslySetInnerHTML` *ends*
  // in `InnerHTML`, case-insensitively, so every VG408 match is a VG012 match
  // at the same position. Proven, not assumed: 15 of 15 raw VG408 matches
  // across the seven dogfooding repos, and by construction too — VG408 needs a
  // `{` after the `=`, which is exactly what VG012's `(?!['"]<)` lookahead
  // lets through.
  //
  // Keeping both did not merely double-report. The 2026-10-13 audit spent a
  // pass teaching VG012 the difference between an HTML sink and a `<style>`
  // element's CSS text, an all-literal expression, and a value already through
  // an escaper. VG408 carries no guard, so it reported all of it again under a
  // different id: eight `<style dangerouslySetInnerHTML={{ __html: css }} />`
  // on app C — the very shape that audit cleared — plus three
  // `sanitizeJsonLd(...)` / `sanitizeThemeInit(...)` calls, and three lines
  // where it simply said what VG012 had already said. Fourteen findings, not
  // one of them a true positive VG012 does not already report. A guarded rule
  // beside an unguarded copy of itself means the guard does nothing.
  ['VG408', 'VG012'],
]);

/**
 * Rules withheld because they misfire in this tool's context, measured against
 * the fixtures plus the reference corpus. Each is recorded with its reason so
 * the judgement can be revisited when upstream changes.
 */
const WITHHELD = new Map<string, string>([
  [
    'VG543',
    'matches `; DROP|DELETE|INSERT|…` anywhere in a .sql file, which is the normal shape of ' +
      'every migration — 43 hits across the corpus, all false',
  ],
  [
    'VG146',
    'an unquoted `.env` value, but declared `languages: ["shell"]`, and `languagesFor` returns ' +
      '`shell` only for `.sh`/`.bash` — so a `.env` never reaches this scanner and the rule ' +
      'cannot fire on its own subject. What it matches is `NAME=$(…)` and `NAME=${VAR:-x}` in ' +
      'shell scripts: command substitution and parameter expansion, where quoting them as the ' +
      'fix instructs breaks the script. Fires on nearly every one of a 272-script corpus that ' +
      'sets a variable. Withheld rather than superseded because the premise is real; reviving ' +
      'it means giving dotenv files their own language token, not feeding them to shell rules',
  ],
  [
    'VG540',
    'flags any destructive DDL in a .sql file; migrations legitimately drop and alter objects',
  ],
  [
    'VG542',
    'flags DELETE/UPDATE without WHERE in .sql files, where a full-table statement in a ' +
      'migration is deliberate',
  ],
  [
    'VG863',
    'a packaging lint (missing "files" field), not a security finding, and wrong for apps ' +
      'rather than published libraries',
  ],
  [
    'VG865',
    'declares itself a `.npmignore` lint but is registered for the `shell` language, so it ' +
      'matches almost every line of every shell script — 6 hits on two `scripts/*.sh` files, ' +
      'all false, and it is a packaging lint rather than a security finding either way',
  ],
  [
    'VG1004',
    'matches every `use server` module with an exported function; it asserts "no rate limiting" ' +
      'without ever checking for it',
  ],
]);

/**
 * Machine-generated dependency lockfiles. Their entries describe the *transitive*
 * graph, which nobody in this repo wrote or can edit directly.
 */
const LOCKFILE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|Pipfile\.lock|poetry\.lock)$/i;

/**
 * Rules whose signal only exists in a hand-authored manifest. The same JSON
 * shapes appear all over a lockfile describing packages a dependency chose, so
 * a hit there is both unactionable and, measured on the dogfooding corpus,
 * wrong: `fast-glob`, `fast-deep-equal`, `common-tags`, `core-js` and
 * `simple-statistics` all trip the deceptive-prefix list, and the "wildcard
 * version" rule fires on transitive `"node": ">=16"` engine constraints.
 * Declared package names are covered properly by CTS020-CTS027, which ask the
 * registry rather than matching a prefix.
 */
const MANIFEST_ONLY = new Map<string, string>([
  ['VG872', 'internal-name heuristic; in a lockfile it names a transitive dependency'],
  ['VG873', 'deceptive-prefix heuristic; matches ordinary transitive package names'],
  ['VG020', 'wildcard version; a transitive range is the dependency author\'s choice'],
]);



// ---------------------------------------------------------------------------
// Linear-time matching
// ---------------------------------------------------------------------------
//
// The overrides above fix four patterns by hand. Fuzzing the whole ruleset
// the same way — each rule's own trigger words, prefixes of its matches and
// its quantifiers pumped, at 16 KB to 400 KB — found 209 of the 435 active
// patterns over 50 ms at 400 KB, 151 over the 250 ms time budget, and 125
// past eight seconds. The shape is almost always the same: a trigger, then a
// gap (`[\s\S]{0,500}?`, `[^)]*`, `.*`, `\s*`) the engine tries every end of,
// from every trigger. `eval.*\(` alone spends 50 s on a 400 KB line of `eval`,
// inside one uninterruptible `exec`. Rewriting 200 patterns by hand, and
// proving each rewrite, is not a job that ends; so they are not rewritten.
//
// Instead each one is run, unchanged, by a small backtracking matcher that
// explores exactly the paths V8's own would, in the same order — so it finds
// exactly the same match — but remembers every (state, position) it has
// already seen fail, and never explores one twice. A failed path depends only
// on where it is in the pattern and in the text (these patterns have no
// backreferences), so skipping a repeat can change nothing but the time. What
// is left is linear in the text, times the size of the pattern.
//
// Speed comes from letting V8's engine do everything it does in linear time:
// finding where a match could start, testing single characters and short
// lookaheads, listing where a character class breaks. A pattern V8 already
// searches in linear time (`linearInIrregexp`) is not routed here at all.
// `test/redos-overrides.test.js` compares the two engines on every rule.

/**
 * Files up to the walker's own 2 MB cap are run through the ruleset. This was
 * 400 KB, and a file between the two was skipped here without a word: an
 * `eval(req.body.code)` in a 420 KB module was never looked at, the run said
 * clear, and nothing said why.
 *
 * The 400 KB cap existed for a real reason — fuzzing the ruleset with each
 * rule's own trigger word repeated finds patterns whose cost grows with the
 * square of the input — so the files above it are not handed to a regex whole.
 * They are searched in line-aligned windows (below), which caps what one
 * uninterruptible `exec` can cost at what a WINDOW-sized input costs, and
 * makes the total linear in the size of the file. Every pattern V8 could
 * backtrack on now runs on the linear-time matcher instead, so the windows
 * are a second line of defence; they also bound the matcher's per-position
 * tables to a window's size.
 */
const MAX_BYTES = 2_000_000;

/** Files above this are searched in windows rather than whole. The old cap, so nothing it scanned changes. */
const WINDOW_FROM = 400_000;
/** Each window owns this many characters: a match is taken from the window it starts in. */
const WINDOW = 64_000;
/**
 * How far past its own region a window reads, so a match that starts near the
 * end of one window can finish. Real matches for these rules are a few
 * hundred characters; a match longer than this starting in the last stretch
 * of a window would be missed, and that is the only difference windowing makes.
 */
const WINDOW_OVERLAP = 16_000;

/**
 * A rule that spends longer than this per 400 KB of input on one file is
 * behaving super-linearly on it. It is not run on any file at least half that
 * size again (a quadratic rule at half the size costs a quarter), and each file
 * it was not run on is reported as not checked. The budget is checked before
 * each search, so a rule that exceeds it part-way through a file stops there,
 * and that file is reported too.
 *
 * With every pattern either linear in V8 or on the linear-time matcher, this
 * is a safety net rather than the thing that contains ReDoS: the worst input
 * the whole-ruleset fuzz and a hill-climbing search could find costs one rule
 * about 120 ms per 400 KB on a loaded developer machine.
 */
const RULE_BUDGET_MS = 250;

function budgetFor(length: number): number {
  return RULE_BUDGET_MS * Math.max(1, length / WINDOW_FROM);
}

/**
 * A pattern anchored to the start of its *input* (leading `^` without the `m`
 * flag — VG964 reads the whole module through lookaheads from there) or to its
 * end (`$`: VG446) would match at window boundaries, so it is run over the
 * whole file. A `(?:^|\n)` alternative is fine windowed: windows start on a
 * line, where it would match anyway.
 */
export function anchoredToInput(re: { readonly multiline: boolean; readonly source: string }): boolean {
  if (re.multiline) return false;
  const source = re.source.replace(/\\\\/g, '').replace(/\[(?:\\.|[^\]\\])*\]/g, '');
  return source.startsWith('^') || /(?:^|[^\\])\$/.test(source);
}

interface Segment {
  /** Offset of `text` in the file. */
  start: number;
  /** Matches starting at or past this offset belong to the next segment. */
  ownEnd: number;
  text: string;
}

/** The whole file, or line-aligned windows of it for a large file. */
function segmentsOf(source: string, whole: boolean): Segment[] {
  if (whole || source.length <= WINDOW_FROM) {
    return [{ start: 0, ownEnd: source.length, text: source }];
  }
  const segments: Segment[] = [];
  let start = 0;
  while (start < source.length) {
    let ownEnd = Math.min(source.length, start + WINDOW);
    if (ownEnd < source.length) {
      const newline = source.indexOf('\n', ownEnd);
      // A file with no newline for a long way is still windowed, just not on a line.
      ownEnd = newline === -1 || newline - ownEnd > WINDOW_OVERLAP / 2 ? ownEnd : newline + 1;
    }
    const end = Math.min(source.length, ownEnd + WINDOW_OVERLAP);
    segments.push({ start, ownEnd: ownEnd >= source.length ? source.length : ownEnd, text: source.slice(start, end) });
    start = ownEnd;
  }
  return segments;
}

/**
 * `lexSpans` declines inputs over 1 MB and returns no spans, which would read
 * every comment in a 1-2 MB file as code. Lex it in line-aligned halves
 * instead; only a block comment or template literal straddling the split can
 * be misread.
 */
function lexLarge(source: string, style: ReturnType<typeof commentStyleFor>): Span[] {
  const LIMIT = 900_000;
  if (source.length <= LIMIT) return lexSpans(source, style);
  const spans: Span[] = [];
  let start = 0;
  while (start < source.length) {
    let end = Math.min(source.length, start + LIMIT);
    if (end < source.length) {
      const newline = source.lastIndexOf('\n', end);
      if (newline > start) end = newline + 1;
    }
    for (const s of lexSpans(source.slice(start, end), style)) {
      spans.push({ start: s.start + start, end: s.end + start, kind: s.kind });
    }
    start = end;
  }
  return spans;
}

/**
 * Vendored rules about a credential, by their own name. Their match is the
 * credential more often than not, and the snippet printed it whole: `VG003`
 * on `--api-key sk_live_…` quoted the live key into the report.
 */
const CREDENTIAL_RULE =
  /hardcoded|hard-coded|secret|credential|api key|token|password|connection string|service account key/i;

/**
 * The line with every credential-looking value inside `match` redacted: a
 * quoted value with no spaces in it, or an opaque run of 16+ characters with a
 * digit (which leaves variable names like `STRIPE_SECRET_KEY` readable).
 */
function redactMatchInLine(lineText: string, match: string): string {
  const values = new Set<string>();
  for (const q of match.matchAll(/(["'`])([^\s"'`]{8,})\1/g)) values.add(q[2]!);
  for (const run of match.matchAll(/[A-Za-z0-9_\-+/=.]{16,}/g)) {
    if (/\d/.test(run[0]) && !/^(?:process\.env|import\.meta)/.test(run[0])) values.add(run[0]);
  }
  let text = lineText;
  for (const value of [...values].sort((a, b) => b.length - a.length)) {
    text = text.split(value).join(redactCredential(value));
  }
  return clip(text.trim());
}

/** Upstream severities already use our vocabulary; this just narrows the type. */
function severityOf(value: string): Severity {
  return (['critical', 'high', 'medium', 'low', 'info'] as const).includes(value as Severity)
    ? (value as Severity)
    : 'medium';
}

/**
 * Rules that only apply on a platform this project is not. Skipping them is not
 * a judgement about the rule — it is that the advice cannot be followed here.
 */
function inapplicable(ctx: ProjectContext): { ids: ReadonlySet<string>; why: string[] } {
  const ids = new Set<string>();
  const why: string[] = [];

  if (!ctx.framework.reactNative) {
    for (const id of GUARDVIBE_REACT_NATIVE_RULE_IDS) ids.add(id);
    why.push(`${GUARDVIBE_REACT_NATIVE_RULE_IDS.size} React Native rules (not a mobile project)`);
  }

  // VG132 asks for an explicit request-body size limit and says itself that
  // Next.js and Vercel already impose one. On a Next.js project it is advice
  // about a limit the framework has already applied.
  if (ctx.framework.nextjs !== null) {
    ids.add('VG132');
    why.push('VG132 body-size limit (Next.js sets one by default)');
  }

  // A rule that names a platform cannot apply to a project that does not use
  // it. "Supabase Auth Missing Middleware" was reported against an app with no
  // Supabase dependency at all — advice about a library it does not import.
  for (const [name, present, keyword] of [
    ['Supabase', ctx.framework.supabase, /supabase/i],
    ['Firebase', ctx.framework.firebase, /firebase|firestore/i],
  ] as const) {
    if (present) continue;
    let n = 0;
    for (const rule of GUARDVIBE_RULES) {
      if (keyword.test(rule.name) || keyword.test(rule.description)) {
        ids.add(rule.id);
        n++;
      }
    }
    if (n > 0) why.push(`${n} ${name} rules (no ${name} dependency)`);
  }

  return { ids, why };
}

/**
 * Whether a dependency-manifest match sits under `devDependencies`, or in a
 * lockfile entry marked `"dev": true`. Both mean the package is a build-time
 * tool that no user ever runs — the split CTS024 already makes for CVEs found
 * through OSV, applied to the vendored CVE rules that run when offline.
 */
function inDevDependencies(source: string, index: number): boolean {
  const before = source.slice(Math.max(0, index - 4000), index);
  if (/"dev"\s*:\s*true[\s\S]{0,600}$/.test(before)) return true;
  const nearest = /"(dev|peer|optional)?[dD]ependencies"\s*:\s*\{(?![\s\S]*"[a-z]*[dD]ependencies"\s*:\s*\{)/.exec(
    before,
  );
  return nearest?.[1] === 'dev';
}


/**
 * The counts the README quotes about this ruleset, exported so the docs can be
 * asserted against the code rather than remembered. The 2026-10-13 audit found
 * "435 additional rules vendored" (435 is the count that *runs*; 468 are
 * vendored) and "21 carry a match guard" (22 did) — two numbers no check read.
 */
export const RULE_COUNTS = {
  vendored: GUARDVIBE_RULES.length,
  superseded: SUPERSEDED.size,
  withheld: WITHHELD.size,
  guarded: Object.keys(MATCH_GUARDS).length,
  overridden: Object.keys(PATTERN_OVERRIDES).length,
  corrected: Object.keys(PATTERN_FIXES).length,
  reworded: Object.keys(TEXT_FIXES).length,
  manifestOnly: MANIFEST_ONLY.size,
  active: GUARDVIBE_RULES.length - SUPERSEDED.size - WITHHELD.size,
};

export const communityScanner: Scanner = {
  name: `Community ruleset (${GUARDVIBE_RULES.length - SUPERSEDED.size - WITHHELD.size} rules)`,

  applies() {
    return true;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const platform = inapplicable(ctx);
    const active = GUARDVIBE_RULES.filter(
      (r) => !SUPERSEDED.has(r.id) && !WITHHELD.has(r.id) && !platform.ids.has(r.id),
    );
    const seen = new Set<string>();
    let filesScanned = 0;
    // Files the ruleset did not read, or read only partly, and why.
    const oversize: string[] = [];
    const failed: string[] = [];
    // Rule id -> the size of the file on which it overran RULE_BUDGET_MS.
    const slowRules = new Map<string, number>();
    // Rule id -> files it was skipped on, or stopped part-way through.
    const unchecked = new Map<string, string[]>();
    const markUnchecked = (id: string, relPath: string) => {
      const list = unchecked.get(id) ?? [];
      list.push(relPath);
      unchecked.set(id, list);
    };

    for (const file of ctx.files) {
      const languages = languagesFor(file);
      if (languages.length === 0) continue;
      const relPath = rel(ctx.root, file);
      // One file that throws must cost that file, not the rest of the run.
      try {
      const source = read(file);
      if (source === null) continue;
      if (source.length > MAX_BYTES) {
        oversize.push(relPath);
        continue;
      }

      const lockfile = LOCKFILE.test(relPath);
      const spans = lexLarge(source, commentStyleFor(languages));
      const suppress = new Suppressions(source, relPath);
      const lines = new LineIndex(source);
      filesScanned++;

      for (const rule of active) {
        if (!rule.languages.some((l) => languages.includes(l))) continue;
        if (lockfile && MANIFEST_ONLY.has(rule.id)) continue;
        const slowAt = slowRules.get(rule.id);
        if (slowAt !== undefined && source.length >= slowAt / 2) {
          markUnchecked(rule.id, relPath);
          continue;
        }
        const guard = MATCH_GUARDS[rule.id];
        const credential = CREDENTIAL_RULE.test(rule.name);

        const re = matcherFor(effectivePattern(rule));
        let m: RegExpExecArray | null;
        let matches = 0;
        const started = performance.now();
        const budget = budgetFor(source.length);
        let cutShort = false;
        segments: for (const segment of segmentsOf(source, anchoredToInput(re))) {
        re.lastIndex = 0;
        // The budget is checked before each further search, so a match already
        // found is always handled and only the unsearched remainder is lost.
        for (;;) {
          if (performance.now() - started > budget) {
            cutShort = true;
            break segments;
          }
          m = re.exec(segment.text);
          if (m === null) break;
          // A zero-width match would spin forever on a global regex.
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          const index = segment.start + m.index;
          // Past this window's own region: the next window reads it from its start.
          if (index >= segment.ownEnd) break;
          // Skipping a match must not skip the non-global `break` below, or a
          // rule without /g would rescan from zero forever.
          // A rule that matched inside a comment matched prose about code, not
          // code. Nothing in the vendored ruleset targets comment content, and
          // a commented-out call is not a call.
          if (isInside(spans, index, 'comment')) {
            if (!re.global) break;
            continue;
          }
          if (guard && !guard(m[0], source, index, spans, relPath)) {
            if (!re.global) break;
            continue;
          }
          // Some rules open with `(?:^|\n)\s*`, so the match starts on the
          // newline ending the previous line. Locate the first character that
          // is actually part of the finding, or it is reported one line early.
          const line = lines.lineAt(index + (m[0].length - m[0].trimStart().length));
          const key = `${relPath}:${line}:${rule.id}`;
          if (!seen.has(key) && !suppress.suppressed(line, rule.id)) {
            seen.add(key);
            let adjusted = SEVERITY_ADJUSTERS[rule.id]?.(m[0], source, index) ?? null;
            // A CVE in something that only ever runs on a build machine is not
            // a shipping vulnerability. OSV-sourced findings are already split
            // this way (CTS024); this is the same split for the vendored CVE
            // rules, which are what runs with --offline.
            if (
              !adjusted &&
              GUARDVIBE_CVE_RULE_IDS.has(rule.id) &&
              (lockfile || /(^|\/)package\.json$/.test(relPath)) &&
              inDevDependencies(source, index)
            ) {
              adjusted = {
                severity: 'low',
                note:
                  ' (Reported at low: this version is declared under devDependencies, so it is a ' +
                  'build-time tool rather than something your users run.)',
              };
            }
            const placed = adjustForPath(adjusted?.severity ?? severityOf(rule.severity), relPath);
            const text = effectiveText(rule);
            result.findings.push({
              id: rule.id,
              severity: placed.severity,
              title: text.name,
              detail: text.description + (adjusted?.note ?? '') + placed.note,
              fix: text.fixCode ? `${text.fix}\n\n${text.fixCode}` : text.fix,
              file: relPath,
              line,
              snippet: credential
                ? redactMatchInLine(lines.lineText(line), m[0])
                : lines.snippet(line),
              owasp: rule.owasp,
              meta: {
                source: 'guardvibe',
                attribution: GUARDVIBE_ATTRIBUTION,
                compliance: rule.compliance,
              },
            });
          }
          // One finding per rule per file is enough to act on.
          if (++matches >= 3) break segments;
          if (!re.global) break;
        }
        }
        if (re instanceof LinearMatcher) re.release();
        if (cutShort) markUnchecked(rule.id, relPath);
        if (performance.now() - started > budget) {
          const previous = slowRules.get(rule.id);
          slowRules.set(rule.id, previous === undefined ? source.length : Math.min(previous, source.length));
        }
      }
      } catch (err) {
        failed.push(`${relPath} (${err instanceof Error ? err.message : String(err)})`);
      }
    }

    const notes = [
      `${SUPERSEDED.size} superseded by ClearToShip's AST checks, ${WITHHELD.size} withheld as noisy, ` +
        `${MANIFEST_ONLY.size} manifest-only (not run over lockfiles)`,
    ];
    if (Object.keys(PATTERN_FIXES).length > 0) {
      notes.push(
        `${Object.keys(PATTERN_FIXES).length} run with a corrected pattern in place of upstream's, ` +
          `which matched text the rule is not about (${Object.keys(PATTERN_FIXES).join(', ')})`,
      );
    }
    if (Object.keys(PATTERN_OVERRIDES).length > 0) {
      notes.push(
        `${Object.keys(PATTERN_OVERRIDES).length} run with a bounded pattern in place of upstream's ` +
          `(${Object.keys(PATTERN_OVERRIDES).join(', ')})`,
      );
    }
    // A reader comparing a finding against upstream GuardVibe's own text should
    // be told the wording is ours, not theirs — especially here, where the
    // correction is that upstream's advice names a flag npm does not have.
    if (Object.keys(TEXT_FIXES).length > 0) {
      notes.push(
        `${Object.keys(TEXT_FIXES).length} reported with corrected wording where upstream's own ` +
          `advice could not work (${Object.keys(TEXT_FIXES).join(', ')})`,
      );
    }
    const linear = active.filter((r) => matcherFor(effectivePattern(r)) instanceof LinearMatcher);
    if (linear.length > 0) {
      notes.push(`${linear.length} run by a linear-time matcher (same matches, no super-linear backtracking)`);
    }
    if (platform.why.length) notes.push(`skipped as inapplicable: ${platform.why.join(', ')}`);
    const incomplete = result.incomplete!;
    if (oversize.length > 0) {
      notes.push(`${oversize.length} file${oversize.length === 1 ? '' : 's'} over ${MAX_BYTES / 1_000_000} MB not read`);
      for (const f of oversize) {
        incomplete.push(`${f} is over the community ruleset's ${MAX_BYTES / 1_000_000} MB limit and was not checked by it.`);
      }
    }
    for (const [id, files] of [...unchecked].sort(([a], [b]) => a.localeCompare(b))) {
      const shown = `${files.slice(0, 3).join(', ')}${files.length > 3 ? `, and ${files.length - 3} more` : ''}`;
      notes.push(`${id} stopped on ${files.length} file${files.length === 1 ? '' : 's'} after exceeding its time budget (${RULE_BUDGET_MS} ms per 400 KB)`);
      incomplete.push(
        `${id} exceeded its time budget (${RULE_BUDGET_MS} ms per 400 KB of file) and was not run to completion on ${shown}; ` +
          'what it looks for there was not checked.',
      );
    }
    for (const f of failed) {
      incomplete.push(`The community ruleset could not finish ${f}; the rest of that file was not checked.`);
    }

    result.checks.push({
      label: `Community ruleset (${active.length} rules over ${filesScanned} files)`,
      passed: result.findings.every((f) => f.severity !== 'critical'),
      note: notes.join('; '),
    });
    return result;
  },
};
