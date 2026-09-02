import { read, rel, lineAt, snippetAt, languagesFor } from '../utils/files.js';
import { Suppressions } from '../utils/suppress.js';
import { GUARDVIBE_RULES, GUARDVIBE_ATTRIBUTION } from '../vendor/guardvibe/index.js';
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
 */
const SUPERSEDED = new Map<string, string>([
  ['VG400', 'CTS033/CTS040'],
  ['VG401', 'CTS002'],
  ['VG402', 'CTS001'],
  ['VG411', 'CTS031'],
  ['VG420', 'CTS001'],
  ['VG427', 'CTS041'],
  ['VG439', 'CTS016'],
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
  ['VG953', 'CTS043'],
  ['VG998', 'CTS045'],
  ['VG437', 'CTS033'],
  ['VG860', 'CTS028'],
  ['VG874', 'CTS028'],
  ['VG876', 'CTS031'],
  ['VG952', 'CTS001'],
  ['VG960', 'CTS044'],
  ['VG1007', 'CTS003'],
  ['VG1010', 'CTS002'],
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

/** SQL verbs strong enough that the call is about a database by itself. */
const SQL_VERBS = /^(query|execute|raw|sql|prepare|QueryRow|QueryContext)$/i;

/** Words that make a string a query rather than a sentence. */
const SQL_KEYWORDS = /\b(select|insert\s+into|update|delete\s+from|from|where|values|set)\b/i;

/** Whether `index` falls inside a quoted string on its own line. */
function insideStringLiteral(source: string, index: number): boolean {
  const lineStart = source.lastIndexOf('\n', index - 1) + 1;
  let quote: string | null = null;
  for (let i = lineStart; i < index; i++) {
    const ch = source[i];
    if (ch === '\\') {
      i++;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
    }
  }
  return quote !== null;
}

/**
 * Per-rule filters for a match shape the upstream regex cannot exclude on its
 * own. Given the matched text plus where it sat, so a guard can look around it.
 */
const MATCH_GUARDS: Record<string, (match: string, source: string, index: number) => boolean> = {
  // A `"link": true` entry is a workspace or pnpm symlink resolved to a path on
  // disk rather than a tarball, so it has no integrity hash by design. Thirty of
  // them in one pnpm-managed lockfile, every one reported as a false critical.
  VG870: (match) => !/"link"\s*:\s*true/.test(match),

  // The verb list has no word boundary in front of it and includes `all`, `get`
  // and `run`, so `querySelectorAll(\`[name="${CSS.escape(k)}"]\`)` reads as a
  // SQL call. Weak verbs have to be backed by something that looks like SQL;
  // `query`, `execute` and friends stand on their own. A real interpolated
  // `exec(\`INSERT INTO ...\`)` still matches — checked against one.
  VG010: (match) => {
    const verb = /^[A-Za-z_]+/.exec(match)?.[0] ?? '';
    return SQL_VERBS.test(verb) || SQL_KEYWORDS.test(match);
  },

  // `(?:child_process|cp)[\s\S]*?(?:exec|spawn…)` lets the bridge run to the end
  // of the file: one match measured 3,608 characters and 109 lines, pairing an
  // `import … from "node:child_process"` with an `exec(` far below it and
  // reporting the import as a critical. A real one is a single statement.
  VG011: (match) => (match.match(/\n/g)?.length ?? 0) <= 1,

  // "An attacker can request the entire table" is the rule's premise, and a
  // query filtered to the caller's own rows does not let them. An unbounded
  // fetch of your own data is a scalability question, not a security finding.
  VG955: (match) =>
    !/\bwhere\b[\s\S]{0,200}?\b(userId|user_id|ownerId|owner_id|orgId|org_id|organizationId|tenantId|tenant_id|workspaceId|workspace_id|accountId|account_id|teamId|team_id|shop|shopDomain|storeId|store_id)\b/i.test(
      match,
    ),

  // `description: 'eval() executes arbitrary code…'` is prose about eval, not a
  // call to it — and security tooling, which is a good deal of what gets
  // scanned, is full of that prose. Code held in a string is not code running
  // here; the eval that would run it is its own match, outside the quotes.
  VG014: (_match, source, index) => !insideStringLiteral(source, index),
};

/** Paths where a match is a fixture or documentation rather than shipped code. */
const NON_PRODUCTION_PATH =
  /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|spec|specs|examples?|docs?|demo|samples?|e2e|cypress|playwright|stories)(\/|$)|\.(test|spec|stories|fixture)\.[a-z]+$/i;

/** Regexes over very large files are where catastrophic backtracking bites. */
const MAX_BYTES = 400_000;

/** Upstream severities already use our vocabulary; this just narrows the type. */
function severityOf(value: string): Severity {
  return (['critical', 'high', 'medium', 'low', 'info'] as const).includes(value as Severity)
    ? (value as Severity)
    : 'medium';
}

export const communityScanner: Scanner = {
  name: `Community ruleset (${GUARDVIBE_RULES.length - SUPERSEDED.size - WITHHELD.size} rules)`,

  applies() {
    return true;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const active = GUARDVIBE_RULES.filter((r) => !SUPERSEDED.has(r.id) && !WITHHELD.has(r.id));
    const seen = new Set<string>();
    let filesScanned = 0;

    for (const file of ctx.files) {
      const languages = languagesFor(file);
      if (languages.length === 0) continue;
      const source = read(file);
      if (source === null || source.length > MAX_BYTES) continue;

      const relPath = rel(ctx.root, file);
      const fixture = NON_PRODUCTION_PATH.test(relPath);
      const lockfile = LOCKFILE.test(relPath);
      const suppress = new Suppressions(source);
      filesScanned++;

      for (const rule of active) {
        if (!rule.languages.some((l) => languages.includes(l))) continue;
        if (lockfile && MANIFEST_ONLY.has(rule.id)) continue;
        const guard = MATCH_GUARDS[rule.id];

        const re = rule.pattern;
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let matches = 0;
        while ((m = re.exec(source)) !== null) {
          // A zero-width match would spin forever on a global regex.
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          // Skipping a match must not skip the non-global `break` below, or a
          // rule without /g would rescan from zero forever.
          if (guard && !guard(m[0], source, m.index)) {
            if (!re.global) break;
            continue;
          }
          const line = lineAt(source, m.index);
          const key = `${relPath}:${line}:${rule.id}`;
          if (!seen.has(key) && !suppress.suppressed(line, rule.id)) {
            seen.add(key);
            result.findings.push({
              id: rule.id,
              severity: fixture ? 'low' : severityOf(rule.severity),
              title: rule.name,
              detail:
                rule.description +
                (fixture ? ' (Path looks like tests or docs, so the severity is reduced.)' : ''),
              fix: rule.fixCode ? `${rule.fix}\n\n${rule.fixCode}` : rule.fix,
              file: relPath,
              line,
              snippet: snippetAt(source, line),
              owasp: rule.owasp,
              meta: {
                source: 'guardvibe',
                attribution: GUARDVIBE_ATTRIBUTION,
                compliance: rule.compliance,
              },
            });
          }
          // One finding per rule per file is enough to act on.
          if (++matches >= 3) break;
          if (!re.global) break;
        }
      }
    }

    result.checks.push({
      label: `Community ruleset (${active.length} rules over ${filesScanned} files)`,
      passed: result.findings.every((f) => f.severity !== 'critical'),
      note:
        `${SUPERSEDED.size} superseded by ClearToShip's AST checks, ${WITHHELD.size} withheld as noisy, ` +
        `${MANIFEST_ONLY.size} manifest-only (not run over lockfiles)`,
    });
    return result;
  },
};
