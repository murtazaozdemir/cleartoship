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
    'VG1004',
    'matches every `use server` module with an exported function; it asserts "no rate limiting" ' +
      'without ever checking for it',
  ],
]);

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
      const suppress = new Suppressions(source);
      filesScanned++;

      for (const rule of active) {
        if (!rule.languages.some((l) => languages.includes(l))) continue;

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
        `${SUPERSEDED.size} superseded by ClearToShip's AST checks, ${WITHHELD.size} withheld as noisy`,
    });
    return result;
  },
};
