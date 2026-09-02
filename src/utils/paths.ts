import { SEVERITY_ORDER } from '../types.js';
import type { Severity } from '../types.js';

/**
 * Where a file sits decides how much a finding in it matters. A dependency CVE
 * already gets this treatment — CTS024 separates what ships from what only ever
 * runs on a developer's machine — and the same reasoning applies to the rules
 * that read code: an interpolated query in a migration script you run by hand is
 * a different risk from one behind a public HTTP endpoint, and neither is the
 * same as one in a test fixture.
 */
export type PathClass = 'production' | 'dev-tooling' | 'non-production';

/** Tests, fixtures, examples and docs: the code is there to be read, not run. */
const NON_PRODUCTION =
  /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|spec|specs|examples?|docs?|demo|samples?|e2e|cypress|playwright|stories)(\/|$)|\.(test|spec|stories|fixture)\.[a-z]+$/i;

/**
 * Build and maintenance tooling. It runs on a developer's machine or in CI,
 * with credentials its author already holds, and never answers a request from
 * the internet — so nothing here is reachable by an attacker who is not already
 * inside the repository.
 *
 * `bin/` is deliberately absent: for a published CLI that is the shipped entry
 * point. So is `migrations/`, which is the production schema.
 */
const DEV_TOOLING =
  /(^|\/)(scripts?|tools?|tooling|\.github|\.husky|\.circleci|seeds?|benchmarks?|codegen)(\/|$)|(^|\/)[^/]*\.config\.[cm]?[jt]s$|(^|\/)(Makefile|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml)$/i;

export function pathClass(relPath: string): PathClass {
  if (NON_PRODUCTION.test(relPath)) return 'non-production';
  if (DEV_TOOLING.test(relPath)) return 'dev-tooling';
  return 'production';
}

const ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** One step down the scale, floored at `low`. */
export function demote(severity: Severity): Severity {
  const index = SEVERITY_ORDER[severity];
  return ORDER[Math.max(1, index - 1)]!;
}

/**
 * The severity a finding should carry once you know where it lives, plus the
 * sentence explaining the adjustment — always stated, never silent.
 */
export function adjustForPath(
  severity: Severity,
  relPath: string,
): { severity: Severity; note: string } {
  switch (pathClass(relPath)) {
    case 'non-production':
      return {
        severity: 'low',
        note: ' (Path looks like tests, fixtures or docs, so the severity is reduced.)',
      };
    case 'dev-tooling':
      return {
        severity: demote(severity),
        note:
          ' (Path is build or maintenance tooling rather than shipped code — it runs on a ' +
          'developer machine or in CI, not in response to a request — so the severity is one ' +
          'step lower than it would be in the app itself.)',
      };
    default:
      return { severity, note: '' };
  }
}
