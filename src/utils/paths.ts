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

/**
 * Tests, fixtures and mocks: markers that mean the same thing wherever they
 * appear. A path matching one of these is not shipped code, full stop.
 *
 * The test family accepts an affix — `transfer-tests/`, `integration_test/` —
 * because that is how those directories get named. Every segment must be
 * followed by a slash: these are directories, and a file named
 * `spec-parser.ts` is production code that happens to parse specs.
 */
const NON_PRODUCTION_STRONG =
  // `_test.go` and `testdata/` are Go's own conventions, and `test_*.py` /
  // `conftest.py` are pytest's: none of them spells "test" the JavaScript way,
  // so a Go scanner's 187 fixture keys were criticals while the same strings
  // in a `.test.ts` were low.
  /(^|\/)(?:(?:[\w.]+[-_])?(?:tests?|specs?|e2e|fixtures?|mocks?)(?:[-_][\w.]+)?|__tests__|__mocks__|__fixtures__|cypress|playwright|testdata)\/|\.(test|spec|stories|fixture)\.[a-z]+$|_test\.go$|(^|\/)(?:test_[^/]*\.py|conftest\.py)$/i;

/**
 * Directory names that usually mean "written to be read, not run" — and that
 * stop meaning it the moment they sit inside a framework's route root.
 *
 * `app/docs/page.tsx` is not documentation. It is the page served at `/docs`,
 * reachable by anyone on the internet, and an XSS there is worth exactly what
 * the same XSS is worth in `app/billing/`. Before this split, it was reported
 * at `low` with the note "Path looks like tests, fixtures or docs" — a silent
 * demotion of a live route, which is the worst failure available here: not a
 * false alarm someone argues with, but a real one they never see.
 *
 * `demo` and `stories` are matched whole on purpose, so `demo-billing/` stays
 * production. A `*.stories.tsx` FILE is still a Storybook story wherever it
 * lives, and stays above in the strong list; it is only the directory name
 * that is unreliable.
 */
const NON_PRODUCTION_WEAK = /(^|\/)(?:examples?|docs?|demo|samples?|stories)\//i;

/**
 * Next.js route roots. Anything under one of these is compiled into the app
 * and addressable, whatever a directory along the way is called — which is why
 * a weak marker loses to this and a strong one does not.
 */
const ROUTE_ROOT = /^(?:src\/)?(?:app|pages)\//i;

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
  /(^|\/)(scripts?|tools?|tooling|\.github|\.husky|\.circleci|seeds?|benchmarks?|codegen)\/|(^|\/)[^/]*\.config\.[cm]?[jt]s$|(^|\/)(Makefile|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml)$/i;

/**
 * A harness file named `<something>-test.mjs` rather than `<something>.test.mjs`.
 *
 * The dot is the convention the strong list above was written for, and the
 * hyphen is just as common for standalone harnesses invoked by name rather than
 * collected by a runner: `smoke-test.mjs`, `scoring-test.mjs`,
 * `client-behaviour-test.mjs`. None of `.test.`, `.spec.` or a `tests/`
 * directory reaches any of them, and such a file usually sits in `scripts/`,
 * which only demotes one step -- so a finding in a test harness was arriving at
 * `high`.
 *
 * Measured across this portfolio by the auditor, 2026-11-13: **38 files** carry
 * this shape, 23 of them in one app, and only one had produced a finding so far.
 * The other 37 were a standing exposure for every rule that demotes on harness
 * paths. Go's `_test.go` is in the strong list already for the same reason; this
 * is the same convention everywhere else.
 */
const HARNESS_SUFFIX = /(^|\/)[^/]*[-_]test\.(?:[cm]?jsx?|[cm]?tsx?|py)$/i;

/**
 * Names that end in `-test` and are not tests.
 *
 * A/B testing is a production feature, and `ab-test.ts` is what it gets called.
 * Demoting it would turn a real finding in request-handling code into a `low`,
 * which is the expensive direction to be wrong in -- so the exception is
 * explicit and listed rather than hidden in a lookahead, because the next person
 * to read it needs to be able to argue with it.
 */
const AB_TEST_FEATURE = /(^|\/)(?:ab|a[-_]b|split|multivariate)[-_]test\.[^/]+$/i;

export function pathClass(relPath: string): PathClass {
  if (NON_PRODUCTION_STRONG.test(relPath)) return 'non-production';
  if (HARNESS_SUFFIX.test(relPath) && !AB_TEST_FEATURE.test(relPath)) return 'non-production';
  // A weak marker inside a route root is a route segment, not a hint about
  // what the file is for. `test/fixtures/<app>/app/...` still reads as
  // non-production, because the strong marker above matched first.
  if (NON_PRODUCTION_WEAK.test(relPath)) {
    return ROUTE_ROOT.test(relPath) ? 'production' : 'non-production';
  }
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
 * One step up the scale, capped at `critical`.
 *
 * The mirror of `demote`, for the case where the surrounding context makes a
 * finding worse than the rule alone knows: a credential that would be a
 * contained problem on the server is a different problem once the file it sits
 * in is compiled into the bundle every visitor downloads.
 */
export function promote(severity: Severity): Severity {
  const index = SEVERITY_ORDER[severity];
  return ORDER[Math.min(ORDER.length - 1, index + 1)]!;
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
