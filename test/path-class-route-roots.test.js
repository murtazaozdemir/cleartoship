import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';
import { pathClass, adjustForPath } from '../dist/utils/paths.js';

// Found 2026-11-12 while checking whether `adjustForPath` should be wired into
// the four scanners that skip it. It should not have been -- the premise was
// backwards. The demotion was already too aggressive: `pathClass` read
// `app/docs/`, `app/examples/`, `app/demo/` and `pages/docs/` as
// non-production, because the directory names appear in the test/docs family.
//
// In Next.js those are ROUTES. `app/docs/page.tsx` is the page served at
// `/docs`, reachable by anyone on the internet, and the identical XSS reported
// `high` in `app/billing/page.tsx` and `low` in `app/docs/page.tsx` -- with the
// note "Path looks like tests, fixtures or docs, so the severity is reduced."
// A false alarm gets argued with; a silent demotion of a live route never gets
// seen at all.
//
// So directory-name markers are split: the ones that mean the same thing
// anywhere (tests, specs, fixtures, mocks, cypress, testdata, and the
// `.test.`/`.stories.` FILE suffixes) still win everywhere; the ambiguous ones
// (docs, examples, demo, samples, stories as a directory) lose to a route root.

async function scanProject(files) {
  const dir = mkdtempSync(join(tmpdir(), 'routeroot-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.28', react: '19.0.0' } }),
  );
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return scan({ root: dir, offline: true, noCommunity: false });
}

const XSS = `export default function P({ searchParams }: any) {
  const raw = searchParams.html;
  return <div dangerouslySetInnerHTML={{ __html: raw }} />;
}
`;

const UNAUTH_ACTION = `"use server";
import { db } from "../../lib/db";
export async function deleteEverything(id: string) {
  await db.workspace.delete({ where: { id } });
  return { ok: true };
}
`;

test('a weak marker inside a Next.js route root is a route segment, not a hint', () => {
  // These are all addressable pages and handlers.
  assert.equal(pathClass('app/docs/page.tsx'), 'production');
  assert.equal(pathClass('app/examples/page.tsx'), 'production');
  assert.equal(pathClass('app/demo/actions.ts'), 'production');
  assert.equal(pathClass('app/samples/route.ts'), 'production');
  assert.equal(pathClass('src/app/docs/page.tsx'), 'production');
  assert.equal(pathClass('pages/docs/api/export.ts'), 'production');
});

test('the same names outside a route root still mean documentation', () => {
  assert.equal(pathClass('docs/guide.md'), 'non-production');
  assert.equal(pathClass('examples/basic.yml'), 'non-production');
  assert.equal(pathClass('demo/seed.ts'), 'non-production');
  assert.equal(pathClass('samples/report.json'), 'non-production');
});

test('a real test marker still wins, even inside a route root', () => {
  assert.equal(pathClass('app/__tests__/login.ts'), 'non-production');
  assert.equal(pathClass('app/e2e-tests/login.ts'), 'non-production');
  assert.equal(pathClass('app/docs/page.test.tsx'), 'non-production');
  assert.equal(pathClass('app/fixtures/user.json'), 'non-production');
  // A Storybook story is a story wherever it lives: the FILE suffix is
  // reliable even though a `stories/` directory inside `app/` is not.
  assert.equal(pathClass('app/docs/Button.stories.tsx'), 'non-production');
  // This repo's own fixtures must keep demoting -- they contain a whole
  // deliberately-vulnerable `app/` tree, and it is not anybody's route.
  assert.equal(pathClass('test/fixtures/vulnerable-app/app/actions/admin.ts'), 'non-production');
});

test('adjustForPath leaves a route-root severity alone and still floors a real test path', () => {
  // The value, not merely "not the worst case": the CVSS mapping was dead for a
  // year behind an assertion that only ruled out `low`.
  assert.equal(adjustForPath('critical', 'app/docs/actions.ts').severity, 'critical');
  assert.equal(adjustForPath('critical', 'app/docs/actions.ts').note, '');
  assert.equal(adjustForPath('critical', 'docs/actions.ts').severity, 'low');
  assert.match(adjustForPath('critical', 'docs/actions.ts').note, /severity is reduced/);
});

test('an XSS in app/docs is reported as loudly as the same XSS in app/billing', async () => {
  const result = await scanProject({ 'app/docs/page.tsx': XSS, 'app/billing/page.tsx': XSS });
  const sev = (file) => result.findings.filter((f) => f.file === file && f.id === 'VG012').map((f) => f.severity);
  assert.deepEqual(sev('app/billing/page.tsx'), ['high']);
  assert.deepEqual(sev('app/docs/page.tsx'), ['high'], 'app/docs/ is the page served at /docs');
});

test('an unauthenticated Server Action under app/docs is still critical', async () => {
  const result = await scanProject({
    'app/docs/actions.ts': UNAUTH_ACTION,
    'app/billing/actions.ts': UNAUTH_ACTION,
  });
  for (const file of ['app/docs/actions.ts', 'app/billing/actions.ts']) {
    const found = result.findings.filter((f) => f.file === file && f.id === 'CTS001');
    assert.equal(found.length, 1, `${file} should report CTS001 once`);
    assert.equal(found[0].severity, 'critical', `${file} is addressable`);
  }
});

// ---------------------------------------------------------------------------
// Harness files named `<something>-test.mjs` rather than `<something>.test.mjs`
// ---------------------------------------------------------------------------
//
// Reported 2026-11-13 with a count, which is what made it worth fixing: 38
// files across the portfolio carry the hyphen shape, 23 of them in one app, and
// only ONE had produced a finding so far. The other 37 were a standing exposure
// for every rule that demotes on a harness path.
//
// The dot is the convention the strong list was written for. The hyphen is just
// as common for a standalone harness invoked by name rather than collected by a
// runner -- `node scripts/scoring-test.mjs`. Such a file usually sits in
// `scripts/`, which only demotes ONE step, so a finding in a test harness was
// arriving at `high` rather than `low`. Go's `_test.go` was already in the
// strong list for exactly this reason; this is the same convention everywhere
// else.
//
// Checked against the real files before demoting anything, because a demotion
// that is wrong is a missed finding: the ones this now covers are a smoke test
// with its own `assert()`, a scoring-verification harness and a round-trip-cost
// harness. All three are run by name and ship nothing.

test('a hyphenated harness name reads as non-production, like _test.go already did', () => {
  for (const p of [
    'scripts/client-behaviour-test.mjs',
    'scripts/smoke-test.mjs',
    'scripts/worker-smoke-test.cjs',
    'scoring-test.mjs',
    'src/fuzz-test.ts',
    'src/hardening-test.tsx',
    'worker_test.py',
  ]) {
    assert.equal(pathClass(p), 'non-production', p);
  }
});

test('A/B testing is a production feature, and `ab-test.ts` is what it gets called', () => {
  // The expensive direction to be wrong in: demoting this turns a real finding
  // in request-handling code into a `low`. The exception is listed explicitly in
  // paths.ts rather than hidden in a lookahead, so it can be argued with.
  for (const p of ['src/ab-test.ts', 'src/a-b-test.tsx', 'src/split-test.ts', 'lib/multivariate-test.js']) {
    assert.equal(pathClass(p), 'production', p);
  }
});

test('a word that merely ends in "test" is not a harness', () => {
  // `[-_]test` is required, not `test`: the separator is the whole signal.
  for (const p of ['src/lib/latest.ts', 'src/protest.ts', 'src/contest.js', 'src/lib/attest.ts']) {
    assert.equal(pathClass(p), 'production', p);
  }
});

test('the demotion is stated in the finding, not applied silently', () => {
  // Same requirement as the route-root case above: a silent demotion of a live
  // file never gets argued with.
  const placed = adjustForPath('critical', 'scripts/smoke-test.mjs');
  assert.equal(placed.severity, 'low');
  assert.match(placed.note ?? '', /test|fixture|doc/i);
});
