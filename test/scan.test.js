import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../dist/index.js';
import { splitStatements, normaliseTable, isAlwaysTrue, clauseAfter } from '../dist/utils/sql.js';
import { editDistance, nearestPopular, POPULAR_NPM } from '../dist/data/popular.js';
import { Suppressions } from '../dist/utils/suppress.js';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');
const CLI = join(here, '..', 'dist', 'cli.js');

const ids = (result) => new Set(result.findings.map((f) => f.id));

test('vulnerable fixture: reports every rule it is built to trigger', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const found = ids(result);
  for (const expected of [
    'CTS001', // missing Server Action / Route Handler auth
    'CTS002', // no runtime input validation
    'CTS003', // service-role key inside an action
    'CTS004', // authenticated but not owner-scoped
    'CTS010', // public table, RLS off
    'CTS012', // always-true write policy
    'CTS013', // sensitive columns readable by anon
    'CTS014', // owner column with no auth.uid() policy
    'CTS015', // SECURITY DEFINER without search_path
    'CTS016', // definer-rights view in public
    'CTS017', // write grant to anon
    'CTS018', // policy trusts user_metadata
    'CTS019', // auth.users republished through a public view
    'CTS028', // install hook runs network/shell code
    'CTS030', // hardcoded secret
    'CTS031', // secret behind NEXT_PUBLIC_
    'CTS032', // .env not gitignored
    'CTS033', // client component reads a server secret
    'CTS040', // client component reads a server env var
    'CTS041', // getSession() used as a server-side auth check
    'CTS042', // webhook without signature verification
    'CTS043', // request body spread into a write
    'CTS044', // schema opts out of validating
    'CTS045', // AI client allowed to run in the browser
    'CTS046', // cron endpoint callable by anyone
    'CTS050', // overlapping permissive policies
    'CTS051', // storage policy allows listing every object
    'CTS052', // SECURITY DEFINER function callable by anon
  ]) {
    assert.ok(found.has(expected), `expected ${expected} to be reported`);
  }
});

test('vulnerable fixture: locations point at the offending line', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const byId = (id) => result.findings.find((f) => f.id === id);

  assert.equal(byId('CTS010').line, 16, 'CTS010 should point at the CREATE TABLE, not the closing paren');
  assert.equal(byId('CTS017').line, 50);
  const definerView = result.findings.find((f) => f.id === 'CTS016' && f.severity === 'medium');
  assert.equal(definerView.line, 47, 'the SECURITY DEFINER view is at line 47');
  const matview = result.findings.find((f) => f.id === 'CTS016' && f.severity === 'high');
  assert.equal(matview.line, 55, 'the materialized view is at line 55');
  assert.equal(byId('CTS001').file, 'app/actions/admin.ts');
});

test('vulnerable fixture: the correctly written action is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const safe = result.findings.filter((f) => f.file === 'app/actions/safe.ts');
  assert.deepEqual(safe, [], `safe.ts should be clean, got ${safe.map((f) => f.id).join(', ')}`);
});

test('vulnerable fixture: secrets are redacted in the reported snippet', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  for (const f of result.findings.filter((f) => f.id === 'CTS030')) {
    assert.ok(f.snippet.includes('…'), `snippet should be redacted: ${f.snippet}`);
    assert.ok(f.snippet.length <= 160);
  }
});

test('clean fixture: no findings at all', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(
    result.findings.map((f) => `${f.id} ${f.file}:${f.line}`),
    [],
  );
  assert.ok(result.checks.every((c) => c.passed));
});

test('scan honours --ignore, --only and --min-severity equivalents', async () => {
  const all = await scan({ root: VULNERABLE, offline: true });
  const ignored = await scan({ root: VULNERABLE, offline: true, ignore: ['CTS001'] });
  assert.ok(all.findings.length > ignored.findings.length);
  assert.ok(!ids(ignored).has('CTS001'));

  const only = await scan({ root: VULNERABLE, offline: true, only: ['CTS010'] });
  assert.deepEqual([...ids(only)], ['CTS010']);

  const criticals = await scan({ root: VULNERABLE, offline: true, minSeverity: 'critical' });
  assert.ok(criticals.findings.every((f) => f.severity === 'critical'));
});

test('inline suppression comments silence a rule', () => {
  const sup = new Suppressions(
    ['const a = 1', '// cleartoship-ignore CTS001', 'const b = 2', 'const c = 3 // cts-ignore'].join('\n'),
  );
  assert.equal(sup.suppressed(3, 'CTS001'), true);
  assert.equal(sup.suppressed(3, 'CTS002'), false);
  assert.equal(sup.suppressed(4, 'CTS999'), true, 'bare cts-ignore suppresses everything on the line');
});

test('SQL splitter records the first token line, not trailing whitespace', () => {
  const sql = ['-- a comment', '', 'create table a (id int);', '', '', 'create table b (id int);'].join('\n');
  const statements = splitStatements(sql);
  assert.equal(statements.length, 2);
  assert.equal(statements[0].line, 3);
  assert.equal(statements[1].line, 6);
});

test('SQL splitter does not break inside dollar-quoted bodies', () => {
  const sql = "create function f() returns void as $$ begin raise notice 'a; b'; end; $$ language plpgsql;\nselect 1;";
  const statements = splitStatements(sql);
  assert.equal(statements.length, 2);
  assert.ok(statements[0].text.includes('raise notice'));
});

test('SQL helpers normalise names and detect permissive predicates', () => {
  assert.equal(normaliseTable('"public"."posts"'), 'public.posts');
  assert.equal(normaliseTable('posts'), 'public.posts');
  assert.equal(isAlwaysTrue('true'), true);
  assert.equal(isAlwaysTrue('(true)'), true);
  assert.equal(isAlwaysTrue('user_id = auth.uid()'), false);
  assert.equal(clauseAfter('using (a = (b))', /\busing\s*(?=\()/i), 'a = (b)');
});

test('edit distance handles transposition and caps out', () => {
  assert.equal(editDistance('express', 'express'), 0);
  assert.equal(editDistance('expres', 'express'), 1);
  assert.equal(editDistance('exprses', 'express'), 1, 'transposition costs one');
  assert.equal(editDistance('completely', 'different', 2), 3);
});

test('typosquat matching skips exact names and very short names', () => {
  assert.equal(nearestPopular('express', POPULAR_NPM), null, 'a popular package is not its own squat');
  assert.equal(nearestPopular('next', POPULAR_NPM), null, 'next must not match nest');
  assert.equal(nearestPopular('ms', POPULAR_NPM), null, 'short names produce noise, not signal');
  assert.equal(nearestPopular('expres', POPULAR_NPM), 'express');
  assert.equal(nearestPopular('@types/react', POPULAR_NPM), null);
});

const runCli = (args) => {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return { code: 0, stdout };
  } catch (err) {
    return { code: err.status, stdout: err.stdout ?? '' };
  }
};

test('CLI exits 1 on the vulnerable fixture and 0 on the clean one', () => {
  assert.equal(runCli(['-C', VULNERABLE, '--offline', '--no-banner']).code, 1);
  assert.equal(runCli(['-C', CLEAN, '--offline', '--no-banner']).code, 0);
});

test('CLI --fail-on=none never fails the build', () => {
  assert.equal(runCli(['-C', VULNERABLE, '--offline', '--no-banner', '--fail-on', 'none']).code, 0);
});

test('CLI emits valid JSON, SARIF, a fix prompt and a badge', () => {
  const json = JSON.parse(runCli(['-C', VULNERABLE, '--offline', '--json']).stdout);
  assert.equal(json.tool, 'cleartoship');
  assert.equal(json.verdict, 'hold');
  assert.ok(json.findings.length > 10);

  const sarif = JSON.parse(runCli(['-C', VULNERABLE, '--offline', '--sarif']).stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'ClearToShip');
  assert.equal(sarif.runs[0].results.length, json.findings.length);
  for (const r of sarif.runs[0].results) {
    assert.ok(r.locations[0].physicalLocation.region.startLine >= 1);
  }

  const prompt = runCli(['-C', VULNERABLE, '--offline', '--fix-prompt']).stdout;
  assert.match(prompt, /# ClearToShip — security fixes to apply/);
  assert.match(prompt, /CTS001/);

  const badge = runCli(['-C', CLEAN, '--offline', '--badge']).stdout;
  assert.match(badge, /img\.shields\.io.*10b981/);
});

test('getSession() does not satisfy the auth check, and replaces CTS001 there', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const settings = result.findings.filter((f) => f.file === 'app/actions/settings.ts');
  const found = new Set(settings.map((f) => f.id));
  assert.ok(found.has('CTS041'), 'supabase.auth.getSession() must be reported');
  assert.ok(
    !found.has('CTS001'),
    'CTS041 is the precise diagnosis; the generic missing-auth rule should not double-report',
  );
});

test('hardcoded keys are not swallowed by placeholder heuristics', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const lines = result.findings.filter((f) => f.id === 'CTS030' && f.file === '.env').map((f) => f.line);
  // service-role JWT, Stripe live key, OpenAI key — one finding each.
  assert.deepEqual(lines.sort((a, b) => a - b), [2, 3, 4]);
});

test('install commands in prose are resolved like manifest dependencies', async () => {
  const { collectProseForTest } = await import('../dist/scanners/dependencies.js');
  const found = collectProseForTest(
    [
      '```bash',
      'npm install next react',
      'npm i -D typescript',
      'npx create-vibe-dashboard --template saas',
      'npm install ./local-package',
      'pip install supabase-py-async',
      '```',
    ].join('\n'),
    'AGENTS.md',
  ).map((d) => `${d.ecosystem}:${d.name}`);

  assert.ok(found.includes('npm:next'));
  assert.ok(found.includes('npm:create-vibe-dashboard'));
  assert.ok(found.includes('pypi:supabase-py-async'));
  assert.ok(!found.some((n) => n.includes('local-package')), 'local paths are not packages');
  assert.ok(!found.some((n) => n.includes('-D')), 'flags are not packages');
});

test('quoted or commented mentions of a risky flag are not findings', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.ok(!result.findings.some((f) => f.id === 'CTS045'));
});

// Registry-dependent rules can only be exercised with network access, so this
// test skips itself rather than turning a flaky connection into a red build.
const online = await fetch('https://registry.npmjs.org/zod', {
  headers: { accept: 'application/vnd.npm.install-v1+json' },
  signal: AbortSignal.timeout(5000),
}).then((r) => r.ok, () => false);

test('registry rules resolve hallucinated and lookalike packages', { skip: !online && 'offline' }, async () => {
  const result = await scan({ root: VULNERABLE });
  const found = ids(result);
  assert.ok(found.has('CTS020'), 'non-existent packages must be reported');
  assert.ok(found.has('CTS023'), 'expres must be matched against express');

  const hallucinated = result.findings
    .filter((f) => f.id === 'CTS020')
    .map((f) => f.meta.package);
  assert.ok(hallucinated.includes('tailwind-modal-components'));
  assert.ok(hallucinated.includes('create-vibe-dashboard'), 'names in AGENTS.md count too');

  // Real packages must never be reported as missing.
  assert.ok(!hallucinated.includes('next') && !hallucinated.includes('react'));
});
