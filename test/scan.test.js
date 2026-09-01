import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { buildFixtures } from './fixture-setup.js';
import { scan } from '../dist/index.js';
import { splitStatements, normaliseTable, isAlwaysTrue, clauseAfter } from '../dist/utils/sql.js';
import { editDistance, nearestPopular, POPULAR_NPM } from '../dist/data/popular.js';
import { Suppressions } from '../dist/utils/suppress.js';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');
const CLI = join(here, '..', 'dist', 'cli.js');

// Credential-shaped fixture state is generated, never committed.
buildFixtures();

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

test('--no-community leaves only ClearToShip rules', async () => {
  const withCommunity = await scan({ root: VULNERABLE, offline: true });
  const withoutCommunity = await scan({ root: VULNERABLE, offline: true, noCommunity: true });

  assert.ok(withCommunity.findings.some((f) => f.id.startsWith('VG')));
  assert.ok(!withoutCommunity.findings.some((f) => f.id.startsWith('VG')));
  assert.ok(withCommunity.findings.length > withoutCommunity.findings.length);
});

test('vendored rules add coverage without duplicating our own', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const community = result.findings.filter((f) => f.id.startsWith('VG'));
  assert.ok(community.length > 0, 'the community ruleset should contribute findings');

  // Every vendored finding must carry its attribution.
  for (const f of community) {
    assert.equal(f.meta.source, 'guardvibe');
    assert.match(f.meta.attribution, /Apache-2\.0/);
  }

  // A superseded rule must never appear beside the rule that replaced it.
  const ids = new Set(community.map((f) => f.id));
  for (const superseded of ['VG400', 'VG401', 'VG402', 'VG427', 'VG952', 'VG1007']) {
    assert.ok(!ids.has(superseded), `${superseded} is superseded and must not fire`);
  }
});

test('suppression directives work from the top of a comment block', () => {
  const sup = new Suppressions(
    [
      'const a = 1',
      '// cleartoship-ignore VG010 — this is why,',
      '// and here is the second line of the reason.',
      'const b = 2',
    ].join('\n'),
  );
  assert.equal(sup.suppressed(4, 'VG010'), true, 'directive may start the comment block');
  assert.equal(sup.suppressed(4, 'VG999'), false, 'other rules are unaffected');
  assert.equal(sup.suppressed(1, 'VG010'), false, 'code above the block is unaffected');
});

test('vendored gitleaks rules cover providers the built-in patterns do not', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const gl = result.findings.filter((f) => f.id.startsWith('GL-'));
  assert.ok(gl.length > 0, 'the gitleaks ruleset should contribute findings');

  for (const f of gl) {
    assert.equal(f.meta.source, 'gitleaks');
    assert.match(f.meta.attribution, /MIT/);
    assert.ok(typeof f.meta.entropy === 'number');
    assert.ok(f.snippet.includes('…'), `snippet must be redacted: ${f.snippet}`);
  }

  const rules = new Set(gl.map((f) => f.id));
  assert.ok(rules.has('GL-npm-access-token'), 'npm token should be detected');
});

test('noisy gitleaks rules are withheld', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const ids = new Set(result.findings.map((f) => f.id));
  assert.ok(!ids.has('GL-generic-api-key'), "gitleaks' catch-all is too noisy to ship");
  assert.ok(!ids.has('GL-sourcegraph-access-token'), 'it matches any 40-char hex, i.e. every SHA');
});

test('a built-in pattern is not double-reported by a gitleaks rule', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const byLocation = new Map();
  for (const f of result.findings.filter((f) => f.id === 'CTS030' || f.id.startsWith('GL-'))) {
    const key = `${f.file}:${f.line}`;
    byLocation.set(key, (byLocation.get(key) ?? 0) + 1);
  }
  for (const [where, count] of byLocation) {
    assert.equal(count, 1, `${where} reported ${count} times by overlapping credential rules`);
  }
});

test('entropy scoring separates real keys from filler', async () => {
  const { shannonEntropy } = await import('../dist/utils/entropy.js');
  assert.ok(shannonEntropy('npm_7Kq2Xw9ZbR4tYn6Vm1Pj8Ld3Hs5Gf0Ec7Ua2') > 4);
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('your_api_key_here') < 4);
  assert.equal(shannonEntropy(''), 0);
});

test('lockfile-free projects still resolve a version for OSV', async () => {
  // The vulnerable fixture has no lockfile, so `next: "14.2.3"` must resolve
  // from the manifest range floor for the CVE check to run at all.
  const result = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    !result.checks.some((c) => c.label.startsWith('Known vulnerabilities')),
    'OSV must not run offline',
  );
});

test('OSV reports real advisories for a known-vulnerable version', { skip: !online && 'offline' }, async () => {
  const result = await scan({ root: VULNERABLE });
  const cves = result.findings.filter((f) => f.id === 'CTS024');
  assert.ok(cves.length > 0, 'next@14.2.3 has published advisories');

  const next = cves.find((f) => f.meta.package === 'next');
  assert.ok(next, 'the vulnerable next version should be flagged');
  assert.equal(next.meta.version, '14.2.3');
  assert.ok(next.meta.advisories.length > 1);
  assert.match(next.title, /CVE-|GHSA-/);

  // With live data available, the hand-written CVE regexes must stand down.
  const { GUARDVIBE_CVE_RULE_IDS } = await import('../dist/vendor/guardvibe/index.js');
  assert.ok(
    !result.findings.some((f) => GUARDVIBE_CVE_RULE_IDS.has(f.id)),
    'vendored CVE-version rules should defer to OSV when it answered',
  );
});

test('yarn.lock is parsed without a backtracking-prone regex', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');

  const dir = mkdtempSync(join(tmpdir(), 'cts-yarn-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', dependencies: { next: '^14.0.0', zod: '^3.0.0' } }),
  );
  writeFileSync(
    join(dir, 'yarn.lock'),
    [
      '# yarn lockfile v1',
      '',
      '"next@npm:^14.0.0", next@^14.0.0:',
      '  version "14.2.3"',
      '  resolved "https://registry.yarnpkg.com/next/-/next-14.2.3.tgz"',
      '',
      'zod@^3.0.0:',
      '  version: 3.23.8',
      '',
    ].join('\n'),
  );

  const { scan: run } = await import('../dist/index.js');
  const started = Date.now();
  const result = await run({ root: dir, offline: true });
  // A catastrophic-backtracking parser would not return promptly.
  assert.ok(Date.now() - started < 5000);
  assert.ok(Array.isArray(result.findings));
});

test('markdown report is well-formed for both verdicts', async () => {
  const { renderMarkdown } = await import('../dist/index.js');

  const vuln = renderMarkdown(await scan({ root: VULNERABLE, offline: true }));
  assert.match(vuln, /## 🔴 ClearToShip — hold before shipping/);
  assert.match(vuln, /\| Severity \| Rule \| Finding \| Location \|/);
  assert.match(vuln, /`CTS001`/);
  assert.match(vuln, /<details><summary>/, 'lower-severity findings should be collapsible');
  // A GitHub comment must not exceed 65536 bytes.
  assert.ok(Buffer.byteLength(vuln) < 65536, 'comment body must fit GitHub limit');

  const clean = renderMarkdown(await scan({ root: CLEAN, offline: true }));
  assert.match(clean, /clear to ship/);
  assert.match(clean, /No security findings/);
  assert.ok(!clean.includes('| Severity |'), 'no table when there is nothing to report');
});

test('the shipped GitHub Action is structurally sound', () => {
  const yml = readFileSync(join(here, '..', 'action.yml'), 'utf8');
  assert.ok(!/\t/.test(yml), 'YAML must not contain tabs');
  assert.match(yml, /using: composite/);
  // The two runner paths the action can take.
  assert.match(yml, /npx --yes cleartoship@/, 'should prefer the published package');
  assert.match(yml, /node \$\{GITHUB_ACTION_PATH\}\/dist\/cli\.js/, 'should fall back to a local build');
  // Balanced GitHub expression braces.
  const opens = (yml.match(/\$\{\{/g) || []).length;
  const closes = (yml.match(/\}\}/g) || []).length;
  assert.equal(opens, closes, 'unbalanced ${{ }} expressions');
  // Every declared output must be produced by the scan step.
  for (const out of ['verdict', 'critical', 'high', 'total']) {
    assert.match(yml, new RegExp(`${out}=`), `output ${out} must be written`);
  }
});
