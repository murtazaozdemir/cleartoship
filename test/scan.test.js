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
import { Gitignore } from '../dist/utils/gitignore.js';
import { pathClass } from '../dist/utils/paths.js';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');
const INDIRECT = join(here, 'fixtures', 'indirect-auth-app');
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
    'CTS080', // caller text concatenated into a prompt (LLM01)
    'CTS081', // model call with no token ceiling (LLM10)
    'CTS082', // system prompt shipped to the browser (LLM07)
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

test('auth resolved in an imported helper counts as auth', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const action = result.findings.filter((f) => f.file === 'app/actions/team.ts');
  assert.deepEqual(
    action.map((f) => f.id),
    [],
    `renameTeam authenticates via requireUser() from @/lib/auth, got ${action
      .map((f) => `${f.id}@${f.line}`)
      .join(', ')}`,
  );
});

test('a shared-secret cron endpoint is authenticated, and its health check is not a finding', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const route = result.findings.filter((f) => f.file === 'app/api/cron/digest/route.ts');
  assert.deepEqual(
    route.filter((f) => f.id === 'CTS001' || f.id === 'CTS046').map((f) => `${f.id}@${f.line}`),
    [],
    'the POST compares Authorization against CRON_SECRET; the GET returns a constant',
  );
  // Nor is a route that never reads a body reported for not validating one.
  assert.equal(route.filter((f) => f.id === 'CTS002').length, 0);
});

test('lockfile entries are judged as lockfile entries', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const lock = result.findings.filter((f) => f.file === 'package-lock.json');

  // A workspace link resolves to a directory, so it has no integrity hash by
  // design; a tarball entry without one is the real finding.
  const integrity = lock.filter((f) => f.id === 'VG870');
  assert.equal(integrity.length, 1, 'only the tampered tarball entry should fire');
  assert.equal(integrity[0].snippet.includes('tampered-pkg'), true);

  // Name heuristics belong to a hand-written manifest: every one of these
  // matched a transitive dependency nobody in the project chose.
  for (const id of ['VG872', 'VG873', 'VG020']) {
    assert.equal(lock.some((f) => f.id === id), false, `${id} should not run over a lockfile`);
  }
});

test('where a file lives changes what a finding in it costs', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });

  // Build tooling: real finding, one step down, and the report says why.
  const seed = result.findings.filter((f) => f.file === 'scripts/seed.mjs');
  assert.ok(seed.length > 0, 'an interpolated query in a script is still reported');
  for (const f of seed) {
    assert.equal(f.severity, 'high', `${f.id} should be demoted from critical, not dropped`);
    assert.match(f.detail, /build or maintenance tooling/);
  }

  // The same shape in the app itself keeps its full severity.
  const app = result.findings.filter(
    (f) => f.id === 'VG010' && !f.file.startsWith('scripts/'),
  );
  assert.ok(
    app.every((f) => !/build or maintenance tooling/.test(f.detail)),
    'application code is not demoted',
  );
});

test('raw-SQL helpers are judged on whether the values are bound', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    bad.findings.some((f) => f.file === 'app/actions/raw-sql.ts' && f.id === 'VG433'),
    "`$executeRawUnsafe` with the caller's value inside the SQL text is reported",
  );

  // The same call, with the placeholder skeleton built in code and every value
  // passed after the query, is the documented safe form.
  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(clean.findings.map((f) => `${f.id} ${f.file}`), []);
});

test('a CVE in a build-time dependency is not a shipping vulnerability', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const cve = result.findings.filter((f) => f.id === 'VG903');
  assert.equal(cve.length, 2, 'the same rule matches both declarations');

  const shipped = cve.find((f) => f.snippet.includes('17.0.2'));
  const build = cve.find((f) => f.snippet.includes('16.14.0'));
  assert.equal(shipped.severity, 'high', 'a dependency your users run keeps its severity');
  assert.equal(build.severity, 'low', 'one under devDependencies does not');
  assert.match(build.detail, /devDependencies/);
});

test('a bound parameter is not an injection; a raw interpolation still is', async () => {
  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(
    clean.findings.map((f) => `${f.id} ${f.file}:${f.line}`),
    [],
    'binding the values and interpolating only the table name is the correct pattern',
  );

  // The same rule still fires where nothing is bound at all.
  const bad = await scan({ root: VULNERABLE, offline: true });
  assert.ok(
    bad.findings.some((f) => f.file === 'scripts/seed.mjs' && f.id === 'VG010'),
    'an interpolated query with no binds is still reported',
  );
});

test('path classification reads directories, not filenames', () => {
  assert.equal(pathClass('transfer-tests/errormonitor-tests.mjs'), 'non-production');
  assert.equal(pathClass('app/e2e-tests/login.ts'), 'non-production');
  assert.equal(pathClass('scripts/seed.mjs'), 'dev-tooling');
  assert.equal(pathClass('next.config.ts'), 'dev-tooling');
  // A file that merely contains one of the words is production code.
  assert.equal(pathClass('src/lib/spec-parser.ts'), 'production');
  assert.equal(pathClass('src/app/api/document-samples/route.ts'), 'production');
  assert.equal(pathClass('src/features/demo-billing/index.ts'), 'production');
  assert.equal(pathClass('src/app/page.tsx'), 'production');
  // bin/ is a published CLI's entry point; migrations are production schema.
  assert.equal(pathClass('bin/cli.js'), 'production');
  assert.equal(pathClass('migrations/001_init.sql'), 'production');
});

test('mass assignment is the payload arriving whole, not any write of caller input', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const flagged = bad.findings.filter((f) => f.file === 'app/actions/mass-assign.ts');

  // `.update(body)` — the payload passed straight in.
  assert.ok(
    flagged.some((f) => f.id === 'CTS002' && f.line === 10),
    'a payload written whole is CTS002',
  );
  // `{ where: {...}, data: { ...input } }` — the same bug one level down, where
  // a top-level scan of the call arguments never looked.
  assert.ok(
    flagged.some((f) => f.id === 'CTS043' && f.line === 18),
    'a nested spread of the payload is CTS043',
  );

  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(
    clean.findings.map((f) => `${f.id} ${f.file}:${f.line}`),
    [],
    'reading named fields into an explicit column list is the safe pattern, spread or not',
  );
});

test('rules naming a platform the project does not use are not run', async () => {
  // The fixture has no Supabase or Firebase dependency. "Supabase Auth Missing
  // Middleware" was being reported against a real app with neither.
  const result = await scan({ root: INDIRECT, offline: true });
  const note = result.checks.find((c) => c.label.startsWith('Community ruleset'))?.note ?? '';
  assert.match(note, /Supabase rules \(no Supabase dependency\)/);
  assert.match(note, /Firebase rules \(no Firebase dependency\)/);
  assert.equal(
    result.findings.some((f) => /supabase|firebase/i.test(f.title)),
    false,
  );

  // The clean fixture does depend on Supabase, so those rules stay switched on.
  const withSupabase = await scan({ root: CLEAN, offline: true });
  const cleanNote =
    withSupabase.checks.find((c) => c.label.startsWith('Community ruleset'))?.note ?? '';
  assert.equal(/Supabase rules/.test(cleanNote), false, 'not skipped where it applies');
});

test('the LLM rules fire on the shape they name, and not on the safe one', async () => {
  const bad = await scan({ root: VULNERABLE, offline: true });
  const byId = (id) => bad.findings.find((f) => f.id === id);

  // Caller text interpolated into the system message.
  assert.equal(byId('CTS080').meta.llm, 'LLM01:2026 - Prompt Injection');
  assert.equal(byId('CTS080').file, 'app/ai/assistant.ts');
  // No max_tokens on a request-reachable model call.
  assert.equal(byId('CTS081').meta.llm, 'LLM06:2026 - Unbounded Consumption');
  // A system prompt in a 'use client' module.
  assert.equal(byId('CTS082').meta.llm, 'LLM08:2026 - Hidden Context Exposure');
  assert.equal(byId('CTS082').file, 'app/ai/panel.tsx');

  // The clean fixture calls the same API with the caller's text as a separate
  // user message and a ceiling on the answer. Nothing to report.
  const clean = await scan({ root: CLEAN, offline: true });
  assert.deepEqual(clean.findings.map((f) => `${f.id} ${f.file}`), []);
});

test('findings carry one OWASP taxonomy, plus an LLM category where it applies', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });

  // The vendored ruleset labels Injection as both A02:2025 and A03:2025, and
  // Security Misconfiguration as A05:2025 and A05:2021. Whatever went in, one
  // spelling comes out.
  const categories = new Set(result.findings.map((f) => f.owasp).filter(Boolean));
  for (const c of categories) {
    assert.match(
      c,
      /^(A\d{2}:2025 - |API\d:2023)/,
      `${c} is neither the 2025 web list nor an API Top 10 label`,
    );
  }
  assert.equal([...categories].filter((c) => /Injection/.test(c)).length, 1, 'one Injection');

  // A hardcoded provider key is an LLM finding as well as a web one; an npm
  // install hook that shells out is not, however much it looks like a "hook".
  const key = result.findings.find((f) => f.id === 'CTS030' && /OpenAI/.test(f.title));
  assert.equal(key.meta.llm, 'LLM02:2026 - Sensitive Information Disclosure');
  const hook = result.findings.find((f) => f.id === 'CTS028');
  assert.equal(hook.meta?.llm, undefined, 'a postinstall hook is supply chain, not excessive agency');
});

test('the scan stays inside the directory it was given', async () => {
  const result = await scan({ root: INDIRECT, offline: true });

  // `escape` points at the vulnerable fixture, which is full of findings.
  assert.equal(
    result.findings.some((f) => f.file?.startsWith('escape/')),
    false,
    'a symlink out of the tree is not followed — its contents are not this project',
  );
  // `self` points at the fixture root: walking it again would report every
  // file twice, at two different paths.
  assert.equal(
    result.findings.some((f) => f.file?.startsWith('self/')),
    false,
    'and a symlink loop is walked once',
  );
  assert.ok(result.escapingSymlinkCount >= 1, 'the report says how many were refused');
});

test('what git ignores is not part of the project', async () => {
  const result = await scan({ root: INDIRECT, offline: true });
  const files = result.findings.map((f) => f.file);

  assert.equal(
    files.some((f) => f.startsWith('vendored/')),
    false,
    'vendored/ is gitignored, so its hardcoded key and eval() are somebody else\'s problem',
  );
  assert.equal(
    files.includes('settings.local.json'),
    false,
    '*.local.json is gitignored too',
  );
  assert.ok(result.gitIgnoredCount >= 2, 'and the report says how many paths were skipped');

  // An ignored `.env` is the exception: the secret is on disk either way, and
  // CTS032 exists precisely to reason about whether the file is ignored.
  const env = result.findings.filter((f) => f.file === '.env');
  assert.equal(env.length, 1, `expected the .env secret, got ${env.map((f) => f.id).join(', ')}`);
  assert.equal(env[0].id, 'CTS030');
  assert.equal(
    result.findings.some((f) => f.id === 'CTS032'),
    false,
    '.env IS covered by .gitignore here, so CTS032 must stay quiet',
  );
});

test('--no-gitignore scans them anyway', async () => {
  const result = await scan({ root: INDIRECT, offline: true, noGitignore: true });
  const vendored = result.findings.filter((f) => f.file?.startsWith('vendored/'));
  assert.ok(vendored.length > 0, 'the opt-out has to actually opt out');
  assert.equal(result.gitIgnoredCount, 0);
});

test('gitignore patterns follow git, not glob intuition', () => {
  const rules = Gitignore.empty().extend('/repo', [
    'logs',            // bare name, any depth, file or directory
    '/build',          // anchored to the root only
    '*.log',           // suffix, any depth
    'tmp/',            // directories only
    'docs/**/draft',   // ** spans directories
    'keep/*.txt',      // anchored by the embedded slash
    '!keep/README.txt',// re-included
  ].join('\n'));

  assert.equal(rules.ignores('/repo/logs', true), true);
  assert.equal(rules.ignores('/repo/src/logs', true), true, 'a bare name matches at any depth');
  assert.equal(rules.ignores('/repo/build', true), true);
  assert.equal(rules.ignores('/repo/src/build', true), false, 'a leading slash anchors');
  assert.equal(rules.ignores('/repo/a/b/c.log', false), true);
  assert.equal(rules.ignores('/repo/tmp', false), false, 'trailing slash means directories only');
  assert.equal(rules.ignores('/repo/tmp', true), true);
  assert.equal(rules.ignores('/repo/docs/a/b/draft', true), true);
  assert.equal(rules.ignores('/repo/keep/notes.txt', false), true);
  assert.equal(rules.ignores('/repo/keep/README.txt', false), false, 'a later ! re-includes');
  assert.equal(rules.ignores('/elsewhere/logs', true), false, 'rules stop at their own tree');
});

test('an ignored directory can have a re-included subdirectory', () => {
  // The shape that exposed the bug, from a real repository: everything under
  // logos/ is ignored except one subdirectory, whose files are tracked.
  const rules = Gitignore.empty().extend('/repo', ['logos/*', '!logos/logos-in-app/'].join('\n'));

  assert.equal(rules.ignores('/repo/logos/scratch.svg', false), true);
  assert.equal(rules.ignores('/repo/logos/logos-in-app', true), false, 're-included');
  assert.equal(
    rules.ignores('/repo/logos/logos-in-app/anim-pulse-24.svg', false),
    false,
    'a pattern matches a path, not everything beneath it — the walk prunes directories instead',
  );
});

test('a pattern that will not compile does not end the scan', () => {
  // `[z-a]` is a reversed range. This used to throw out of walk(), before any
  // scanner error handling, and kill the run on one line of somebody's file.
  const rules = Gitignore.empty().extend(
    '/repo',
    ['**/[z-a]/**', '[unclosed', 'node_modules', 'x'.repeat(900)].join('\n'),
  );
  assert.equal(rules.ignores('/repo/node_modules', true), true, 'the valid rules still apply');
  assert.equal(rules.ignores('/repo/src/index.ts', false), false);
});

test('a nested .gitignore overrides the one above it', () => {
  const rules = Gitignore.empty()
    .extend('/repo', '*.json')
    .extend('/repo/config', '!*.json');
  assert.equal(rules.ignores('/repo/a.json', false), true);
  assert.equal(rules.ignores('/repo/config/a.json', false), false);
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
  // Every declared output must be produced by the scan step. The list is read
  // out of the outputs: block rather than hard-coded, so a newly declared
  // output cannot ship without something actually writing it.
  const outputsBlock = yml.slice(yml.indexOf('\noutputs:'), yml.indexOf('\nruns:'));
  const declared = [...outputsBlock.matchAll(/^  ([a-z][a-z-]*):$/gm)].map((m) => m[1]);
  assert.ok(declared.length >= 5, 'the action should declare its outputs');
  for (const out of declared) {
    assert.match(yml, new RegExp(`\\b${out}=`), `output ${out} must be written`);
  }

  // Shell-quoting guard. The inline script is fed to node over a quoted
  // heredoc, never `node -e '...'`, where a single apostrophe in a comment
  // truncates the script and every output silently comes back empty.
  assert.ok(!/node -e '/.test(yml), "inline node must not be passed via node -e '...'");
  assert.match(yml, /node <<'NODE'/, 'inline node should be fed over a quoted heredoc');
  // After YAML strips the block indentation the terminator must land in column
  // 0, or the heredoc never closes.
  const runIndent = /^(\s*)node <<'NODE'/m.exec(yml)[1];
  assert.match(
    yml,
    new RegExp(`^${runIndent}NODE$`, 'm'),
    'heredoc terminator must sit at the run body indentation',
  );

  // The gate must be counted off every finding's severity. Rebuilding it from
  // the critical/high outputs alone is the bug that made fail-on=medium and
  // fail-on=low silently behave like fail-on=high.
  assert.match(
    yml,
    /rank\[f\.severity\] >= rank\[gate\]/,
    'the severity gate must count findings at every severity',
  );
});

test('CVEs distinguish shipping deps from dev/build deps', { skip: !online && 'offline' }, async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'cts-devprod-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({
      name: 'x',
      dependencies: { next: '14.2.3' },     // ships — known CVE cluster
      devDependencies: { postcss: '8.4.30' }, // build-only — known CVE
    }),
  );
  const { scan: run } = await import('../dist/index.js');
  const r = await run({ root: dir });
  const cves = r.findings.filter((f) => f.id === 'CTS024');

  const prod = cves.find((f) => f.meta.package === 'next');
  const dev = cves.find((f) => f.meta.package === 'postcss');
  assert.ok(prod && dev, 'both packages should have advisories');

  assert.equal(prod.meta.production, true);
  assert.notEqual(prod.severity, 'low', 'a shipping CVE keeps its CVSS severity');

  assert.equal(dev.meta.production, false);
  assert.equal(dev.severity, 'low', 'a dev/build CVE is held below the gate');
  assert.match(dev.title, /Dev dependency/);

  // The known-vulnerabilities check fails on shipping deps, not dev ones.
  const check = r.checks.find((c) => c.label.startsWith('Known vulnerabilities'));
  assert.equal(check.passed, false);
  assert.match(check.note, /1 shipping/);
});

test('generated code (Prisma client, *.generated.*) is skipped', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const inGenerated = result.findings.filter((f) => (f.file || '').includes('generated/prisma'));
  assert.deepEqual(inGenerated, [], 'vendor/generated code must not produce findings');
});

test('webhook that verifies via a framework helper or sig header is not flagged', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const cts042 = result.findings.filter((f) => f.id === 'CTS042').map((f) => f.file);
  assert.ok(
    cts042.includes('app/api/webhooks/stripe/route.ts'),
    'the unverified webhook must still be flagged',
  );
  assert.ok(
    !cts042.some((f) => f.includes('stripe-verified')),
    'a webhook that reads the signature header + verifies must not be flagged',
  );
});

test('A09/A10/A08 logic rules fire precisely and skip the safe cases', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const ids = (id) => result.findings.filter((f) => f.id === id);

  // A09 — secrets/PII in logs, but NOT a non-sensitive object or a string message.
  const logs = ids('CTS070');
  assert.ok(logs.length >= 3, 'should catch logged password, token, and request body');
  assert.ok(logs.some((f) => f.title.includes('Request body')), 'whole-body log flagged');
  assert.ok(!logs.some((f) => f.line === 8), 'console.log("user", user) must not fire');

  // A10 — fails-open flagged, fail-closed not.
  const failOpen = ids('CTS071');
  assert.ok(failOpen.some((f) => f.severity === 'high'), 'catch { return true } in a verify fn is high');
  assert.ok(
    !failOpen.some((f) => f.meta?.function === 'safeVerify'),
    'catch { return false } must not be flagged',
  );

  // A08 — insecure deserialization in both JS and Python.
  const deser = ids('CTS072');
  assert.ok(deser.some((f) => f.file.endsWith('.ts')), 'node-serialize unserialize flagged');
  assert.ok(deser.some((f) => f.file.endsWith('.py')), 'pickle/yaml.load flagged');

  for (const f of [...logs, ...failOpen, ...deser]) {
    assert.match(f.owasp, /A0[89]|A10/, 'maps to A08/A09/A10');
  }
});

test('logic rules do not fire on the clean fixture', async () => {
  const result = await scan({ root: CLEAN, offline: true });
  assert.ok(!result.findings.some((f) => ['CTS070', 'CTS071', 'CTS072'].includes(f.id)));
});
