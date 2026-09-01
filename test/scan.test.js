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
    'CTS030', // hardcoded secret
    'CTS031', // secret behind NEXT_PUBLIC_
    'CTS032', // .env not gitignored
    'CTS033', // client component reads a server secret
  ]) {
    assert.ok(found.has(expected), `expected ${expected} to be reported`);
  }
});

test('vulnerable fixture: locations point at the offending line', async () => {
  const result = await scan({ root: VULNERABLE, offline: true });
  const byId = (id) => result.findings.find((f) => f.id === id);

  assert.equal(byId('CTS010').line, 16, 'CTS010 should point at the CREATE TABLE, not the closing paren');
  assert.equal(byId('CTS017').line, 50);
  assert.equal(byId('CTS016').line, 47);
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
