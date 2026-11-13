import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { arityOf } from '../dist/scanners/sql-functions.js';

// Reported through the portfolio auditor, 2026-11-12, by the session that owns
// app B, as two symptoms of one defect: a Postgres function's current
// definition is the LAST one in timestamp order across the whole migrations
// directory, and rls.ts pushed its function findings as it met each statement.
// So a definition a later migration replaced or dropped still reported -- the
// finding's subject did not exist once the series finished replaying.
//
//   CTS052 on a zero-argument get_admin_user_ids() with an anon grant, which a
//          later migration DROPs and replaces with a uuid[] version.
//   CTS015 on the migration that pins search_path on that same zero-argument
//          function, one file before it is deleted. Dead text.
//
// Arity is load-bearing here, not decoration. The replacing migration does
// `DROP FUNCTION ... get_admin_user_ids()` (arity 0) in the same file where it
// creates `get_admin_user_ids(user_ids UUID[])` (arity 1) and grants anon
// EXECUTE on it. Keyed by bare name, that DROP would have deleted the LIVE
// function's finding too -- turning a false positive into a false negative on a
// genuine issue.
//
// What these tests do NOT assert is anything about a database. The surviving
// definition is what the repository says; that app's production database still
// answered the old wide RPC three days after the replacing migration was
// committed, because it had never been applied.

const PKG = JSON.stringify({
  name: 'x',
  version: '1.0.0',
  dependencies: { '@supabase/supabase-js': '2.0.0' },
});

function migrations(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts-series-'));
  mkdirSync(join(dir, 'supabase', 'migrations'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), PKG);
  for (const [name, body] of Object.entries(files)) {
    writeFileSync(join(dir, 'supabase', 'migrations', name), body);
  }
  return dir;
}

const run = async (files) => (await scan({ root: migrations(files), offline: true })).findings;

test('a dropped function stops being reported, for both CTS015 and CTS052', async () => {
  const f = await run({
    '20260101000000_add.sql': `CREATE FUNCTION public.wide()
RETURNS SETOF uuid LANGUAGE sql SECURITY DEFINER AS $$ SELECT id FROM public.admins $$;
GRANT EXECUTE ON FUNCTION public.wide() TO anon;
`,
    '20260202000000_remove.sql': `DROP FUNCTION IF EXISTS public.wide();
`,
  });
  assert.deepEqual(f.filter((x) => x.id === 'CTS015').map((x) => x.id), []);
  assert.deepEqual(f.filter((x) => x.id === 'CTS052').map((x) => x.id), []);
});

test('a dropped overload does not take a surviving one with it', async () => {
  // The shape from the real report: drop the zero-arg version, create and grant
  // a one-arg version, in the same migration.
  const f = await run({
    '20260101000000_add.sql': `CREATE FUNCTION public.ids()
RETURNS SETOF uuid LANGUAGE sql SECURITY DEFINER AS $$ SELECT id FROM public.admins $$;
GRANT EXECUTE ON FUNCTION public.ids() TO anon;
`,
    '20260202000000_scope.sql': `CREATE OR REPLACE FUNCTION public.ids(user_ids uuid[])
RETURNS SETOF uuid LANGUAGE sql SECURITY DEFINER
SET search_path = public AS $$ SELECT id FROM public.admins WHERE id = ANY(user_ids) $$;
GRANT EXECUTE ON FUNCTION public.ids(uuid[]) TO anon, authenticated;
DROP FUNCTION IF EXISTS public.ids();
`,
  });
  const cts052 = f.filter((x) => x.id === 'CTS052');
  assert.equal(cts052.length, 1, 'the surviving one-arg overload must still report');
  assert.match(cts052[0].file, /20260202000000_scope\.sql$/, 'on the migration that survives, not the dead one');
  // The survivor pins search_path, so CTS015 must not fire for it either.
  assert.deepEqual(f.filter((x) => x.id === 'CTS015').map((x) => x.file), []);
});

test('a later CREATE OR REPLACE that pins search_path clears CTS015', async () => {
  const f = await run({
    '20260101000000_add.sql': `CREATE FUNCTION public.helper()
RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;
`,
    '20260202000000_pin.sql': `CREATE OR REPLACE FUNCTION public.helper()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT true $$;
`,
  });
  assert.deepEqual(f.filter((x) => x.id === 'CTS015').map((x) => x.file), []);
});

test('an unpinned replacement of a pinned function starts reporting', async () => {
  // The direction that must not be lost: the series can make things worse.
  const f = await run({
    '20260101000000_pinned.sql': `CREATE FUNCTION public.helper()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT true $$;
`,
    '20260202000000_unpinned.sql': `CREATE OR REPLACE FUNCTION public.helper()
RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;
`,
  });
  const cts015 = f.filter((x) => x.id === 'CTS015');
  assert.equal(cts015.length, 1);
  assert.match(cts015[0].file, /20260202000000_unpinned\.sql$/);
});

test('REVOKE cancels the anon grant', async () => {
  const f = await run({
    '20260101000000_add.sql': `CREATE FUNCTION public.thing()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT true $$;
GRANT EXECUTE ON FUNCTION public.thing() TO anon;
`,
    '20260202000000_revoke.sql': `REVOKE EXECUTE ON FUNCTION public.thing() FROM anon;
`,
  });
  assert.deepEqual(f.filter((x) => x.id === 'CTS052').map((x) => x.id), []);
});

test('the finding says what it is evidence of: the series, not the database', async () => {
  const f = await run({
    '20260101000000_add.sql': `CREATE FUNCTION public.thing()
RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;
GRANT EXECUTE ON FUNCTION public.thing() TO anon;
`,
  });
  const cts015 = f.find((x) => x.id === 'CTS015');
  const cts052 = f.find((x) => x.id === 'CTS052');
  assert.match(cts015.detail, /after the migration series replays/);
  assert.match(cts052.detail, /survive the migration series/);
  // It must not claim to know the deployed state.
  for (const d of [cts015.detail, cts052.detail]) {
    assert.ok(!/in your database|currently deployed|is live/i.test(d));
  }
});

test('arityOf counts top-level arguments only', () => {
  assert.equal(arityOf('()'), 0);
  assert.equal(arityOf('(uuid)'), 1);
  assert.equal(arityOf('(uuid[], text)'), 2);
  // A comma inside a type modifier or a default is not an argument separator.
  assert.equal(arityOf('(a numeric(10,2))'), 1);
  assert.equal(arityOf("(a text DEFAULT 'x,y')"), 1);
  assert.equal(arityOf('(a numeric(10,2), b text[])'), 2);
});
