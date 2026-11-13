import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { blankSqlComments } from '../dist/utils/sql.js';

// Reported through the portfolio auditor, 2026-11-12, by the session that owns
// app B: six CTS010 findings ("Public table with Row Level Security disabled")
// on a Cloudflare D1 schema. D1 is SQLite -- it has no row-level security and
// `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` is not a statement it has -- so
// no edit to that file could ever have cleared the finding.
//
// rls.ts already judges each .sql file's dialect and excludes the ones that are
// not Postgres. The gap was that it judged the dialect from the whole file
// including comments, so the schema was read as Postgres **because its comments
// explain that it is not**:
//
//   -- `has_role(auth.uid(),'admin')`. There is no auth.uid() here.
//   --   4. No gen_random_uuid(). The Worker supplies ids with crypto.randomUUID().
//
// The first makes PG_RLS_IDIOMS match (`auth.uid(`), which skips the exclusion
// branch outright; the second would have vetoed the SQLite reading anyway, via
// POSTGRES_ONLY. Both are prose about what the file deliberately does NOT do.
// Same class as the VG530 false positive: a pattern reading a comment as code.

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts-dialect-'));
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

const SUPABASE_PKG = JSON.stringify({
  name: 'x',
  version: '1.0.0',
  dependencies: { '@supabase/supabase-js': '2.0.0' },
});

// A real D1 schema: SQLite syntax in code, Postgres only ever in prose.
const D1_SCHEMA = `-- D1 (SQLite). Ported off Postgres; the Worker is the only line.
--
-- Notes for the reader:
--   1. The old policy was \`has_role(auth.uid(),'admin')\`. There is no
--      auth.uid() here -- D1 has no session.
--   2. No gen_random_uuid(). The Worker supplies ids with crypto.randomUUID().
--   3. No row level security, because SQLite has none.
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
) WITHOUT ROWID;
`;

test('a D1 schema is not reported for RLS because its comments mention auth.uid()', async () => {
  const root = project({
    'package.json': SUPABASE_PKG,
    'workers/api/d1/schema.sql': D1_SCHEMA,
  });
  const res = await scan({ root, offline: true });
  const onSchema = res.findings.filter((f) => (f.file || '').includes('d1/schema.sql'));
  assert.deepEqual(
    onSchema.map((f) => f.id),
    [],
    `expected no findings on the D1 schema, got ${onSchema.map((f) => f.id).join(', ')}`,
  );
});

test('a genuine Postgres table with RLS off is still reported, so nothing is lost', async () => {
  const root = project({
    'package.json': SUPABASE_PKG,
    'supabase/migrations/0001_init.sql': `CREATE TABLE public.notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  body text
);
`,
  });
  const res = await scan({ root, offline: true });
  const cts010 = res.findings.filter((f) => f.id === 'CTS010');
  assert.equal(cts010.length, 1);
  assert.equal(cts010[0].severity, 'critical');
  assert.match(cts010[0].fix, /ENABLE ROW LEVEL SECURITY/);
});

test('Postgres syntax in code still wins, even when the RLS idiom is only in prose', async () => {
  // The dialect test must key on what the file *does*. SQLite-only syntax is
  // present, but so is real Postgres syntax in code, so this stays Postgres.
  const root = project({
    'package.json': SUPABASE_PKG,
    'db/0001.sql': `-- migrated away from row level security
CREATE TABLE public.audit (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  note text
);
`,
  });
  const res = await scan({ root, offline: true });
  assert.ok(
    res.findings.some((f) => f.id === 'CTS010'),
    'a file with Postgres-only syntax in code must still be modelled as Postgres',
  );
});

test('blankSqlComments blanks comments, keeps offsets, and leaves strings alone', () => {
  const src = `SELECT 1; -- auth.uid()\n/* gen_random_uuid() */ SELECT 2;`;
  const out = blankSqlComments(src);
  assert.equal(out.length, src.length, 'offsets must be preserved');
  assert.ok(!out.includes('auth.uid'), 'line comment should be blanked');
  assert.ok(!out.includes('gen_random_uuid'), 'block comment should be blanked');
  assert.ok(out.includes('SELECT 1;'), 'code must survive');
  assert.ok(out.includes('SELECT 2;'), 'code after a block comment must survive');

  // A `--` inside a string literal is data, not a comment opener. If this were
  // mishandled the stripper would eat the rest of the file from here on.
  const withString = `INSERT INTO t VALUES ('-- not a comment'); SELECT autoincrement_marker;`;
  const kept = blankSqlComments(withString);
  assert.ok(kept.includes('SELECT autoincrement_marker;'), 'code after a string containing -- must survive');
});
