import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';

// Reported from the portfolio auditor, 2026-11-12, by the session that owns app B:
// CTS070 "Request body written to logs" fired on a service-role read helper that
// logs a FAILED upstream PostgREST response. Nothing a caller sent is in that
// object, so the finding's central sentence -- "whatever a caller put in the
// request body" -- was simply untrue of the code it fired on.
//
// It is re-worded rather than suppressed, because logging the payload is not
// risk-free: PostgREST returns `details` and `hint` alongside `code`/`message`,
// those can quote the offending row, and a TypeScript `as {code, message}` cast
// narrows the declared type without narrowing what actually arrives.
//
// The side is resolved from the binding chain, not from the identifier's name,
// because the name is the ambiguous part: `const body = await res.json()` and a
// destructured request body are both called `body`. The chain here is
// body <- await res.json().catch(...) <- res <- await fetch(...), which needs
// the TSAsExpression, the await and the `.catch()` all unwrapped -- so these
// fixtures keep that exact shape.

async function scanTs(name, body) {
  const dir = mkdtempSync(join(tmpdir(), 'cts070-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  writeFileSync(join(dir, name), body);
  const res = await scan({ root: dir, offline: true });
  return res.findings.filter((f) => f.id === 'CTS070');
}

const UPSTREAM = `export async function selectRows(url: string, key: string, table: string) {
  const res = await fetch(\`\${url}/rest/v1/\${table}\`, { headers: { k: key } });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { code?: string; message?: string };
    console.error(\`selectRows \${table} -> \${res.status}\`, body);
    return null;
  }
  return res.json();
}
`;

test('an upstream fetch response body is reported as one, at low', async () => {
  const f = await scanTs('upstream.ts', UPSTREAM);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'low');
  assert.equal(f[0].title, 'Upstream response body written to logs');
  assert.equal(f[0].meta.side, 'upstream');
  assert.equal(f[0].line, 5);
});

test('the upstream wording drops the caller claim and names the real risk', async () => {
  const [f] = await scanTs('upstream.ts', UPSTREAM);
  // The sentence that was false about this code must be gone...
  assert.ok(!/whatever a caller put in the request body/.test(f.detail));
  assert.ok(!/passwords, tokens, personal data/.test(f.detail));
  // ...and the reason it is still worth reporting must be stated.
  assert.match(f.detail, /details/);
  assert.match(f.detail, /hint/);
  assert.match(f.detail, /row/);
  // The remedy has to be the one that fits: pick keys, not "redact the field".
  assert.match(f.fix, /body\.code/);
  assert.ok(!/non-reversible reference/.test(f.fix));
});

test('a real request body is still medium, and still called one', async () => {
  const f = await scanTs('req.ts', `export async function h(req: any) {
  const body = await req.json();
  console.error('inbound', body);
}
`);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
  assert.equal(f[0].title, 'Request body written to logs');
  assert.equal(f[0].meta.side, 'request');
  assert.match(f[0].detail, /whatever a caller put in the request body/);
});

test('a request body reached through one more binding still resolves', async () => {
  const f = await scanTs('hop.ts', `export async function h(req: any) {
  const payload = req.body;
  console.log('dump', payload);
}
`);
  assert.equal(f.length, 1);
  assert.equal(f[0].meta.side, 'request');
  assert.equal(f[0].severity, 'medium');
});

test('a named secret on an upstream body still outranks the body rule', async () => {
  const f = await scanTs('secret.ts', `export async function h(url: string) {
  const res = await fetch(url);
  const body = await res.json();
  console.error('token was', body.access_token);
}
`);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
  assert.equal(f[0].title, 'Secret or PII written to logs');
});

test('an unresolvable chain keeps the request wording, so nothing is lost', async () => {
  // `getBody()` is opaque: the scanner cannot say which side it came from, and
  // the fail-safe direction is to keep reporting it as before.
  const f = await scanTs('opaque.ts', `declare function getBody(): any;
export function h() {
  const body = getBody();
  console.error('x', body);
}
`);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'medium');
  assert.equal(f[0].meta.side, 'unknown');
  assert.equal(f[0].title, 'Request body written to logs');
});
