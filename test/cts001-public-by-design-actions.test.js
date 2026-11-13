import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { isPublicByDesign } from '../dist/scanners/public-by-design.js';

// Reported 2026-11-08 by a caller who walked the whole `critical` tier across 42
// projects: 233 findings, 2 real. 27 were CTS001, and 14 of those were /login,
// /logout, /register, /forgot-password, /reset-password, /verify-email --
// endpoints that CANNOT require a session.
//
// The path exception for that already existed (since 2026-09-01) and works. What
// did not work was the same flow written as a **Server Action**, which is the
// idiomatic App Router way to back a login form: `intentionallyPublic` was gated
// on `isRoute`, so an action never qualified and drew a blocking `critical` for
// not checking a session it cannot have.
//
// The gate was right to exist, though, and is kept. A route's path IS its URL,
// so `app/login/route.ts` really is `/login`. An action's path is not its URL --
// actions are invoked by reference, so `app/login/actions.ts` may export
// anything, `deleteAllUsers()` included. So a route is judged on its path and an
// action on its own name, and the test below puts a public-by-design action and
// a destructive one in the SAME file to prove the directory is not what decides.

const PKG = JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { next: '15.5.28' } });

function app(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cts001-'));
  writeFileSync(join(dir, 'package.json'), PKG);
  for (const [name, body] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, body);
  }
  return dir;
}

const cts001 = async (files) => {
  const res = await scan({ root: app(files), offline: true });
  return res.findings.filter((f) => f.id === 'CTS001');
};

test('a login action is low, and a destructive action beside it stays critical', async () => {
  const found = await cts001({
    'app/login/actions.ts': `'use server';
import { db } from '@/lib/db';
export async function login(formData: FormData) {
  await db.from('sessions').insert({ email: formData.get('email') as string });
  return { ok: true };
}
export async function signUp(formData: FormData) {
  await db.from('users').insert({ email: formData.get('email') as string });
  return { ok: true };
}
export async function deleteAllUsers() {
  await db.from('users').delete();
  return { ok: true };
}
`,
  });
  // Keyed by the action's name from meta rather than by line, so the assertion
  // does not move every time the fixture's whitespace does.
  const byName = new Map(found.map((f) => [f.meta.action, f]));
  assert.deepEqual([...byName.keys()].sort(), ['deleteAllUsers', 'login', 'signUp']);
  assert.equal(byName.get('login').severity, 'low');
  assert.equal(byName.get('signUp').severity, 'low');
  assert.equal(byName.get('deleteAllUsers').severity, 'critical', 'same directory as login');
  assert.match(byName.get('deleteAllUsers').title, /Missing Server Action authorization/);
});

test('a destructive action is critical wherever it lives', async () => {
  const found = await cts001({
    'app/admin/actions.ts': `'use server';
import { db } from '@/lib/db';
export async function removeAccount(id: string) {
  await db.from('users').delete().eq('id', id);
  return { ok: true };
}
`,
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
});

test('the route path exception still works, and still only for routes', async () => {
  const found = await cts001({
    'app/forgot-password/route.ts': `import { db } from '@/lib/db';
export async function POST(req: Request) {
  const { email } = await req.json();
  await db.from('reset_tokens').insert({ email });
  return new Response('ok');
}
`,
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'low');
});

test('an action is judged by its name, not by the directory it sits in', () => {
  // The asymmetry is the whole point, so it is asserted directly rather than
  // only through a scan.
  assert.equal(isPublicByDesign({ isRoute: false, relPath: 'app/login/actions.ts', name: 'deleteAllUsers', readsRequestInput: true }), false);
  assert.equal(isPublicByDesign({ isRoute: false, relPath: 'app/admin/actions.ts', name: 'login', readsRequestInput: true }), true);
  // A route is judged by its path, not by the exported function's name.
  assert.equal(isPublicByDesign({ isRoute: true, relPath: 'app/admin/delete/route.ts', name: 'login', readsRequestInput: true }), false);
  assert.equal(isPublicByDesign({ isRoute: true, relPath: 'app/login/route.ts', name: 'POST', readsRequestInput: true }), true);
});

test('naming style does not matter: signIn, sign_in and SignIn are one entry', () => {
  for (const name of ['signIn', 'sign_in', 'SignIn', 'signin']) {
    assert.equal(
      isPublicByDesign({ isRoute: false, relPath: 'app/a/actions.ts', name, readsRequestInput: false }),
      true,
      name,
    );
  }
  assert.equal(isPublicByDesign({ isRoute: false, relPath: 'app/a/actions.ts', name: 'signInUserAsAdmin', readsRequestInput: false }), false);
});

test('a logout action that reads caller input is not public by design', () => {
  // `/logout` taking a userId is the one shape where a sign-out endpoint is a bug.
  assert.equal(isPublicByDesign({ isRoute: false, relPath: 'app/a/actions.ts', name: 'logout', readsRequestInput: false }), true);
  assert.equal(isPublicByDesign({ isRoute: false, relPath: 'app/a/actions.ts', name: 'logout', readsRequestInput: true }), false);
});
