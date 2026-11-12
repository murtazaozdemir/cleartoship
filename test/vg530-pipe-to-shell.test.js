import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Reported from the portfolio auditor, 2026-11-12: VG530 "pipe to shell execution",
// critical, on a script that does the opposite — it downloads to a FILE and then
// verifies a SHA-256 against a hardcoded digest. Two defects in upstream's pattern,
// and it takes both:
//
//   1. the span is `[^|]*`, a negated class, so it crosses newlines and attaches
//      the NEXT line's pipe to this line's `curl`;
//   2. the interpreter alternation has no trailing `\b`, so `| shasum` matches as
//      `| sh` — the matched text ends mid-word.
//
// Both are fixed in PATTERN_FIXES, so a single-line test cannot reproduce either:
// the shapes below are two-line on purpose.

async function scanShell(name, body) {
  const dir = mkdtempSync(join(tmpdir(), 'vg530-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  mkdirSync(dirname(join(dir, name)), { recursive: true });
  writeFileSync(join(dir, name), body);
  const result = await scan({ root: dir, offline: true, noCommunity: false });
  return result.findings.filter((f) => f.id === 'VG530');
}

const HEAD = '#!/usr/bin/env bash\nset -euo pipefail\n';

test('a curl -o on one line and a checksum pipe on the next is not a pipe to shell', async () => {
  const found = await scanShell(
    'install-python.sh',
    HEAD +
      [
        'PBS_FILE="cpython-3.14.7-x86_64-apple-darwin-install_only.tar.gz"',
        'PBS_SHA256="11ff6db91dadbf8544d437e617586ee5184382ce95e4a44b7a64864db48cfe87"',
        'curl -fL --retry 3 -o "build-python/${PBS_FILE}" "$PBS_URL"',
        'echo "${PBS_SHA256}  build-python/${PBS_FILE}" | shasum -a 256 -c -',
        'tar -xzf "build-python/${PBS_FILE}" -C build-python',
      ].join('\n') +
      '\n',
  );
  assert.deepEqual(found, []);
});

test('the same shape with sha256sum is not a pipe to shell either', async () => {
  const found = await scanShell(
    'install-python.sh',
    HEAD +
      [
        'curl -fsSL -o payload.tar.gz "$URL"',
        'echo "$SHA256  payload.tar.gz" | sha256sum -c',
      ].join('\n') +
      '\n',
  );
  assert.deepEqual(found, []);
});

test('a curl on one line and an unrelated pipe lines later is not a pipe to shell', async () => {
  // The span defect by itself: the word "curl" inside an echo, and a real
  // `| bash` thirty-odd lines below it, were reported together — on the echo.
  const filler = Array.from({ length: 30 }, (_, i) => `echo "   step ${i}"`).join('\n');
  const found = await scanShell(
    'build.sh',
    HEAD +
      [
        'echo "Building the bridge for the curl installer"',
        filler,
        'grep -c . manifest.txt | bash_version_check',
      ].join('\n') +
      '\n',
  );
  assert.deepEqual(found, []);
});

test('printing an install command is not running it', async () => {
  const found = await scanShell(
    'build.sh',
    HEAD +
      [
        'echo "   Users install with:"',
        'echo "   curl -fsSL https://example.com/install.sh | bash"',
        'printf "   curl -fsSL %s | bash\\n" "$URL"',
      ].join('\n') +
      '\n',
  );
  assert.deepEqual(found, []);
});

test('a real curl pipe to bash is still reported', async () => {
  const found = await scanShell(
    'install.sh',
    HEAD + 'curl -fsSL https://example.com/install.sh | bash\n',
  );
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'critical');
  assert.equal(found[0].line, 3);
});

test('a pipe to sh, with the interpreter the last word on the line, is still reported', async () => {
  // `\b` at the end of the input is still a boundary: the fix must not need a
  // character after `sh` to recognise it.
  const found = await scanShell('install.sh', HEAD + 'wget -qO- https://example.com/i.sh | sh');
  assert.equal(found.length, 1);
});

test('a pipe to a shell continued on the next line is still reported', async () => {
  // A pipe at end of line continues the command, so this really is one pipeline —
  // the span fix must bound the search at the newline BEFORE the pipe, not after.
  const found = await scanShell(
    'install.sh',
    HEAD + 'curl -fsSL https://example.com/install.sh |\n  bash -s -- --quiet\n',
  );
  assert.equal(found.length, 1);
});

test('a curl piped to a shell inside bash -c is still reported', async () => {
  // A string, but one being executed rather than printed: the guard is about
  // `echo`, not about strings.
  const found = await scanShell(
    'install.sh',
    HEAD + 'bash -c "curl -fsSL https://example.com/install.sh | bash"\n',
  );
  assert.equal(found.length, 1);
});

test('base64 -d piped to a shell is still reported', async () => {
  const found = await scanShell('install.sh', HEAD + 'echo "$PAYLOAD" | base64 -d | bash\n');
  assert.equal(found.length, 1);
});
