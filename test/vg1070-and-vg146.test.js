import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';
import { PATTERN_FIXES, RULE_COUNTS } from '../dist/scanners/community.js';
import { TEXT_FIXES } from '../dist/scanners/community-text.js';

// Both reported 2026-11-12 by apps in this portfolio, and both are cases where
// a vendored rule asks for something that cannot work.
//
// VG1070 is the worse of the two, because it was a scanner certifying a no-op.
// Upstream's pattern treats `--expect-provenance` as satisfying the rule and its
// `fix` text recommends that flag FIRST. There is no such npm flag: `npm config
// get expect-provenance` returns undefined, it is absent from `npm help ci`, and
// npm accepts it silently and exits 0 (measured on npm 10.9.2). So an app that
// followed this tool's own advice added a string that hardens nothing, and the
// finding went quiet. The green check was the harm.
//
// VG146 is "Unquoted .env Value with Special Characters" declared for the
// `shell` language, and `languagesFor` only ever returns `shell` for `.sh` and
// `.bash` — so it cannot fire on a `.env` at all. What it matched was
// `NAME=$(…)` and `NAME=${VAR:-default}` in shell scripts, where quoting them
// as instructed breaks the script.

async function scanProject(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vg1070-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return scan({ root: dir, offline: true, noCommunity: false });
}

const WORKFLOW = `name: CI
on: [push]
jobs:
  fake:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci --expect-provenance
  bare:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
  real:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci --ignore-scripts
`;

test('a flag npm does not have no longer satisfies VG1070', async () => {
  const result = await scanProject({ '.github/workflows/ci.yml': WORKFLOW });
  const lines = result.findings.filter((f) => f.id === 'VG1070').map((f) => f.line).sort((a, b) => a - b);
  // Line 7 is `npm ci --expect-provenance`, line 11 is the bare `npm ci`,
  // line 15 is `npm ci --ignore-scripts`. The first two are findings; the
  // third is the actual remedy. Asserting the lines, not just the count,
  // because a count passes whichever two it picked.
  assert.deepEqual(lines, [7, 11]);
});

test('--ignore-scripts still silences VG1070', async () => {
  const result = await scanProject({
    '.github/workflows/ok.yml': `name: CI\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci --ignore-scripts\n`,
  });
  assert.deepEqual(result.findings.filter((f) => f.id === 'VG1070'), []);
});

test('VG1070 no longer tells the reader to use the flag that does nothing', async () => {
  const result = await scanProject({ '.github/workflows/ci.yml': WORKFLOW });
  const found = result.findings.find((f) => f.id === 'VG1070');
  assert.ok(found, 'VG1070 should still fire on a bare npm ci');
  // The corrected text must name the real remedy and the real provenance check.
  assert.match(found.fix, /--ignore-scripts/);
  assert.match(found.fix, /npm audit signatures/);
  // And it must say outright that the upstream recommendation is not a flag,
  // rather than quietly dropping it: an app may already have it in CI.
  assert.match(found.fix, /no `--expect-provenance` flag/);
  assert.match(found.title, /--ignore-scripts/);
  // Upstream's own wording recommended it first; that must be gone.
  assert.doesNotMatch(found.fix, /Add `--expect-provenance` \(recommended/);
});

test('the corrected VG1070 pattern is the one actually run', () => {
  assert.ok('VG1070' in PATTERN_FIXES, 'VG1070 must carry a corrected pattern');
  // Upstream accepted either flag; the correction accepts only the real one.
  assert.doesNotMatch(PATTERN_FIXES.VG1070.source, /expect-provenance/);
  assert.match(PATTERN_FIXES.VG1070.source, /ignore-scripts/);
  // Which rules carry a re-wording, not how many: a bare count passes just as
  // happily when one entry is swapped for another, and the point of the count
  // is that every re-wording is a deliberate, reviewed claim.
  //   VG1070 -- upstream accepted a flag npm does not have
  //   VG414  -- upstream named a vulnerability the pattern does not find
  assert.deepEqual(Object.keys(TEXT_FIXES).sort(), ['VG1070', 'VG414']);
  assert.equal(RULE_COUNTS.reworded, Object.keys(TEXT_FIXES).length);
});

test('VG146 does not fire on a shell script that sets a variable', async () => {
  const result = await scanProject({
    'scripts/build.sh': '#!/bin/sh\nset -e\nREPO=$(cd "$(dirname "$0")/.." && pwd)\nBASE=${FOP_BASE:-HEAD}\n',
    // No shebang: a sourced fragment, which a shebang test would have missed.
    'scripts/lib.sh': 'PREFIX=$(dirname "$0")\nTARGET=${DEST:-/opt/app}\n',
  });
  assert.deepEqual(result.findings.filter((f) => f.id === 'VG146'), []);
});

test('the scanner says how many rules it withheld, and VG146 is one of them', async () => {
  const result = await scanProject({ 'scripts/build.sh': '#!/bin/sh\nA=$(echo hi)\n' });
  const note = result.checks.find((c) => c.label.startsWith('Community ruleset'))?.note ?? '';
  // Withholding must be stated, not silent: "no findings" cannot be
  // indistinguishable from "that rule was never run".
  assert.match(note, new RegExp(`${RULE_COUNTS.withheld} withheld as noisy`));
});
