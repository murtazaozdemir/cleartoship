import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { GUARDVIBE_RULES } from '../dist/vendor/guardvibe/index.js';
import { WITHHELD } from '../dist/scanners/community-roster.js';

// Two vendored rules described the same CVE and disagreed, and the one that had
// it wrong was the `critical`.
//
//   VG1044 (high):     0.79.0 through 0.91.0, Memory Tool, names both GHSAs and
//                      both CVE ids, fix 0.81.0 / 0.91.1.
//   VG921  (critical): "versions before 0.81.0 ... sandbox escape ... access the
//                      host system, read files, and execute arbitrary commands."
//
// CVE-2026-34451 / GHSA-5474-4w2j-mq4c affects 0.79.0 up to 0.81.0. Verified
// against NVD and the GitLab advisory rather than read off either rule: a prefix
// check in the local-filesystem Memory Tool omitted a trailing separator, so a
// sibling directory (`memory-evil` beside `memory`) passed validation. CVSS 5.4,
// medium, reachable only by a project that uses that tool.
//
// VG921's pattern matches 0.0.x through 0.80.x -- the entire version history
// before the vulnerability existed -- so its overlap with the truth is two minor
// versions out of eighty-one. Measured on two real manifests declaring ^0.52.0
// and ^0.39.0: both matched, neither can resolve into 0.79.x, both false.
//
// Withheld rather than re-pointed, because VG1044 already owns the subject and
// states it better. Running both would double-report the same CVE.

function manifest(dep) {
  const dir = mkdtempSync(join(tmpdir(), 'vg921-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 't', version: '1.0.0', dependencies: { '@anthropic-ai/sdk': dep } }),
  );
  return dir;
}

const idsFor = async (dep) => {
  const res = await scan({ root: manifest(dep), offline: true });
  return res.findings.filter((f) => f.id === 'VG921' || f.id === 'VG1044');
};

test('a version that predates the vulnerability reports nothing', async () => {
  // ^0.52.0 resolves within 0.52.x for a 0.x package, so it cannot reach 0.79.0.
  for (const dep of ['^0.52.0', '^0.39.0', '0.12.4', '~0.60.1']) {
    assert.deepEqual(await idsFor(dep), [], dep);
  }
});

test('a genuinely affected version still reports, from the rule that has it right', async () => {
  const found = await idsFor('0.79.5');
  assert.equal(found.length, 1, 'exactly one rule owns this CVE now');
  assert.equal(found[0].id, 'VG1044');
  assert.equal(found[0].severity, 'high');
  // The surviving rule names the advisory and the real fix version.
  assert.match(found[0].detail, /GHSA-5474-4w2j-mq4c/);
  assert.match(found[0].fix, /0\.91\.1/);
});

test('the withholding is stated with its reason, not applied silently', () => {
  const why = WITHHELD.get('VG921');
  assert.ok(why, 'VG921 must be withheld with a reason');
  // The reason has to carry the verified range, or the next reader cannot check it.
  assert.match(why, /0\.79\.0 up to 0\.81\.0/);
  assert.match(why, /VG1044/);
});

test('the vendored rule is untouched, so re-vendoring stays an overwrite', () => {
  const vendored = GUARDVIBE_RULES.find((r) => r.id === 'VG921');
  assert.equal(vendored.severity, 'critical');
  assert.match(vendored.description, /execute arbitrary commands/);
});

test("VG921's pattern really does match versions that predate the flaw", () => {
  // Non-vacuity: without the withholding this fires on ^0.52.0, so the test
  // above is testing the withholding rather than a pattern that never matched.
  const vendored = GUARDVIBE_RULES.find((r) => r.id === 'VG921');
  const live = new RegExp(vendored.pattern.source, 'g');
  assert.equal(live.test('"@anthropic-ai/sdk": "^0.52.0"'), true);
  live.lastIndex = 0;
  assert.equal(live.test('"@anthropic-ai/sdk": "^0.03.0"'), true);
});
