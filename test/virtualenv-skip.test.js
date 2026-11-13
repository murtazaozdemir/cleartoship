import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { scan } from '../dist/index.js';

// Found 2026-11-12 from a portfolio sweep that had slowed from ~2m20s to 829s
// for 42 apps, with one app accounting for 358s of it.
//
// `SKIP_DIRS` names `.venv` and `venv`, which is all a name test can safely do:
// `env/` is too ambiguous to skip blind and a virtualenv can be called
// anything. That app had a `.venv-convert/` beside its ordinary `.venv/`,
// holding 7,454 `.py` files -- and `.py` is in `SCAN_EXTS`, so every one was
// opened and run through the Python community rules. Measured on that app:
// 86s and 645 findings before, of which 636 were inside `.venv-convert`;
// 5s and 9 findings after. 98.6% of its findings were in code nobody there
// wrote.
//
// `pyvenv.cfg` is the right test because PEP 405 requires it: a directory is a
// virtualenv exactly when it has one. That keeps this a general rule rather
// than a project-specific name, which is the bar SKIP_DIRS has to meet --
// `site` and `_reference` were once on that list, and every user with a
// `site/` directory had the whole subtree reported clean without a file being
// opened.

const SECRET = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n';

async function scanWith(files) {
  const dir = mkdtempSync(join(tmpdir(), 'venv-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return scan({ root: dir, offline: true, noCommunity: false });
}

test('a virtualenv is skipped whatever it is called, when it carries pyvenv.cfg', async () => {
  const result = await scanWith({
    'app.py': 'import os\n',
    // Named nothing like `.venv`, which is the whole point.
    '.venv-convert/pyvenv.cfg': 'home = /usr/local/bin\nversion = 3.12.0\n',
    '.venv-convert/lib/python3.12/site-packages/pkg/creds.py': SECRET,
    'whisper-env/pyvenv.cfg': 'home = /usr/local/bin\n',
    'whisper-env/lib/site-packages/other/creds.py': SECRET,
  });
  const inEnvs = result.findings.filter(
    (f) => f.file.includes('.venv-convert') || f.file.includes('whisper-env'),
  );
  assert.deepEqual(inEnvs, [], 'nothing inside a virtualenv should be reported');
});

test('a directory that merely looks like an env is still scanned', async () => {
  // No `pyvenv.cfg`, so it is somebody's source directory and must be read.
  // Skipping on the name alone is what this fix deliberately does NOT do.
  const result = await scanWith({
    'env/settings.py': SECRET,
    'environment/config.py': SECRET,
  });
  const files = [...new Set(result.findings.map((f) => f.file))].sort();
  assert.ok(
    files.some((f) => f.startsWith('env/')),
    `env/settings.py must still be read; got ${JSON.stringify(files)}`,
  );
  assert.ok(
    files.some((f) => f.startsWith('environment/')),
    `environment/config.py must still be read; got ${JSON.stringify(files)}`,
  );
});

test('the skip is reported, not silent', async () => {
  // "No findings" must never be indistinguishable from "nothing was read".
  const result = await scanWith({
    'app.py': 'import os\n',
    '.venv-convert/pyvenv.cfg': 'home = /usr/local/bin\n',
    '.venv-convert/lib/creds.py': SECRET,
  });
  assert.ok(
    result.skippedDirs.includes('.venv-convert'),
    `the skipped directory should be named; got ${JSON.stringify(result.skippedDirs)}`,
  );
});
