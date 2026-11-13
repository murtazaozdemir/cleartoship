import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { shellIsInvolved } from '../dist/scanners/shell-exec.js';

// VG011 ("Command injection risk") was measured 0-for-6 on real code in the
// 2026-11-08 critical-tier walk. The pattern's last alternative is
// `.*(?:req\.|request\.|params\.|body\.|input|argv)`, so ANY argument that
// mentions `argv` or merely contains the substring `input` turns a command
// runner into a critical finding.
//
// The thing the rule's own name depends on is whether a SHELL is in the way.
// Command injection needs something to read `;`, `|` and `$(` and act on them.
// The argv forms have nothing of the sort: subprocess.run(["make", "-C", d, t])
// execs make directly, so a `t` of `x; rm -rf /` is one literal argument. That
// is the form Python's documentation recommends, and the rule fired on it.
//
// What is left in an argv call is ARGUMENT injection -- a `t` of
// `--output=/etc/passwd` is still a flag make will honour. Real, different,
// different fix. Reporting it as command injection at critical is the specific
// thing that teaches people to skip the tier.

function at(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vg011-'));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

const ids = async (files) => {
  const res = await scan({ root: at(files), offline: true });
  return res.findings.filter((f) => f.id === 'VG011').map((f) => `${f.file.split('/').pop()}:${f.line}`);
};

test('an argv list reaches no shell, so it is not command injection', async () => {
  assert.deepEqual(
    await ids({
      'safe.py': `import subprocess, sys
def build(target):
    subprocess.run(["make", "-C", sys.argv[1], target], check=True)
`,
      'safe.js': `const { spawnSync } = require('child_process');
function run(req) { return spawnSync('git', ['log', req.params.ref]); }
`,
    }),
    [],
  );
});

test('a string handed to a shell still reports', async () => {
  const found = await ids({
    'unsafe.py': `import subprocess, os
def bad1(target):
    subprocess.run("make " + target, shell=True)
def bad2(user_input):
    os.system("rm -rf " + user_input)
`,
    'unsafe.js': `const cp = require('child_process');
function bad(req) { return cp.execSync(\`git log \${req.params.ref}\`); }
`,
  });
  // os.system and child_process.exec always have a shell; shell=True asks for one.
  assert.deepEqual(found.sort(), ['unsafe.js:1', 'unsafe.py:3', 'unsafe.py:5']);
});

test('shell: true puts the shell back into an otherwise-argv call', async () => {
  // The whole point of keying on the option rather than on the function name.
  assert.deepEqual(
    await ids({
      'x.js': `const { spawn } = require('child_process');
function bad(req) { return spawn(\`git log \${req.params.ref}\`, { shell: true }); }
`,
    }),
    ['x.js:1'],
  );
});

test('RegExp.prototype.exec is not command execution', async () => {
  // `.exec(` matches the vendored pattern just as well as child_process.exec,
  // and `re.exec(req.body.q)` satisfies its `req.` alternative too.
  assert.deepEqual(
    await ids({
      'regex.js': `const re = /x(\\d+)/;
function parse(req) { return re.exec(req.body.text); }
`,
    }),
    [],
  );
});

test('an unrecognised runner keeps its finding', () => {
  // Deliberate asymmetry: missing a real injection costs more than one more
  // read of a call that turns out to be fine.
  //
  // Asserted on the function rather than through a scan, because the vendored
  // pattern cannot actually produce this shape -- every callee it can match is
  // one `shellIsInvolved` recognises. `shell_exec` would be the natural fixture
  // and PHP is not in VG011's language list (`javascript, typescript, python,
  // go, shell`), so a .php file is never read and the test passed vacuously
  // while asserting nothing. This is the branch, exercised directly.
  const args = () => 'req.body.cmd';
  assert.equal(shellIsInvolved('weirdRunner(', 'weirdRunner(req.body.cmd)', args), true);
});
