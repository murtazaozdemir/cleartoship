import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scan } from '../dist/index.js';
import { GUARDVIBE_RULES } from '../dist/vendor/guardvibe/index.js';
import { TEXT_FIXES } from '../dist/scanners/community-text.js';

// VG414 is vendored as "Server-Side Template Injection (SSTI)" at critical. It
// does not find SSTI, and the two are different vulnerabilities:
//
//   SSTI is user input becoming part of the TEMPLATE SOURCE, so the engine
//   evaluates attacker-written template expressions. `render_template_string(
//   "Hello " + name)` with a name of `{{7*7}}` returns `Hello 49`, and from
//   there Jinja2's object graph reaches os.system. That is RCE.
//
//   This pattern finds `<%- x %>`, `{{{ x }}}` and `{{ x | safe }}`: a
//   developer-written template rendering a VALUE without HTML-escaping it. The
//   template is not attacker-controlled and the value is never evaluated as
//   template syntax. The worst case is XSS.
//
// Measured 0-for-10 on live code in the 2026-11-08 walk. The re-label is a
// factual correction and is what the auditor itself suggested over re-tuning;
// the severity follows the class, because critical was carrying SSTI's
// remote-code-execution worst case.

function page(body) {
  const dir = mkdtempSync(join(tmpdir(), 'vg414-'));
  writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
  writeFileSync(join(dir, 'page.html'), body);
  return dir;
}

const vg414 = async (body) => {
  const res = await scan({ root: page(body), offline: true });
  return res.findings.filter((f) => f.id === 'VG414');
};

test('it reports XSS, not template injection, and not at critical', async () => {
  const found = await vg414('<div>{{{ userBio }}}</div>\n');
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'high');
  assert.equal(found[0].title, 'Unescaped value in a template (XSS)');
  assert.doesNotMatch(found[0].title, /SSTI|Server-Side Template Injection/i);
});

test('the finding carries the reason the severity differs from the published rule', async () => {
  // A reader who sees high where the rule says critical is owed the reason in
  // the report, not in a source file they will never open.
  const [f] = await vg414('<p><%- comment %></p>\n');
  assert.match(f.detail, /Reported at high rather than critical/);
  assert.match(f.detail, /no path to code execution on the server/);
  // And the thing the check genuinely cannot see is stated rather than implied.
  assert.match(f.detail, /whether that value can carry anything a user supplied/);
});

test('the false claim that the script runs server-side is gone', async () => {
  // The upstream description got the mechanism right and then overreached:
  // "allowing attackers to inject arbitrary HTML and JavaScript that executes
  // server-side". This shape cannot do that, and it is the sentence that makes
  // the old name look justified.
  const [f] = await vg414('<span>{{ description | safe }}</span>\n');
  assert.doesNotMatch(f.detail, /executes server-side/i);
  assert.match(f.detail, /cross-site scripting/i);
  assert.match(f.detail, /cannot run code on the server/i);
});

test('all three unescaped syntaxes are still found — this is a re-label, not a narrowing', async () => {
  const found = await vg414('<div>{{{ a }}}</div>\n<p><%- b %></p>\n<span>{{ c | safe }}</span>\n');
  assert.deepEqual(found.map((f) => f.line).sort(), [1, 2, 3]);
  assert.deepEqual([...new Set(found.map((f) => f.severity))], ['high']);
});

test('the fix names a sanitiser, because `| safe` is not a control', async () => {
  // Where the value really is HTML, escaping is not what should change -- so
  // the advice has to say what the actual guarantee is, or it reads as "stop
  // rendering your rich text".
  const [f] = await vg414('<div>{{{ renderedMarkdown }}}</div>\n');
  assert.match(f.fix, /allow-list sanitiser/i);
  assert.match(f.fix, /DOMPurify|rehype-sanitize/);
  assert.match(f.fix, /sanitiser is the control/i);
});

test('the advice does not itself contain a live unescaped-template expression', () => {
  // The self-scan caught this on the first version of the text, which illustrated
  // the safe chain with a complete `{{ body | markdown | sanitize | safe }}`.
  // VG414 read its own remediation string and reported community-text.ts at high,
  // which dropped the repo's self-scan from CLEAR to CONDITIONAL.
  //
  // The rule was right and the text was wrong: advice about a pattern tends to
  // contain that pattern. The same thing happened once with a credential-shaped
  // literal in a source comment. Fixing the rule to accommodate this repo's own
  // documentation would be shaping the ruleset around this repo, which is the one
  // thing the ruleset must not be shaped around -- so the example is now carried
  // in prose and the libraries are named instead.
  const vendored = GUARDVIBE_RULES.find((r) => r.id === 'VG414');
  const live = new RegExp(vendored.pattern.source, 'gi');
  for (const [field, text] of Object.entries(TEXT_FIXES.VG414)) {
    live.lastIndex = 0;
    assert.equal(live.test(text), false, `TEXT_FIXES.VG414.${field} trips VG414's own pattern`);
  }
});

test('the vendored rule is untouched, so re-vendoring stays an overwrite', () => {
  // Every correction is applied at runtime; src/vendor/guardvibe/ stays a
  // faithful copy of upstream.
  const vendored = GUARDVIBE_RULES.find((r) => r.id === 'VG414');
  assert.equal(vendored.name, 'Server-Side Template Injection (SSTI)');
  assert.equal(vendored.severity, 'critical');
});
