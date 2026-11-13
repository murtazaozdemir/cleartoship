/**
 * Corrections to a vendored community rule's *words* — its name, what it says
 * is wrong, or what it tells you to do about it.
 *
 * Separate from the pattern corrections in `community.ts` because a pattern
 * defect and a prose defect are different bugs: one reports the wrong line, the
 * other sends the reader somewhere useless. The vendored files under
 * `src/vendor/guardvibe/` stay a faithful copy of upstream either way, so
 * re-vendoring remains a straight overwrite.
 *
 * The bar for an entry here is the same as for a pattern correction: the text
 * must be wrong as a matter of fact, not merely phrased in a way we would not
 * have chosen. Advice that cannot work is a defect; advice we would word
 * differently is not.
 */
export const TEXT_FIXES: Record<
  string,
  { name?: string; description?: string; fix?: string; fixCode?: string }
> = {
  // Upstream calls this "Server-Side Template Injection (SSTI)". It is not, and
  // the two are different vulnerabilities with different worst cases.
  //
  // SSTI is user input becoming part of the TEMPLATE SOURCE, so the engine
  // evaluates attacker-written template expressions -- `render_template_string(
  // "Hello " + name)` with a `name` of `{{7*7}}` returns `Hello 49`, and from
  // there Jinja2's object graph reaches `os.system`. That is remote code
  // execution, and critical is right for it.
  //
  // What this pattern finds is `<%- x %>`, `{{{ x }}}` and `{{ x | safe }}`: a
  // developer-written template rendering a VALUE without HTML-escaping it. Only
  // the value is attacker-controlled, the template is not, and the engine never
  // evaluates the value as template syntax. The worst case is XSS -- serious,
  // not RCE. The upstream description already describes this mechanism
  // correctly, which is what makes the name a defect rather than a disagreement;
  // it then overreaches by claiming the injected script "executes server-side",
  // which this shape cannot do.
  //
  // Severity moves critical -> high in SEVERITY_ADJUSTERS, for the same reason.
  VG414: {
    name: 'Unescaped value in a template (XSS)',
    description:
      'A template renders a value with HTML escaping turned off — EJS `<%- %>`, Handlebars ' +
      '`{{{ }}}`, Pug `!=` or the Nunjucks/Jinja2 `| safe` filter. If the value can carry ' +
      'anything an attacker supplied, the markup and script in it reach the page as markup ' +
      'and script. This is cross-site scripting: the template itself is yours and the engine ' +
      'does not evaluate the value as template syntax, so it is not template injection and ' +
      'cannot run code on the server.',
    fix:
      'Escape it: `<%= %>`, `{{ }}`, Pug `=`. Turn escaping off only for markup you produced ' +
      'yourself.\n\n' +
      'Where the value really is HTML — rendered Markdown, a rich-text field — the escaping ' +
      'is not what should change. Sanitise it first, and put the sanitiser in the filter chain ' +
      'immediately before the unescaped one so the next reader can see the guarantee rather ' +
      'than having to trace where the value came from. Use an allow-list sanitiser: DOMPurify, ' +
      'or `rehype-sanitize` in a Markdown pipeline. The sanitiser is the control — turning ' +
      'escaping off states only that escaping was skipped.',
  },

  VG1070: {
    name: 'CI npm install/ci without --ignore-scripts',
    description:
      'A CI workflow runs `npm install` or `npm ci` without `--ignore-scripts`, so every ' +
      'dependency in the tree may run arbitrary code on the build runner the first time it ' +
      'lands there — with whatever secrets that job holds. Lifecycle scripts are how the ' +
      '2026 @tanstack mass-malware wave, the 2022 node-ipc protestware and the long tail of ' +
      'postinstall crypto-miners all executed.',
    fix:
      'Add `--ignore-scripts` to every `npm install` / `npm ci` in CI. If a build genuinely ' +
      'needs a lifecycle script, check first whether it still does: platform binaries now ' +
      'usually arrive as optional dependencies rather than postinstall downloads (esbuild ' +
      '0.28 and wrangler 4 both do), so `--ignore-scripts` is often free. Where one is ' +
      'really required, run that package\'s script explicitly rather than leaving the flag ' +
      'off for the whole tree.\n\n' +
      'Provenance is a separate check, not a flag on this command: `npm audit signatures` ' +
      'verifies registry signatures and SLSA attestations, and fails the job when one does ' +
      'not verify. Note it reaches the registry and Sigstore, so it needs network and an ' +
      'outage will fail it.\n\n' +
      'There is no `--expect-provenance` flag. npm accepts it silently and exits 0, so ' +
      'adding it buys a green check and no hardening at all. Upstream GuardVibe recommends ' +
      'it and accepts it as satisfying this rule; ClearToShip does neither.',
    fixCode:
      '# BAD - every dependency may run code on the runner\n' +
      '- run: npm ci\n\n' +
      '# BAD - the flag does not exist; npm ignores it and exits 0\n' +
      '- run: npm ci --expect-provenance\n\n' +
      '# GOOD\n' +
      '- run: npm ci --ignore-scripts\n\n' +
      '# GOOD - and verify what the registry signed, as its own step\n' +
      '- run: npm ci --ignore-scripts\n' +
      '- run: npm audit signatures',
  },
};

/** The rule as this scanner reports it, with any prose correction applied. */
export function effectiveText(rule: {
  id: string;
  name: string;
  description: string;
  fix: string;
  fixCode?: string;
}): { name: string; description: string; fix: string; fixCode?: string } {
  const patch = TEXT_FIXES[rule.id];
  return {
    name: patch?.name ?? rule.name,
    description: patch?.description ?? rule.description,
    fix: patch?.fix ?? rule.fix,
    fixCode: patch?.fixCode ?? rule.fixCode,
  };
}

