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

