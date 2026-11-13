/**
 * Corrections to a vendored pattern that matches text the rule is not about —
 * a defect in the regex itself, reproducible from the rule's own input. Unlike
 * the bounded replacements below, these deliberately match at *different*
 * positions from upstream: that is the whole point of them, so they are held
 * to regression tests of the shape that found them rather than to an
 * equivalence check. The vendored files still stay a faithful copy of upstream,
 * so re-vendoring remains a straight overwrite.
 *
 * A correction belongs here, rather than in `MATCH_GUARDS`, when the defect is
 * in the *span* the pattern consumes. A guard can only reject a match the
 * pattern already found, and by then `lastIndex` has moved past everything that
 * match swallowed — so a guard would drop the false positive and take any real
 * finding inside that span with it.
 */
export const PATTERN_FIXES: Record<string, RegExp> = {
  // Upstream's lookahead accepts two flags as satisfying this rule,
  // `--expect-provenance` and `--ignore-scripts`, and the first does not
  // exist: `npm config get expect-provenance` is `undefined`, it is absent
  // from `npm help ci`, and npm takes the unknown flag silently and exits 0
  // (npm 10.9.2). So the rule could be silenced by a string that hardens
  // nothing, while its own `fix` text recommended that string first — a
  // scanner certifying a no-op, where the green check is the harm. Reported
  // independently by two apps here on the same day. Only `--ignore-scripts`
  // stops a lifecycle script, so only it silences this now; provenance is
  // `npm audit signatures`, a separate step, not a flag. Wording in
  // `community-text.ts`.
  VG1070:
    /(?:^|\n)\s*(?:-\s+)?(?:run|cmd|shell):\s*[|>-]?\s*["'`]?[^"'`\n]*\bnpm\s+(?:ci|install|i)\b(?![^\n"'`]*--ignore-scripts)[^\n"'`]*/gi,

  // Upstream: `(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh|…)|base64 …`.
  // Two defects, and it takes both to produce the match that found them —
  // `VG530` reported "pipe to shell execution", critical, on a checksum
  // verification:
  //
  //     curl -fL --retry 3 -o "build-python/${PBS_FILE}" "$PBS_URL"
  //     echo "${PBS_SHA256}  build-python/${PBS_FILE}" | shasum -a 256 -c -
  //
  // First, `[^|]*` is a negated class, so it crosses newlines: the span walks
  // from the `curl` on line one into line two and takes *that* line's pipe.
  // Second, the interpreter alternation carries no trailing `\b`, so
  // `| shasum` matches as `| sh` — the matched text ends mid-word.
  // `| sha256sum -c` goes the same way, so the rule fired on checksum
  // verification in any shell script: the opposite of the risk it describes,
  // and exactly what its own `fix` text recommends doing instead.
  //
  // The span fix is also what keeps the rule honest about *where* it fires. On
  // another script the unbounded span ran 32 lines, from the word "curl" inside
  // `echo "🔨 Building … for curl installer"` down to a `| bash` far below, and
  // reported the finding on the echo. A command and the pipe it feeds sit on one
  // line (`[^|\n]*`), and what follows the pipe is a whole word (`\b`).
  VG530:
    /(?:curl|wget)\s+[^|\n]*\|\s*(?:bash|sh|zsh|ksh|dash|source\s+\/dev\/stdin)\b|base64\s+(?:-d|--decode)\s+[^|\n]*\|\s*(?:bash|sh)\b/gi,
};

/**
 * Bounded replacements for vendored patterns whose backtracking is super-linear
 * in the size of the file. The vendored files stay a faithful copy of upstream;
 * the replacement is used in its place at runtime. Each one matches at exactly
 * the positions upstream's does for any input with the features the rule is
 * about within a few kilobytes of each other — the only difference is that the
 * search from any one position is bounded, so a file of the rule's own trigger
 * word repeated cannot stall the scan. `test/rules-audit.test.js` checks each
 * against its original, position by position, on generated inputs. These four
 * predate the linear-time matcher below, which now runs them as well.
 */
export const PATTERN_OVERRIDES: Record<string, RegExp> = {
  // Upstream: `TRIGGER[\s\S]{0,500}?(?:(?!X-Content-Type-Options|nosniff)[\s\S]){10,}?TERMINATOR`.
  // A lazy skip of up to 500 characters, then an *unbounded* tempered run —
  // every split of the gap between the two is tried, from every trigger. A file
  // of `res.sendFile(` repeated took 8.5 s at 8 KB and grew about 4.5x per
  // doubling. Reading the pattern for what it accepts: the skip can always be
  // stretched so the tempered run is its minimum of ten characters, so a
  // terminator 10-510 characters on matches unless `nosniff` starts in the ten
  // characters before it (`X-Content-Type-Options` is 22 long and cannot fit
  // there without overlapping the terminator), and a terminator further on
  // matches when nothing forbidden starts past the 500th character. The second
  // branch is where the bound is: 2,000 characters past that point.
  VG678:
    /(?:res\.sendFile|res\.download|createReadStream|getSignedUrl|getPublicUrl|\.pipe\s*\(\s*res)(?:[\s\S]{10,510}?(?<!nosniff[\s\S]{0,3})(?:res\.end|\.pipe|return|response)|[\s\S]{500}(?:(?!X-Content-Type-Options|nosniff)[\s\S]){11,2000}?(?:res\.end|\.pipe|return|response))/gi,

  // Upstream: `TRIGGER\s*\([\s\S]{0,500}?(?:(?!introspection\s*:\s*false)[\s\S]){0,300}\)`,
  // the same nested shape: 80 KB took 3 s. The tempered run may be empty, so
  // any `)` within 500 characters of the `(` matches outright, and one up to
  // 300 further matches when `introspection: false` does not start past the
  // 500th character. That is all this says, with each branch bounded.
  VG974:
    /(?:introspection\s*:\s*true|enableIntrospection|ApolloServer|createYoga|createHandler)\s*\((?:[\s\S]{0,500}?\)|[\s\S]{500}(?:(?!introspection\s*:\s*false)[\s\S]){0,300}?\))/g,

  // Upstream: `echo\s+['"]?[^'"|\n]+['"]?\s*\|…|(?:mysql|psql|mongosh?)\s+.*-p…`.
  // `[^'"|\n]+` and `.*` each run to the end of the line from every `echo` or
  // `mysql` on it and backtrack all the way home when there is no pipe or `-p`,
  // so one long line of them is quadratic. A command line is not 500
  // characters of echo payload or of flags before the password.
  VG533:
    /(?:echo\s+['"]?[^'"|\n]{1,500}['"]?\s*\|\s*sudo\s+-[Ss]|(?:mysql|psql|mongosh?)\s+.{0,500}-p\s*['"]?\w+['"]?)/gi,

  // Upstream: `TRIGGER\w*\s*(?:=\s*async|\([\s\S]*?\)\s*(?:=>|{))(?:(?!confirm|…)[\s\S]){10,}?(?:delete|…)\s*\(`.
  // Found on real code, not a fuzz input: `terminat` matches `terminator`, and
  // from each one the unbounded parameter list and tempered run search the
  // rest of the file — six seconds on @babel/parser's 480 KB build, against
  // single-digit milliseconds for every other rule. Bounded here to a
  // 1,000-character parameter list and a destructive call within 3,000
  // characters of it; a function body further from its own signature than
  // that is not what this rule is reading anyway.
  VG958:
    /(?:deleteAccount|deleteUser|cancelSubscription|transferFunds|refund|terminat)\w*\s*(?:=\s*async|\([\s\S]{0,1000}?\)\s*(?:=>|{))(?:(?!confirm|verify|reauthenticate|twoFactor|2fa|otp|challenge)[\s\S]){10,3000}?(?:delete|destroy|remove|cancel)\s*\(/gi,
};

/**
 * The pattern a rule is actually run with: a correction if it has one, else a
 * bounded replacement, else upstream's own. No rule is in both maps — a
 * corrected pattern that also needed bounding would have to be bounded in its
 * corrected form, not in two places — and `test/rules-audit.test.js` holds the
 * two sets disjoint.
 */
export function effectivePattern(rule: { id: string; pattern: RegExp }): RegExp {
  return PATTERN_FIXES[rule.id] ?? PATTERN_OVERRIDES[rule.id] ?? rule.pattern;
}
