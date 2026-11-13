/* ------------------------------------------------------------------------- *
 * Which vendored rules run at all.
 *
 * The fifth calibration layer, and the bluntest. The other four change what a
 * rule says, matches, survives or scores; these three decide whether it is
 * consulted:
 *
 *   - `SUPERSEDED`    a first-party scanner answers the same question better,
 *                     and running both would double-report and import the
 *                     weaker result
 *   - `WITHHELD`      the rule cannot be made useful as written -- it fires on
 *                     the normal shape of correct code, or on a subject it can
 *                     never actually reach
 *   - `MANIFEST_ONLY` the rule is fine, but not against a machine-generated
 *                     lockfile, whose entries nobody here wrote
 *
 * Nothing is deleted from `src/vendor/guardvibe/`, so re-vendoring stays a
 * straight overwrite. Each reason is prose on purpose: a rule turned off without
 * a stated reason is indistinguishable from one turned off because it was
 * inconvenient, and the scanner reports these counts and reasons in its output
 * rather than quietly running fewer rules than it claims.
 * ------------------------------------------------------------------------- */

/**
 * Upstream rules that restate a check ClearToShip already performs against the
 * AST or the parsed schema. The AST version reasons about a whole function body
 * instead of a fixed character window, so it is both more accurate and better
 * located — running both would double-report and import the weaker result.
 *
 * These are disabled here rather than deleted from the vendored files, so those
 * stay a faithful copy of upstream and re-vendoring is a straight overwrite.
 *
 * Those marked inline are superseded by the RLS and Server Actions scanners
 * (`rls.ts`, `server-actions.ts`). They stay suppressed on purpose: standing the
 * vendored versions up as fallback coverage reported `VG1010` — critical — on
 * `clean-app`'s `updateProfile`, a Server Action proven safe by the fixture's own
 * doc comment (an explicit field list, no caller-controlled columns). The vendored
 * version is "the weaker result" for a reason: it is a no-schema-library-detected
 * pattern match, not real argument-flow analysis, and running it would trade the
 * precise first-party result for a false "critical" on correct code — worse for a
 * tool whose whole trust model is "a true positive a developer will act on, not
 * coverage for its own sake."
 */
export const SUPERSEDED = new Map<string, string>([
  ['VG400', 'CTS033/CTS040'],
  ['VG401', 'CTS002'], // Server Actions suite
  ['VG402', 'CTS001'], // Server Actions suite
  ['VG411', 'CTS031'],
  ['VG420', 'CTS001'], // Server Actions suite
  ['VG427', 'CTS041'], // Server Actions suite
  ['VG439', 'CTS016'], // RLS suite
  ['VG604', 'CTS031'],
  ['VG627', 'CTS031'],
  ['VG631', 'CTS031'],
  ['VG655', 'CTS031'],
  ['VG656', 'CTS030'],
  ['VG657', 'CTS030'],
  ['VG665', 'CTS030'],
  ['VG671', 'CTS031'],
  ['VG708', 'CTS030'],
  ['VG754', 'CTS031'],
  ['VG953', 'CTS043'], // Server Actions suite
  ['VG998', 'CTS045'],
  ['VG437', 'CTS033'],
  ['VG860', 'CTS028'],
  ['VG874', 'CTS028'],
  ['VG876', 'CTS031'],
  ['VG952', 'CTS001'], // Server Actions suite
  ['VG960', 'CTS044'], // Server Actions suite
  ['VG1007', 'CTS003'], // Server Actions suite
  ['VG1010', 'CTS002'], // Server Actions suite
  // Same defect, same line, twice: CTS081 reads the call's own option keys for
  // `max_tokens` / `maxTokens` / `maxOutputTokens` off the AST, and only where
  // the call is reachable from a request — which is the calibration, not an
  // omission. A model call in a build script with no ceiling is not a bill
  // anyone else can run up.
  ['VG999', 'CTS081'], // LLM & agent suite
  // Every callee VG123 names (`query`, `execute`, `prepare`, `db.run`…) is in
  // VG010's own verb list, followed by the same backtick-plus-`${` shape, so the
  // two reported the same line twice across the sweep (24 of 24 VG123 findings).
  // Upstream agrees — its own test comments call VG010 "the concat rule (which
  // dedup-takes-over)". What VG123 added beyond the duplicates was only the
  // matches VG010's guard had dropped for not being SQL at all
  // (`querySelectorAll`-class verbs with no SQL keyword in the statement).
  ['VG123', 'VG010'],
  // VG408 matches `dangerouslySetInnerHTML={{ __html:` and VG012 matches
  // `innerHTML` followed by `=` or `:` — and `dangerouslySetInnerHTML` *ends*
  // in `InnerHTML`, case-insensitively, so every VG408 match is a VG012 match
  // at the same position. Proven, not assumed: 15 of 15 raw VG408 matches
  // across the seven dogfooding repos, and by construction too — VG408 needs a
  // `{` after the `=`, which is exactly what VG012's `(?!['"]<)` lookahead
  // lets through.
  //
  // Keeping both did not merely double-report. The 2026-10-13 audit spent a
  // pass teaching VG012 the difference between an HTML sink and a `<style>`
  // element's CSS text, an all-literal expression, and a value already through
  // an escaper. VG408 carries no guard, so it reported all of it again under a
  // different id: eight `<style dangerouslySetInnerHTML={{ __html: css }} />`
  // on app C — the very shape that audit cleared — plus three
  // `sanitizeJsonLd(...)` / `sanitizeThemeInit(...)` calls, and three lines
  // where it simply said what VG012 had already said. Fourteen findings, not
  // one of them a true positive VG012 does not already report. A guarded rule
  // beside an unguarded copy of itself means the guard does nothing.
  ['VG408', 'VG012'],
]);

/**
 * Rules withheld because they misfire in this tool's context, measured against
 * the fixtures plus the reference corpus. Each is recorded with its reason so
 * the judgement can be revisited when upstream changes.
 */
export const WITHHELD = new Map<string, string>([
  [
    'VG921',
    'duplicates VG1044 on the same CVE and contradicts it, at a higher severity, so the wrong ' +
      'one wins the reader\'s attention. Its pattern is ' +
      '`0\\.(?:[0-7]\\d|80)\\.\\d+`, which matches 0.0.x through 0.80.x — the whole version ' +
      'history before the vulnerability existed. CVE-2026-34451 / GHSA-5474-4w2j-mq4c affects ' +
      '**0.79.0 up to 0.81.0**, verified against NVD and the GitLab advisory rather than taken ' +
      'from this rule\'s own text: a prefix check in the local-filesystem Memory Tool omitted a ' +
      'trailing separator, so a sibling directory (`memory-evil` beside `memory`) passed ' +
      'validation. CVSS 5.4, medium, and only reachable by a project that actually uses that ' +
      'tool. So the overlap between what this matches and what is vulnerable is two minor ' +
      'versions out of eighty-one. It is also overstated: "break out of the SDK\'s sandboxed ' +
      'execution environment … and execute arbitrary commands" is not a sibling-directory path ' +
      'escape, and a rule that calls a medium path-traversal a critical RCE is the reason a ' +
      'critical tier stops being read. Measured on two real manifests declaring `^0.52.0` and ' +
      '`^0.39.0`: both matched, neither can resolve into 0.79.x, both false. VG1044 keeps the ' +
      'subject — it carries the right range, both GHSAs, both CVE ids and the 0.91.1 fix that ' +
      'also covers the world-readable-permissions issue',
  ],
  [
    'VG543',
    'matches `; DROP|DELETE|INSERT|…` anywhere in a .sql file, which is the normal shape of ' +
      'every migration — 43 hits across the corpus, all false',
  ],
  [
    'VG146',
    'an unquoted `.env` value, but declared `languages: ["shell"]`, and `languagesFor` returns ' +
      '`shell` only for `.sh`/`.bash` — so a `.env` never reaches this scanner and the rule ' +
      'cannot fire on its own subject. What it matches is `NAME=$(…)` and `NAME=${VAR:-x}` in ' +
      'shell scripts: command substitution and parameter expansion, where quoting them as the ' +
      'fix instructs breaks the script. Fires on nearly every one of a 272-script corpus that ' +
      'sets a variable. Withheld rather than superseded because the premise is real; reviving ' +
      'it means giving dotenv files their own language token, not feeding them to shell rules',
  ],
  [
    'VG540',
    'flags any destructive DDL in a .sql file; migrations legitimately drop and alter objects',
  ],
  [
    'VG542',
    'flags DELETE/UPDATE without WHERE in .sql files, where a full-table statement in a ' +
      'migration is deliberate',
  ],
  [
    'VG863',
    'a packaging lint (missing "files" field), not a security finding, and wrong for apps ' +
      'rather than published libraries',
  ],
  [
    'VG865',
    'declares itself a `.npmignore` lint but is registered for the `shell` language, so it ' +
      'matches almost every line of every shell script — 6 hits on two `scripts/*.sh` files, ' +
      'all false, and it is a packaging lint rather than a security finding either way',
  ],
  [
    'VG1004',
    'matches every `use server` module with an exported function; it asserts "no rate limiting" ' +
      'without ever checking for it',
  ],
]);

/**
 * Machine-generated dependency lockfiles. Their entries describe the *transitive*
 * graph, which nobody in this repo wrote or can edit directly.
 */
export const LOCKFILE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|composer\.lock|Pipfile\.lock|poetry\.lock)$/i;

/**
 * Rules whose signal only exists in a hand-authored manifest. The same JSON
 * shapes appear all over a lockfile describing packages a dependency chose, so
 * a hit there is both unactionable and, measured on the dogfooding corpus,
 * wrong: `fast-glob`, `fast-deep-equal`, `common-tags`, `core-js` and
 * `simple-statistics` all trip the deceptive-prefix list, and the "wildcard
 * version" rule fires on transitive `"node": ">=16"` engine constraints.
 * Declared package names are covered properly by CTS020-CTS027, which ask the
 * registry rather than matching a prefix.
 */
export const MANIFEST_ONLY = new Map<string, string>([
  ['VG872', 'internal-name heuristic; in a lockfile it names a transitive dependency'],
  ['VG873', 'deceptive-prefix heuristic; matches ordinary transitive package names'],
  ['VG020', 'wildcard version; a transitive range is the dependency author\'s choice'],
]);
