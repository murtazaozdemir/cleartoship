/* ------------------------------------------------------------------------- *
 * Corrections to a vendored rule's SEVERITY.
 *
 * The fourth of the calibration layers, and separate from the other three for
 * the same reason they are separate from each other -- a wrong severity is its
 * own kind of defect:
 *
 *   - `community-text.ts`     the rule's words are wrong
 *   - `community-patterns.ts` the rule's pattern is wrong
 *   - `community-guards.ts`   the match cannot be judged without its context
 *   - here                    the match is real and the severity misstates it
 *
 * The bar: the severity has to be wrong about the vulnerability the rule
 * actually finds, as a matter of fact. Two things qualify. One is a rule that
 * matches two shapes with genuinely different worst cases (`VG105`). The other
 * is a rule whose severity was set for a vulnerability class it turns out not to
 * detect, where the class correction forces the severity to follow (`VG414`,
 * re-labelled from SSTI to XSS: SSTI reaches code execution, XSS does not).
 *
 * What does NOT qualify is a severity that produces more findings than someone
 * wants to read. Lowering a tier to quieten it is how a scanner stops meaning
 * anything, and it is indistinguishable from this file six months later -- so
 * every entry says which class it is reasoning about and why.
 *
 * Every adjustment also appends a note to the finding, because a reader who sees
 * a severity that differs from the published rule is owed the reason in the
 * report rather than in this file.
 * ------------------------------------------------------------------------- */

import type { Severity } from '../internal.js';

/**
 * Rules whose upstream severity is right for one shape they match and wrong for
 * another. Returning null leaves the rule's own severity alone.
 */
export const SEVERITY_ADJUSTERS: Record<
  string,
  (match: string, source: string, index: number) => { severity: Severity; note: string } | null
> = {
  // The rule matches two different things. Explicitly accepting `alg: none` is
  // the critical it is named for. Merely calling `jwt.verify(token, secret)`
  // without pinning `algorithms` is not: jsonwebtoken has rejected `none` on a
  // keyed verify since v9, so what is left is defence against algorithm
  // confusion — worth doing, not worth blocking a deploy over.
  // Re-labelled from SSTI to XSS in community-text.ts; the severity has to move
  // with the class, because critical was carrying SSTI's remote-code-execution
  // worst case and this shape has no path to it.
  //
  // high, not lower: an unescaped value that an attacker can reach is real XSS,
  // and the measured 0-for-10 on live code says those ten values were
  // developer-controlled -- which this rule cannot see, and which is exactly the
  // one thing a reader has to check. Demoting on ten unexamined samples would be
  // loosening a threshold to make findings go away.
  VG414: () => ({
    severity: 'high',
    note:
      ' (Reported at high rather than critical: this is cross-site scripting, not the ' +
      'server-side template injection the upstream rule is named for — the template is ' +
      'yours and the value is never evaluated as template syntax, so there is no path to ' +
      'code execution on the server. Whether it is exploitable at all depends on something ' +
      'this check cannot see: whether that value can carry anything a user supplied.)',
  }),

  VG105: (match) =>
    /algorithms\s*:\s*\[\s*['"]none['"]/i.test(match)
      ? null
      : {
          severity: 'medium',
          note:
            ' (Reported at medium: no `algorithms` option is pinned, but nothing here accepts ' +
            '`alg: none` — a keyed `jwt.verify` rejects it. Pinning the algorithm is defence ' +
            'against algorithm confusion, which matters most when the key could be a public key.)',
        },
};
