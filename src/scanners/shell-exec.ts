/* ------------------------------------------------------------------------- *
 * Does this call hand a string to a shell?
 *
 * The question `VG011` ("Command injection risk") depends on, and the reason it
 * was 0-for-6 on real code: command injection needs a shell -- something has to
 * read `;`, `|` and `$(` and act on them. The argv forms have none, so a
 * tainted argument is one literal argument and nothing more.
 *
 * Its own file for the same reason `public-by-design.ts` is: it is a piece of
 * domain knowledge about a platform -- which runners shell out, and which option
 * puts a shell back -- rather than a fact about this scanner, and it is the kind
 * of list that grows as runners are added.
 *
 * It imports nothing on purpose. The argument text it needs is read by the
 * caller and passed in as `argsAt`, because the obvious alternative -- importing
 * `callArgs` from `community-guards.ts`, which imports this -- is an import
 * cycle, and this ships as one bundled file where a cycle can leave a binding
 * `undefined` at module-init time rather than failing loudly.
 * ------------------------------------------------------------------------- */

/**
 * The command-running calls the vendored pattern can land on.
 *
 * Scanned for the *last* one in the match, because the pattern's
 * `(?:child_process|cp)[\s\S]*?(?:exec|spawn…)` bridge starts the match at the
 * import and ends it at the call, so the call is at the end.
 */
const EXEC_FAMILY =
  /\b(?:os\s*\.\s*(?:system|popen)|shell_exec|subprocess\s*\.\s*(?:call|run|Popen)|execFileSync|execFile|execSync|exec|spawnSync|spawn)\s*\(/g;

/** `shell=True` in Python, `shell: true` in Node. Either one puts a shell back. */
const SHELL_OPTION_TRUE = /\bshell\s*[=:]\s*(?:True|true)\b/;

/**
 * One-entry cache for the `child_process` test below.
 *
 * Without it that test rescans the whole file for every match, which on a 1 MB
 * file with many matches is quadratic -- the shape this scanner already has a
 * budget and a linear-time matcher to avoid, so it should not be reintroduced
 * in a guard.
 */
let lastSourceSeen: { source: string; result: boolean } | null = null;

function fileImportsChildProcess(source: string): boolean {
  if (lastSourceSeen?.source !== source) {
    lastSourceSeen = { source, result: /\bchild_process\b/.test(source) };
  }
  return lastSourceSeen.result;
}

/**
 * Whether the call really hands a string to a shell to interpret.
 *
 * This is the distinction the rule's name depends on:
 *
 *   - `subprocess.run(["make", "-C", d, target])` execs `make` directly, so a
 *     `target` of `x; rm -rf /` is one literal argument named `x; rm -rf /`.
 *     This is the form Python's own documentation recommends, and the rule fired
 *     on it -- six times out of six, every one a false positive.
 *   - `spawnSync('git', ['log', ref])` likewise, unless `shell: true`.
 *   - `os.system`, `os.popen`, `shell_exec` and `child_process.exec` always have
 *     a shell, and anything passing `shell=True` has asked for one.
 *
 * The residual risk in an argv call is *argument* injection: a `target` of
 * `--output=/etc/passwd` is still a flag the program will honour. That is a real
 * class and a different one, with a different fix (`--`, or validation), and
 * calling it command injection at `critical` is what teaches people to skip the
 * tier.
 *
 * Unrecognised shapes keep the finding. Missing a real injection costs more than
 * one more read of a call that turns out to be fine.
 *
 * @param match   The vendored pattern's matched text.
 * @param source  The whole file, for the `child_process` test.
 * @param argsAt  Reads the argument list of the call at an offset *within the
 *                match*, so this file needs no source-reading helper of its own.
 */
export function shellIsInvolved(
  match: string,
  source: string,
  argsAt: (offsetInMatch: number) => string,
): boolean {
  let call: { name: string; at: number } | null = null;
  EXEC_FAMILY.lastIndex = 0;
  for (let m = EXEC_FAMILY.exec(match); m; m = EXEC_FAMILY.exec(match)) {
    call = { name: m[0].replace(/[\s(]/g, ''), at: m.index };
  }
  if (!call) return true;

  // Asked for a shell explicitly.
  if (SHELL_OPTION_TRUE.test(argsAt(call.at))) return true;

  const tail = call.name.split('.').pop()!;
  // Always a shell, whatever the arguments are.
  if (call.name.startsWith('os.') || tail === 'shell_exec') return true;
  // `child_process.exec` runs its string through `/bin/sh`.
  // `RegExp.prototype.exec` does not, and `re.exec(req.body.q)` matches this
  // pattern just as well, so the import has to be there for the call to be one.
  if (tail === 'exec' || tail === 'execSync') return fileImportsChildProcess(source);
  // Everything left is an argv form without `shell: true`: no shell, no
  // command injection.
  return false;
}
