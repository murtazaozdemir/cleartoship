import { join } from 'node:path';

/**
 * A `.gitignore` matcher, implemented rather than shelled out to.
 *
 * Two reasons not to call `git check-ignore`: ClearToShip promises it starts no
 * processes while it reads your code (see SECURITY.md), and half the trees worth
 * scanning — an unpacked tarball, a CI checkout of a subdirectory — have no git
 * binary or no repository to ask.
 *
 * Supports what real ignore files use: comments, negation with `!`, directory-only
 * patterns, anchoring, `*`, `?`, `**` and character classes. Precedence follows
 * git: the deepest `.gitignore` wins, and within one file the last matching
 * pattern wins.
 *
 * Checked against `git check-ignore` over four real repositories — 1,858 paths,
 * no disagreement in the direction that matters (nothing is skipped that git
 * would keep). Two deliberate divergences remain, both of which scan *more*
 * than git would:
 *
 *  - The user's global ignore file is not read; see `repositoryExcludes`.
 *  - Git never ignores a file it already tracks, whatever the patterns say.
 *    Reading `.git/index` to know that is a binary-format parser for a case
 *    that, across those four repositories, affected exactly one path — a
 *    compiled Mach-O binary no scanner would open. Documented rather than built.
 */

interface Rule {
  re: RegExp;
  negated: boolean;
  dirOnly: boolean;
}

interface Layer {
  /** Absolute directory the patterns are relative to, without a trailing slash. */
  base: string;
  rules: Rule[];
}

function escapeLiteral(ch: string): string {
  return /[.*+?^${}()|[\]\\]/.test(ch) ? '\\' + ch : ch;
}

/** Translates one gitignore pattern body into a regex source. */
function translate(pattern: string): string {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;

    if (ch === '\\' && i + 1 < pattern.length) {
      out += escapeLiteral(pattern[++i]!);
      continue;
    }

    if (ch === '*') {
      // `****` means no more than `**` does, and collapsing it keeps the
      // translated regex free of the nested quantifiers that backtrack badly.
      while (pattern[i + 1] === '*' && pattern[i + 2] === '*') i++;
      const doubled = pattern[i + 1] === '*';
      if (doubled) {
        const atStart = i === 0 || pattern[i - 1] === '/';
        const slashAfter = pattern[i + 2] === '/';
        if (atStart && slashAfter) {
          // `**/` matches zero or more leading directories.
          out += '(?:[^/]+/)*';
          i += 2;
          continue;
        }
        // A trailing or embedded `**` crosses directory boundaries.
        out += '.*';
        i += 1;
        continue;
      }
      out += '[^/]*';
      continue;
    }

    if (ch === '?') {
      out += '[^/]';
      continue;
    }

    if (ch === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close === -1) {
        out += '\\[';
        continue;
      }
      let body = pattern.slice(i + 1, close);
      if (body.startsWith('!')) body = '^' + body.slice(1);
      out += '[' + body + ']';
      i = close;
      continue;
    }

    out += escapeLiteral(ch);
  }
  return out;
}

/**
 * A pattern longer than this is not a real ignore rule. The cap exists because
 * this text comes from the repository being scanned, which for a security tool
 * is untrusted input: it reaches a regex compiler, and a regex compiler is a
 * place where hostile input has leverage.
 */
const MAX_PATTERN = 500;

/** Likewise, a `.gitignore` with more rules than this is not one. */
const MAX_RULES = 2000;

function compile(line: string): Rule | null {
  // Trailing whitespace is not part of the pattern unless it was escaped.
  let pattern = line.replace(/(?<!\\)\s+$/, '');
  if (pattern === '' || pattern.startsWith('#')) return null;
  if (pattern.length > MAX_PATTERN) return null;

  let negated = false;
  if (pattern.startsWith('!')) {
    negated = true;
    pattern = pattern.slice(1);
  } else if (pattern.startsWith('\\!') || pattern.startsWith('\\#')) {
    pattern = pattern.slice(1);
  }

  let dirOnly = false;
  if (pattern.endsWith('/')) {
    dirOnly = true;
    pattern = pattern.slice(0, -1);
  }
  if (pattern === '') return null;

  // A slash anywhere but the end anchors the pattern to this file's directory;
  // otherwise it matches a basename at any depth.
  const anchored = pattern.includes('/');
  if (pattern.startsWith('/')) pattern = pattern.slice(1);

  const body = translate(pattern);
  // No subtree suffix: a pattern matches a path, not everything beneath it.
  // Git prunes ignored directories during traversal instead, which is what the
  // walk does — and only that order makes `logos/*` followed by
  // `!logos/logos-in-app/` mean what git means. Matching the subtree here made
  // the negation unreachable: every file under the re-included directory stayed
  // ignored, 28 of them tracked, in one real repository.
  const source = anchored ? `^${body}$` : `(?:^|/)${body}$`;
  try {
    return { re: new RegExp(source), negated, dirOnly };
  } catch {
    // `[z-a]` is a reversed range, and one line of it used to end the scan:
    // the throw escaped `walk()`, which runs before any scanner's error
    // handling. A pattern git itself would treat as literal is not worth
    // dying over — skip it and read the rest of the file.
    return null;
  }
}

export class Gitignore {
  private constructor(private readonly layers: readonly Layer[]) {}

  static empty(): Gitignore {
    return new Gitignore([]);
  }

  /** A copy of this matcher with one more `.gitignore`'s worth of rules. */
  extend(base: string, content: string): Gitignore {
    const rules: Rule[] = [];
    for (const line of content.split(/\r?\n/)) {
      if (rules.length >= MAX_RULES) break;
      const rule = compile(line);
      if (rule) rules.push(rule);
    }
    if (rules.length === 0) return this;
    return new Gitignore([...this.layers, { base: base.replace(/\/+$/, ''), rules }]);
  }

  get isEmpty(): boolean {
    return this.layers.length === 0;
  }

  /**
   * Whether git would ignore `absPath`. Deepest layer first, and inside a layer
   * the last matching pattern decides — both are git's own rules.
   */
  ignores(absPath: string, isDir: boolean): boolean {
    for (let i = this.layers.length - 1; i >= 0; i--) {
      const layer = this.layers[i]!;
      if (!absPath.startsWith(layer.base + '/')) continue;
      const relative = absPath.slice(layer.base.length + 1);
      for (let j = layer.rules.length - 1; j >= 0; j--) {
        const rule = layer.rules[j]!;
        if (rule.dirOnly && !isDir) continue;
        if (rule.re.test(relative)) return !rule.negated;
      }
    }
    return false;
  }
}

/**
 * The ignore rules that apply to one path, assembled by descending from the
 * scan root — root `.gitignore`, `.git/info/exclude`, and every nested
 * `.gitignore` on the way down, in git's own precedence order.
 *
 * Exists so a rule that needs to ask "would git ignore this?" about a single
 * file can ask this matcher instead of pattern-matching the text of a
 * `.gitignore` itself. CTS032 did the latter — it compared the root file's
 * lines against five literal strings — and so reported `/.env` and `.env.local`
 * as *not* covering the very files they cover, a high-severity finding on a
 * correctly configured repository.
 */
export function rulesForPath(
  root: string,
  absPath: string,
  read: (path: string) => string | null,
): Gitignore {
  let rules = extendedAt(repositoryExcludes(root, read), root, read);
  if (!absPath.startsWith(root)) return rules;
  const segments = absPath
    .slice(root.length)
    .split(/[/\\]+/)
    .filter(Boolean)
    .slice(0, -1); // the file's own name is not a directory to descend into
  let dir = root.replace(/[/\\]+$/, '');
  for (const segment of segments) {
    dir = join(dir, segment);
    rules = extendedAt(rules, dir, read);
  }
  return rules;
}

/** The ignore rules that apply at `dir`, given those inherited from above. */
export function extendedAt(
  parent: Gitignore,
  dir: string,
  read: (path: string) => string | null,
): Gitignore {
  const content = read(join(dir, '.gitignore'));
  return content === null ? parent : parent.extend(dir, content);
}

/**
 * Repository-local excludes. Same syntax, same precedence as a root
 * `.gitignore`, but kept out of version control — so a machine-specific
 * scratch directory is invisible here without appearing in anyone's diff.
 *
 * The user's *global* ignore file (`core.excludesFile`, usually
 * `~/.config/git/ignore`) is deliberately not read: it lives outside the scan
 * root, which SECURITY.md promises we do not touch, and it is per-machine — a
 * CI checkout would not have it, so honouring it would make a local scan
 * quieter than the one that gates the merge.
 */
export function repositoryExcludes(
  root: string,
  read: (path: string) => string | null,
): Gitignore {
  const content = read(join(root, '.git', 'info', 'exclude'));
  return content === null ? Gitignore.empty() : Gitignore.empty().extend(root, content);
}
