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

function compile(line: string): Rule | null {
  // Trailing whitespace is not part of the pattern unless it was escaped.
  let pattern = line.replace(/(?<!\\)\s+$/, '');
  if (pattern === '' || pattern.startsWith('#')) return null;

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
  const source = anchored ? `^${body}(?:/.*)?$` : `(?:^|/)${body}(?:/.*)?$`;
  return { re: new RegExp(source), negated, dirOnly };
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
 */
export function repositoryExcludes(
  root: string,
  read: (path: string) => string | null,
): Gitignore {
  const content = read(join(root, '.git', 'info', 'exclude'));
  return content === null ? Gitignore.empty() : Gitignore.empty().extend(root, content);
}
