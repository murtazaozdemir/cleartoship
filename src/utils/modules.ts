import { dirname, join } from 'node:path';
import { isScript, rel } from './files.js';

/**
 * Resolves an import specifier to a first-party file that is already in the
 * scan set, so a scanner can follow a call into the helper it lands in.
 *
 * Deliberately not a real module resolver: it never reads `tsconfig.json`
 * `paths`, never touches disk beyond the file list it was given, and answers
 * `null` for anything from `node_modules`. Aliases (`@/lib/auth`, `~/server/db`)
 * are matched by path suffix instead, which finds the file whether the alias is
 * rooted at the project or at `src/` — the two shapes that cover essentially
 * every Next.js app — without pretending to know which.
 */
export interface ModuleIndex {
  /** Absolute path of the file `spec` names when imported from `fromFile`. */
  resolve(spec: string, fromFile: string): string | null;
}

/** Alias prefixes that stand for "somewhere in this project", not a package. */
const ALIAS = /^(@|~|#|\$)\//;

function stripExt(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(0, dot) : path;
}

export function buildModuleIndex(files: string[], root: string): ModuleIndex {
  /** Extensionless absolute path -> file. `dir/index.ts` also registers `dir`. */
  const byAbs = new Map<string, string>();
  /**
   * Every suffix of a file's extensionless project-relative path -> file, for
   * alias lookups. A suffix shared by two files is recorded as ambiguous
   * (`null`) so an alias never resolves to an arbitrary one of them.
   */
  const bySuffix = new Map<string, string | null>();

  const addSuffix = (key: string, file: string) => {
    const current = bySuffix.get(key);
    if (current === undefined) bySuffix.set(key, file);
    else if (current !== file) bySuffix.set(key, null);
  };

  for (const file of files) {
    if (!isScript(file)) continue;
    const noExt = stripExt(file);
    byAbs.set(noExt, file);
    if (/\/index$/.test(noExt)) byAbs.set(noExt.slice(0, -'/index'.length), file);

    const relNoExt = stripExt(rel(root, file));
    const segments = relNoExt.split('/');
    for (let i = 0; i < segments.length; i++) {
      addSuffix(segments.slice(i).join('/'), file);
      // `lib/auth/index.ts` is what `@/lib/auth` names.
      if (i < segments.length - 1 && segments[segments.length - 1] === 'index') {
        addSuffix(segments.slice(i, segments.length - 1).join('/'), file);
      }
    }
  }

  const fromAbsolute = (base: string): string | null =>
    // `./auth` and `./auth.js` (the ESM-correct spelling of `auth.ts`) both name
    // the same file, and `./auth` may also be `auth/index.ts`.
    byAbs.get(base) ?? byAbs.get(stripExt(base)) ?? null;

  return {
    resolve(spec: string, fromFile: string): string | null {
      if (!spec || spec.startsWith('node:') || spec.startsWith('data:')) return null;

      if (spec.startsWith('./') || spec.startsWith('../')) {
        return fromAbsolute(join(dirname(fromFile), spec));
      }

      const aliased = ALIAS.test(spec)
        ? spec.slice(spec.indexOf('/') + 1)
        : // A bare specifier is a package unless it looks like a project path
          // that was written without a leading alias (`src/lib/auth`).
          /^(src|app|lib|server|utils|components)\//.test(spec)
          ? spec
          : null;
      if (!aliased) return null;

      const hit = bySuffix.get(stripExt(aliased));
      return hit ?? null;
    },
  };
}
