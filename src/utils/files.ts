import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', '.turbo', '.vercel', '.wrangler',
  'dist', 'build', 'out', 'coverage', '.venv', 'venv', '__pycache__',
  '.open-next', '.sst', '.vercel',
  '.cache', '.pnpm-store', 'vendor', 'target', '.svelte-kit', '.nuxt',
  '.cts-cache', '_reference', 'site',
]);

const SCAN_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.sql',
  '.json', '.txt', '.toml', '.env', '.yaml', '.yml',
  // Prose files matter: AI agents copy `npm install <hallucination>` out of
  // READMEs and agent instruction files long before it reaches a manifest.
  '.md', '.mdc', '.mdx',
  // Reachable by the vendored community ruleset, which covers more ecosystems
  // than the AST scanners do.
  '.py', '.go', '.sh', '.bash', '.tf', '.tfvars', '.rb', '.php',
]);

/** Extensionless files worth reading. */
const NAMED_FILES = new Set(['Dockerfile', 'Makefile', 'Procfile']);

/** Instruction files read by coding agents. No extension, but high signal. */
const AGENT_FILES = new Set([
  '.cursorrules', '.windsurfrules', '.clinerules', '.aiderrules', '.goosehints',
]);

/** Files bigger than this are almost certainly bundles or fixtures, not source. */
const MAX_FILE_BYTES = 2_000_000;

export function walk(root: string): string[] {
  const found: string[] = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue;
        stack.push(full);
        continue;
      }
      if (!st.isFile() || st.size > MAX_FILE_BYTES) continue;
      const dot = entry.lastIndexOf('.');
      const ext = dot === -1 ? '' : entry.slice(dot);
      // .env, .env.local, requirements.txt and friends have no useful extension.
      if (
        SCAN_EXTS.has(ext) ||
        AGENT_FILES.has(entry) ||
        NAMED_FILES.has(entry) ||
        entry.startsWith('Dockerfile') ||
        entry.startsWith('.env') ||
        entry === 'requirements.txt'
      ) {
        found.push(full);
      }
    }
  }
  return found.sort();
}

export function read(file: string): string | null {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

export function rel(root: string, file: string): string {
  const r = relative(root, file);
  return r === '' ? '.' : r.split(sep).join('/');
}

export function exists(p: string): boolean {
  return existsSync(p);
}

/** 1-indexed line number for a character offset. */
export function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

export function snippetAt(source: string, line: number): string {
  const text = source.split('\n')[line - 1] ?? '';
  const trimmed = text.trim();
  return trimmed.length > 160 ? trimmed.slice(0, 157) + '...' : trimmed;
}

const SCRIPT_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts']);

export function isScript(file: string): boolean {
  const dot = file.lastIndexOf('.');
  return dot !== -1 && SCRIPT_EXTS.has(file.slice(dot));
}

export function isSql(file: string): boolean {
  return file.endsWith('.sql');
}

/** Prose and agent-instruction files, where install commands get copy-pasted from. */
export function isProse(file: string): boolean {
  const base = file.slice(file.lastIndexOf('/') + 1);
  return /\.(md|mdc|mdx|txt)$/.test(base) || AGENT_FILES.has(base);
}

/** Language tokens the vendored community rules match on. */
export function languagesFor(file: string): string[] {
  const base = file.slice(file.lastIndexOf('/') + 1);
  const ext = base.includes('.') ? base.slice(base.lastIndexOf('.')) : '';
  if (base.startsWith('Dockerfile')) return ['dockerfile'];
  switch (ext) {
    case '.ts':
    case '.tsx':
    case '.mts':
    case '.cts':
      return ['typescript', 'javascript'];
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return ['javascript'];
    case '.json':
      return base === 'vercel.json' ? ['json', 'vercel-config'] : ['json'];
    case '.sql':
      return ['sql'];
    case '.yml':
    case '.yaml':
      return ['yaml'];
    case '.py':
      return ['python'];
    case '.go':
      return ['go'];
    case '.sh':
    case '.bash':
      return ['shell'];
    case '.tf':
    case '.tfvars':
      return ['terraform'];
    case '.rb':
      return ['ruby'];
    case '.php':
      return ['php'];
    default:
      return [];
  }
}
