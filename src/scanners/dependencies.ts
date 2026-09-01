import { basename } from 'node:path';
import { read, rel } from '../utils/files.js';
import { Registry, pool } from '../utils/registry.js';
import { POPULAR_NPM, POPULAR_PYPI, nearestPopular } from '../data/popular.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner } from '../types.js';

const NEW_PACKAGE_DAYS = 60;
const LOW_DOWNLOADS = 250;
const VERY_LOW_DOWNLOADS = 50;

interface Declared {
  name: string;
  range: string;
  ecosystem: 'npm' | 'pypi';
  file: string;
  line: number;
  dev: boolean;
}

function collectFromPackageJson(source: string, relPath: string): Declared[] {
  let pkg: any;
  try {
    pkg = JSON.parse(source);
  } catch {
    return [];
  }
  const lines = source.split('\n');
  const lineOf = (name: string): number => {
    const needle = `"${name}"`;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i]!.includes(needle)) return i + 1;
    }
    return 1;
  };
  const out: Declared[] = [];
  for (const [field, dev] of [
    ['dependencies', false],
    ['devDependencies', true],
    ['optionalDependencies', true],
    ['peerDependencies', true],
  ] as const) {
    const block = pkg?.[field];
    if (!block || typeof block !== 'object') continue;
    for (const [name, range] of Object.entries(block)) {
      if (typeof range !== 'string') continue;
      out.push({ name, range, ecosystem: 'npm', file: relPath, line: lineOf(name), dev });
    }
  }
  return out;
}

function collectFromRequirements(source: string, relPath: string): Declared[] {
  const out: Declared[] = [];
  source.split('\n').forEach((raw, i) => {
    const line = raw.split('#')[0]!.trim();
    if (!line || line.startsWith('-')) return;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(line);
    if (!m) return;
    out.push({
      name: m[1]!,
      range: (m[3] ?? '').trim(),
      ecosystem: 'pypi',
      file: relPath,
      line: i + 1,
      dev: false,
    });
  });
  return out;
}

function collectFromPyproject(source: string, relPath: string): Declared[] {
  const out: Declared[] = [];
  const lines = source.split('\n');
  let inDeps = false;
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (/^\[/.test(line)) {
      inDeps = /\[(tool\.poetry\.(dev-)?dependencies|project\.optional-dependencies)\]/.test(line);
      return;
    }
    if (/^dependencies\s*=\s*\[/.test(line)) inDeps = true;
    if (!inDeps) return;
    const quoted = /^["']([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line.replace(/^\s*["']?/, (m0) => m0));
    const poetry = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
    const strItem = /["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*[<>=!~ ]*[^"']*["']/.exec(line);
    const name = poetry?.[1] ?? strItem?.[1] ?? quoted?.[1];
    if (!name || name === 'python') return;
    out.push({ name, range: '', ecosystem: 'pypi', file: relPath, line: i + 1, dev: false });
  });
  return out;
}

export const dependencyScanner: Scanner = {
  name: 'Dependency hallucination & slopsquatting',

  applies(ctx) {
    return ctx.files.some((f) => {
      const b = basename(f);
      return b === 'package.json' || b === 'requirements.txt' || b === 'pyproject.toml';
    });
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    const declared: Declared[] = [];

    for (const file of ctx.files) {
      const b = basename(file);
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      if (b === 'package.json') declared.push(...collectFromPackageJson(source, relPath));
      else if (b === 'requirements.txt') declared.push(...collectFromRequirements(source, relPath));
      else if (b === 'pyproject.toml') declared.push(...collectFromPyproject(source, relPath));
    }

    // Local workspace references never hit a registry.
    const checkable = declared.filter(
      (d) => !/^(file:|link:|workspace:|portal:|git\+|https?:|github:|npm:)/.test(d.range),
    );
    const unique = new Map<string, Declared>();
    for (const d of checkable) {
      const key = `${d.ecosystem}:${d.name}`;
      if (!unique.has(key)) unique.set(key, d);
    }
    const list = [...unique.values()];

    if (list.length === 0) {
      result.checks.push({ label: 'Dependency verification', passed: true, note: 'no dependencies declared' });
      return result;
    }

    if (ctx.offline) {
      result.checks.push({
        label: `Dependency verification (${list.length} packages)`,
        passed: true,
        note: 'skipped — running with --offline',
      });
      return result;
    }

    const registry = new Registry(ctx.cacheDir, ctx.offline);
    const facts = await pool(list, 8, (d) => registry.lookup(d.name, d.ecosystem));

    if (registry.networkErrors > 0) {
      result.warnings.push(
        `${registry.networkErrors} registry lookup(s) failed; those packages were treated as valid.`,
      );
    }

    list.forEach((d, i) => {
      const f = facts[i]!;
      const popular = d.ecosystem === 'npm' ? POPULAR_NPM : POPULAR_PYPI;
      const registryName = d.ecosystem === 'npm' ? 'npm' : 'PyPI';

      if (!f.exists) {
        const near = nearestPopular(d.name, popular, 2);
        result.findings.push({
          id: 'CTS020',
          severity: 'critical',
          title: 'Dependency does not exist on the registry',
          detail:
            `\`${d.name}\` is declared in ${d.file} but no such package is published on ${registryName}. ` +
            'This is the classic signature of an AI-hallucinated import. The name is unclaimed, so an ' +
            'attacker can register it and have their code execute in every install and CI run from then on.' +
            (near ? ` Did you mean \`${near}\`?` : ''),
          fix: near
            ? `Replace \`${d.name}\` with \`${near}\`, or remove the dependency and the code importing it.`
            : `Remove \`${d.name}\` and the code that imports it, or publish the package yourself to claim the name.`,
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ecosystem: d.ecosystem, suggestion: near },
        });
        return;
      }

      if (f.error) return; // lookup failed; already reported as a warning

      const ageDays = f.created
        ? Math.floor((Date.now() - Date.parse(f.created)) / 86_400_000)
        : null;
      const downloads = f.weeklyDownloads;
      const near = nearestPopular(d.name, popular, 1);

      if (near) {
        // Squats of very popular names still rack up thousands of installs from
        // people making the same mistake, so download volume tunes the severity
        // rather than gating the finding.
        const busy = downloads !== undefined && downloads >= 10_000;
        result.findings.push({
          id: 'CTS023',
          severity: busy ? 'medium' : 'high',
          title: 'Dependency name is one edit away from a popular package',
          detail:
            `\`${d.name}\` differs from the widely-used \`${near}\` by a single character` +
            (downloads !== undefined ? ` and has ${downloads.toLocaleString()} weekly downloads` : '') +
            '. Typosquats and slopsquats are published precisely to catch this substitution — and a ' +
            'squat of a popular name still collects real install traffic, so a download count is not ' +
            'on its own reassuring.',
          fix:
            `Confirm you meant \`${d.name}\` and not \`${near}\`. Check the package's repository, ` +
            'maintainer and install scripts before trusting it.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, lookalike: near, weeklyDownloads: downloads },
        });
      }

      if (ageDays !== null && ageDays <= NEW_PACKAGE_DAYS && (downloads === undefined || downloads < LOW_DOWNLOADS)) {
        result.findings.push({
          id: 'CTS021',
          severity: 'high',
          title: 'Newly published, barely used dependency',
          detail:
            `\`${d.name}\` was first published ${ageDays} day${ageDays === 1 ? '' : 's'} ago` +
            (downloads !== undefined ? ` and has ${downloads} weekly downloads` : '') +
            '. A package that appears in an AI-written manifest and was registered days ago is the ' +
            'expected shape of a slopsquat: the model invents the name, an attacker registers it.',
          fix:
            `Open https://www.npmjs.com/package/${d.name} and check the repository, the maintainer and the ` +
            'install scripts before trusting it. Pin an exact version if you keep it.',
          file: d.file,
          line: d.line,
          cwe: 'CWE-1357: Reliance on Insufficiently Trustworthy Component',
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, ageDays, weeklyDownloads: downloads },
        });
      } else if (
        downloads !== undefined &&
        downloads < VERY_LOW_DOWNLOADS &&
        !d.dev &&
        !near
      ) {
        result.findings.push({
          id: 'CTS022',
          severity: 'low',
          title: 'Runtime dependency with almost no users',
          detail:
            `\`${d.name}\` has ${downloads} weekly downloads. That is not a vulnerability by itself, but ` +
            'an unmaintained single-author package in your runtime path is worth a deliberate decision ' +
            'rather than an accidental one.',
          fix: 'Confirm the package is maintained and actually needed, or vendor the few functions you use.',
          file: d.file,
          line: d.line,
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name, weeklyDownloads: downloads },
        });
      }

      if (f.deprecated) {
        result.findings.push({
          id: 'CTS025',
          severity: 'low',
          title: 'Dependency is deprecated upstream',
          detail: `The latest published version of \`${d.name}\` is marked deprecated by its maintainer.`,
          fix: 'Check the deprecation notice on the registry page and migrate to the successor package.',
          file: d.file,
          line: d.line,
          owasp: 'A03:2025 - Software Supply Chain Failures',
          meta: { package: d.name },
        });
      }
    });

    const missing = result.findings.filter((f) => f.id === 'CTS020').length;
    result.checks.push({
      label: `Dependency verification (${list.length} package${list.length === 1 ? '' : 's'} checked against npm/PyPI)`,
      passed: missing === 0,
      note: missing > 0 ? `${missing} do not exist` : undefined,
    });
    return result;
  },
};
