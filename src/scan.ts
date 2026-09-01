import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { walk } from './utils/files.js';
import { detectFramework } from './utils/detect.js';
import { SCANNERS, communityScanner } from './scanners/index.js';
import { SEVERITY_ORDER } from './types.js';
import type { CheckSummary, Finding, ProjectContext, Severity } from './types.js';

export interface ScanOptions {
  root: string;
  paths?: string[];
  offline?: boolean;
  ignore?: string[];
  only?: string[];
  minSeverity?: Severity;
  /** Skip the vendored community ruleset, leaving only ClearToShip's own checks. */
  noCommunity?: boolean;
  verbose?: boolean;
  onProgress?: (step: number, total: number, name: string) => void;
}

export interface FullScan {
  root: string;
  framework: string;
  fileCount: number;
  findings: Finding[];
  checks: CheckSummary[];
  warnings: string[];
  counts: Record<Severity, number>;
  durationMs: number;
}

export async function scan(options: ScanOptions): Promise<FullScan> {
  const started = Date.now();
  const root = resolve(options.root);
  const roots = options.paths?.length ? options.paths.map((p) => resolve(root, p)) : [root];

  const files = [...new Set(roots.flatMap((r) => walk(r)))];
  const framework = detectFramework(root, files);

  const ctx: ProjectContext = {
    root,
    files,
    framework,
    offline: Boolean(options.offline),
    cacheDir: process.env.CLEARTOSHIP_CACHE ?? join(homedir(), '.cache', 'cleartoship'),
    verbose: Boolean(options.verbose),
  };

  const active = SCANNERS.filter(
    (s) => s.applies(ctx) && !(options.noCommunity && s === communityScanner),
  );
  const findings: Finding[] = [];
  const checks: CheckSummary[] = [];
  const warnings: string[] = [];

  for (let i = 0; i < active.length; i++) {
    const scanner = active[i]!;
    options.onProgress?.(i + 1, active.length, scanner.name);
    try {
      const result = await scanner.run(ctx);
      findings.push(...result.findings);
      checks.push(...result.checks);
      warnings.push(...result.warnings);
    } catch (err) {
      warnings.push(
        `${scanner.name} failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  let filtered = findings;
  if (options.ignore?.length) {
    const ignored = new Set(options.ignore.map((s) => s.toUpperCase()));
    filtered = filtered.filter((f) => !ignored.has(f.id.toUpperCase()));
  }
  if (options.only?.length) {
    const only = new Set(options.only.map((s) => s.toUpperCase()));
    filtered = filtered.filter((f) => only.has(f.id.toUpperCase()));
  }
  if (options.minSeverity) {
    const floor = SEVERITY_ORDER[options.minSeverity];
    filtered = filtered.filter((f) => SEVERITY_ORDER[f.severity] >= floor);
  }

  filtered.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    const byFile = (a.file ?? '').localeCompare(b.file ?? '');
    if (byFile !== 0) return byFile;
    return (a.line ?? 0) - (b.line ?? 0);
  });

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of filtered) counts[f.severity]++;

  return {
    root,
    framework: framework.describe(),
    fileCount: files.length,
    findings: filtered,
    checks,
    warnings,
    counts,
    durationMs: Date.now() - started,
  };
}
