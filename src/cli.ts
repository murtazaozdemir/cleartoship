#!/usr/bin/env node
import { Command, Option } from 'commander';
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pc from 'picocolors';
import { scan } from './scan.js';
import { banner } from './banner.js';
import { renderTerminal, renderJson, renderSarif, renderFixPrompt, renderBadge } from './report.js';
import { SEVERITY_ORDER } from './types.js';
import type { Severity } from './types.js';

const here = dirname(fileURLToPath(import.meta.url));
let version = '0.0.0';
try {
  version = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')).version;
} catch {
  /* running from an unusual layout; version is cosmetic */
}

const program = new Command();

program
  .name('cleartoship')
  .description(
    'Pre-flight security check for AI-built & vibe-coded apps.\n' +
      'Finds missing Server Action auth, Supabase RLS holes, hallucinated npm\n' +
      'packages and leaked keys before you deploy.',
  )
  .version(version, '-v, --version')
  .argument('[paths...]', 'files or directories to scan (default: the whole project)')
  .option('-C, --cwd <dir>', 'project root', process.cwd())
  .addOption(
    new Option('--fail-on <severity>', 'exit non-zero at or above this severity')
      .choices(['critical', 'high', 'medium', 'low', 'none'])
      .default('critical'),
  )
  .addOption(
    new Option('--min-severity <severity>', 'hide findings below this severity')
      .choices(['critical', 'high', 'medium', 'low', 'info'])
      .default('low'),
  )
  .option('--json', 'emit machine-readable JSON instead of the report')
  .option('--sarif', 'emit SARIF 2.1.0 (upload to GitHub code scanning)')
  .option('--fix-prompt', 'emit a ready-to-paste prompt for Cursor / Claude Code')
  .option('--badge', 'print the markdown status badge for your README')
  .option('-o, --output <file>', 'write the chosen output to a file instead of stdout')
  .option('--offline', 'skip registry lookups (no network)')
  .option('--ignore <ids>', 'comma-separated rule ids to skip, e.g. CTS004,CTS022')
  .option('--only <ids>', 'comma-separated rule ids to report exclusively')
  .option('--no-banner', 'suppress the ASCII header')
  .option('--quiet', 'only print findings, no passed checks')
  .option('--verbose', 'extra diagnostic output')
  .action(async (paths: string[], opts) => {
    const machineReadable = Boolean(opts.json || opts.sarif || opts.fixPrompt || opts.badge);
    const interactive = !machineReadable && !opts.output;

    if (interactive && opts.banner !== false) {
      process.stderr.write(banner(version) + '\n');
    }

    const list = (value?: string) =>
      value ? value.split(',').map((s) => s.trim()).filter(Boolean) : undefined;

    const result = await scan({
      root: opts.cwd,
      paths,
      offline: opts.offline,
      ignore: list(opts.ignore),
      only: list(opts.only),
      minSeverity: opts.minSeverity as Severity,
      verbose: opts.verbose,
      onProgress: interactive
        ? (step, total, name) => {
            process.stderr.write(pc.dim(`  [${step}/${total}] ${name}…\n`));
          }
        : undefined,
    });

    if (interactive) {
      process.stderr.write(
        `\n  ${pc.dim('root')}      ${result.root}\n` +
          `  ${pc.dim('stack')}     ${result.framework}\n`,
      );
    }

    let output: string;
    if (opts.json) output = renderJson(result);
    else if (opts.sarif) output = renderSarif(result, version);
    else if (opts.fixPrompt) output = renderFixPrompt(result);
    else if (opts.badge) output = renderBadge(result);
    else output = renderTerminal(result, { showPassed: !opts.quiet });

    if (opts.output) {
      writeFileSync(opts.output, output.endsWith('\n') ? output : output + '\n');
      process.stderr.write(pc.dim(`\n  wrote ${opts.output}\n`));
    } else {
      process.stdout.write(output.endsWith('\n') ? output : output + '\n');
    }

    if (opts.failOn === 'none') return;
    const floor = SEVERITY_ORDER[opts.failOn as Severity];
    const blocking = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= floor).length;
    if (blocking > 0) process.exitCode = 1;
  });

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(pc.red(`cleartoship: ${err instanceof Error ? err.message : String(err)}\n`));
  process.exitCode = 2;
});
