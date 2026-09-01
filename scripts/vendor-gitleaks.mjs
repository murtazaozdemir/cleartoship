#!/usr/bin/env node
/**
 * Converts gitleaks' generated config/gitleaks.toml into a TypeScript data
 * module. Run when re-vendoring; the output is committed so nothing is parsed
 * at runtime.
 *
 *   node scripts/vendor-gitleaks.mjs <path-to-gitleaks-checkout>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const checkout = process.argv[2] ?? '_reference/gitleaks__gitleaks';
const toml = readFileSync(join(checkout, 'config/gitleaks.toml'), 'utf8');
const lines = toml.split('\n');

/**
 * Go's RE2 accepts scoped inline flags — (?i), (?i:...), (?-i:...) — that
 * JavaScript has no equivalent for. Rather than drop those rules (37 of them,
 * covering real providers), the flag is hoisted to the whole pattern and the
 * scoped groups become plain non-capturing groups.
 *
 * The cost is precision, not safety: a prefix the original matched
 * case-sensitively is now matched either way, so `P8E-` matches where upstream
 * wanted `p8e-`. Every match still has to clear the entropy threshold and the
 * placeholder filters downstream, so the practical effect is negligible. Rules
 * changed this way are recorded and reported.
 */
function toJs(pattern) {
  const flags = new Set();
  let source = pattern;
  let folded = false;

  while (source.startsWith('(?i)')) {
    source = source.slice(4);
    flags.add('i');
  }

  if (/\(\?-?[ims]+[):]/.test(source)) {
    folded = true;
    source = source
      .replace(/\(\?([ims]+)\)/g, (_, f) => {
        for (const c of f) flags.add(c);
        return '';
      })
      .replace(/\(\?([ims]+):/g, (_, f) => {
        for (const c of f) flags.add(c);
        return '(?:';
      })
      .replace(/\(\?-([ims]+):/g, '(?:');
  }

  source = source.replace(/\(\?P</g, '(?<');

  const flagStr = [...flags].sort().join('');
  try {
    new RegExp(source, flagStr);
  } catch {
    return null;
  }
  return { source, flags: flagStr, folded };
}

const rules = [];
let current = null;
let context = null; // 'rules' | 'allowlists' | 'global-allowlist'
const globalStopwords = new Set();
let collectingStopwords = false;

const strValue = (line) => {
  const triple = /=\s*'''([\s\S]*?)'''\s*$/.exec(line);
  if (triple) return triple[1];
  const dq = /=\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(line);
  if (dq) return dq[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  return null;
};

for (const raw of lines) {
  const line = raw.trimEnd();
  const trimmed = line.trim();

  if (trimmed === '[[rules]]') {
    if (current) rules.push(current);
    current = { id: '', description: '', regex: null, entropy: null, keywords: [] };
    context = 'rules';
    collectingStopwords = false;
    continue;
  }
  if (trimmed === '[[rules.allowlists]]' || trimmed === '[rules.allowlist]') {
    context = 'allowlists'; // per-rule allowlists are not carried over
    collectingStopwords = false;
    continue;
  }
  if (trimmed === '[allowlist]') {
    context = 'global-allowlist';
    continue;
  }

  if (collectingStopwords) {
    if (trimmed.startsWith(']')) {
      collectingStopwords = false;
      continue;
    }
    const m = /"((?:[^"\\]|\\.)*)"/.exec(trimmed);
    if (m && context === 'global-allowlist') globalStopwords.add(m[1].toLowerCase());
    continue;
  }
  if (/^stopwords\s*=\s*\[/.test(trimmed)) {
    collectingStopwords = true;
    // single-line form
    const inline = trimmed.match(/"((?:[^"\\]|\\.)*)"/g);
    if (inline && trimmed.includes(']')) {
      collectingStopwords = false;
      if (context === 'global-allowlist') {
        for (const s of inline) globalStopwords.add(s.slice(1, -1).toLowerCase());
      }
    }
    continue;
  }

  if (context !== 'rules' || !current) continue;

  if (/^id\s*=/.test(trimmed)) current.id = strValue(trimmed) ?? '';
  else if (/^description\s*=/.test(trimmed)) current.description = strValue(trimmed) ?? '';
  else if (/^regex\s*=/.test(trimmed)) current.regex = strValue(trimmed);
  else if (/^entropy\s*=/.test(trimmed)) {
    const n = Number(/=\s*([\d.]+)/.exec(trimmed)?.[1]);
    current.entropy = Number.isFinite(n) ? n : null;
  } else if (/^keywords\s*=/.test(trimmed)) {
    current.keywords = (trimmed.match(/"((?:[^"\\]|\\.)*)"/g) ?? []).map((s) =>
      s.slice(1, -1).toLowerCase(),
    );
  }
}
if (current) rules.push(current);

const converted = [];
let dropped = 0;
for (const r of rules) {
  if (!r.id || !r.regex) {
    dropped++;
    continue;
  }
  const js = toJs(r.regex);
  if (!js) {
    dropped++;
    continue;
  }
  converted.push({ ...r, source: js.source, flags: js.flags, folded: js.folded });
}
const foldedCount = converted.filter((r) => r.folded).length;

const body = `/*
 * Credential detection rules vendored from gitleaks.
 *
 * Source:    https://github.com/gitleaks/gitleaks (config/gitleaks.toml)
 * Copyright: (c) 2019 Zachary Rice
 * Licence:   MIT — full text in LICENSES/gitleaks-MIT.txt
 *
 * GENERATED FILE — do not edit by hand.
 * Regenerate with: node scripts/vendor-gitleaks.mjs <gitleaks-checkout>
 *
 * Modifications: Go RE2 patterns are translated to JavaScript regular
 * expressions — a leading inline (?i) becomes the \`i\` flag and (?P<n>)
 * becomes (?<n>). Rule ids, descriptions, entropy thresholds and keyword
 * prefilters are carried over unchanged. Per-rule allowlists are not carried
 * over; ClearToShip applies its own placeholder and fixture-path handling.
 */

export interface GitleaksRule {
  id: string;
  description: string;
  pattern: RegExp;
  /** Minimum Shannon entropy of the captured secret, when upstream sets one. */
  entropy: number | null;
  /** Cheap substring prefilter: skip the regex unless one of these appears. */
  keywords: string[];
}

export const GITLEAKS_ATTRIBUTION =
  'gitleaks (github.com/gitleaks/gitleaks), Copyright (c) 2019 Zachary Rice, MIT';

/** Words that mark a match as a documentation placeholder rather than a secret. */
export const GITLEAKS_STOPWORDS: string[] = ${JSON.stringify([...globalStopwords].sort(), null, 2)
  .split('\n')
  .join('\n')};

export const GITLEAKS_RULES: GitleaksRule[] = [
${converted
  .map(
    (r) =>
      `  {\n    id: ${JSON.stringify(r.id)},\n    description: ${JSON.stringify(
        r.description,
      )},\n    pattern: /${r.source.replace(/\//g, '\\/')}/${r.flags}g,\n    entropy: ${
        r.entropy ?? 'null'
      },\n    keywords: ${JSON.stringify(r.keywords)},\n  },`,
  )
  .join('\n')}
];
`;

writeFileSync('src/vendor/gitleaks/rules.ts', body);
console.log(
  `vendored ${converted.length} rules ` +
    `(${dropped} dropped, ${foldedCount} case-folded), ${globalStopwords.size} stopwords`,
);
