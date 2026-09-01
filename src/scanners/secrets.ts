import { basename } from 'node:path';
import { read, rel, lineAt, snippetAt, exists, isScript } from '../utils/files.js';
import { Suppressions } from '../utils/suppress.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner, Severity } from '../types.js';
import { join } from 'node:path';

interface Pattern {
  id: string;
  label: string;
  re: RegExp;
  severity: Severity;
  /** Extra confirmation step; return false to discard the match. */
  confirm?: (match: string) => boolean;
  note?: string;
}

/** Decodes a JWT payload without verifying it — we only want the claims. */
function jwtPayload(token: string): any | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

const PATTERNS: Pattern[] = [
  {
    id: 'supabase-service-role',
    label: 'Supabase service-role key',
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'critical',
    confirm: (m) => jwtPayload(m)?.role === 'service_role',
    note: 'This key bypasses every Row Level Security policy on the project.',
  },
  {
    id: 'supabase-anon',
    label: 'Supabase anon key',
    re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'info',
    confirm: (m) => jwtPayload(m)?.role === 'anon',
    note: 'The anon key is designed to be public; it is only as safe as your RLS policies.',
  },
  { id: 'supabase-secret', label: 'Supabase secret key', re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g, severity: 'critical' },
  { id: 'openai', label: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}/g, severity: 'critical' },
  { id: 'anthropic', label: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{24,}/g, severity: 'critical' },
  { id: 'stripe-live', label: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, severity: 'critical' },
  { id: 'stripe-test', label: 'Stripe test secret key', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}/g, severity: 'medium' },
  { id: 'aws', label: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical' },
  { id: 'github-pat', label: 'GitHub personal access token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, severity: 'critical' },
  { id: 'google', label: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'high' },
  { id: 'slack', label: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'critical' },
  { id: 'resend', label: 'Resend API key', re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, severity: 'high' },
  { id: 'sendgrid', label: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, severity: 'critical' },
  { id: 'private-key', label: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: 'critical' },
  { id: 'postgres-url', label: 'PostgreSQL connection string with password', re: /\bpostgres(?:ql)?:\/\/[^\s:'"$]+:[^\s@'"$]{6,}@[^\s/'"]+/g, severity: 'critical' },
];

/**
 * Values that are obviously stand-ins rather than live credentials. Docs,
 * READMEs and rule fixtures are full of these and reporting them is pure noise.
 */
const PLACEHOLDER =
  /(your[_-]?|example|placeholder|sample|template|<[a-z_ -]+>|\.\.\.|\u2026|changeme|change_me|dummy|redacted|notreal|fake|mock|s3cret|abc123|abcdef|deadbeef|1234567|xxx|yyy|zzz|\bfoo\b|\bbar\b)/i;

/** The same character five or more times running, e.g. `sk_live_aaaaaaaa`. */
const REPEATED_RUN = /(.)\1{4,}/;

/**
 * Paths where a credential-shaped string is a fixture, not a deployed secret.
 * Findings here are reported at `low` so they are visible but never blocking.
 */
const NON_PRODUCTION_PATH =
  /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|fixtures?|spec|specs|examples?|docs?|demo|samples?|e2e|cypress|playwright|stories)(\/|$)|\.(test|spec|stories|fixture)\.[a-z]+$|(^|\/)(README|CHANGELOG|CONTRIBUTING)/i;

/** Env var names that are meant to be public even though they read like secrets. */
const PUBLIC_BY_DESIGN =
  /(ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY|CLIENT_ID|MEASUREMENT_ID|PROJECT_ID|APP_ID|SENDER_ID|FIREBASE_API_KEY|MAPBOX_TOKEN|POSTHOG_KEY|SENTRY_DSN)$/;
const SECRETY_NAME = /(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|PASSWD|_TOKEN|API_KEY|ACCESS_KEY|CREDENTIAL)/;

const LOCKFILES = new Set([
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb',
  'poetry.lock', 'Pipfile.lock', 'composer.lock',
]);

/**
 * True when the match sits on a commented-out line. Splits on real newlines and
 * on the two-character `\n` escape as well, because docs-in-a-string-literal
 * (`"# .env — WRONG\n# NEXT_PUBLIC_SECRET=..."`) are a common way to show the
 * wrong way to do something, and flagging those is noise.
 */
function isCommentedOut(source: string, index: number): boolean {
  const before = source.slice(0, index);
  const start = Math.max(
    before.lastIndexOf('\n'),
    before.lastIndexOf('\\n') + 1,
    before.lastIndexOf('"'),
    before.lastIndexOf("'"),
    before.lastIndexOf('`'),
  );
  const segment = before.slice(start + 1).trimStart();
  return /^(#|\/\/|\*|--)/.test(segment);
}

export const secretsScanner: Scanner = {
  name: 'Secrets & client-bundle boundary',

  applies() {
    return true;
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let filesScanned = 0;
    const seen = new Set<string>();

    for (const file of ctx.files) {
      const name = basename(file);
      if (LOCKFILES.has(name)) continue;
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      const isExample = /\.(example|sample|template)$/.test(relPath) || /\.env\.example/.test(relPath);
      const fixtureFile = NON_PRODUCTION_PATH.test(relPath);
      filesScanned++;
      const suppress = new Suppressions(source);
      const clientComponent = /^\s*(['"])use client\1/m.test(source.slice(0, 400));

      for (const pattern of PATTERNS) {
        pattern.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.re.exec(source)) !== null) {
          const value = m[0];
          if (pattern.confirm && !pattern.confirm(value)) continue;
          if (PLACEHOLDER.test(value) || REPEATED_RUN.test(value)) continue;
          if (pattern.id === 'supabase-anon') continue; // informational only, not reported
          const line = lineAt(source, m.index);
          if (suppress.suppressed(line, 'CTS030')) continue;

          const key = `${relPath}:${line}:${pattern.id}`;
          if (seen.has(key)) continue;
          seen.add(key);

          const redacted = value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
          // Redact first, then truncate: a long key would otherwise be cut off
          // before the replacement could match, leaving the secret on screen.
          const rawLine = source.split('\n')[line - 1] ?? '';
          const safeLine = rawLine.split(value).join(redacted).trim();
          const snippet = safeLine.length > 160 ? safeLine.slice(0, 157) + '...' : safeLine;
          const severity: Severity =
            isExample || fixtureFile
              ? 'low'
              : clientComponent && pattern.severity === 'critical'
                ? 'critical'
                : pattern.severity;

          result.findings.push({
            id: 'CTS030',
            severity,
            title: `Hardcoded ${pattern.label}`,
            detail:
              `${pattern.label} \`${redacted}\` is written into ${relPath}. ` +
              (clientComponent
                ? 'This file is a client component, so the value is compiled into the JavaScript bundle every visitor downloads. '
                : 'Anything committed to git is recoverable from history even after you delete the line. ') +
              (pattern.note ?? '') +
              (isExample
                ? ' (This looks like an example file, so the severity is reduced — confirm the value is not real.)'
                : fixtureFile
                  ? ' (This path looks like tests or docs, so the severity is reduced — confirm the value is not real.)'
                  : ''),
            fix:
              'Move the value into an environment variable that is only read server-side, rotate the key ' +
              'at the provider (assume it is burned), and purge it from git history if it was ever committed.',
            file: relPath,
            line,
            snippet,
            cwe: 'CWE-798: Use of Hard-coded Credentials',
            owasp: 'A04:2025 - Cryptographic Failures',
            meta: { kind: pattern.id, clientComponent },
          });
        }
      }

      // Server-only secrets routed through a NEXT_PUBLIC_ variable end up in the bundle.
      // Only a genuine read (`process.env.X`) or assignment (`X=...`) counts;
      // a variable merely named inside a string or a test description does not.
      const envRe = /process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)|(NEXT_PUBLIC_[A-Z0-9_]+)\s*[=:]/g;
      let e: RegExpExecArray | null;
      while ((e = envRe.exec(source)) !== null) {
        const varName = e[1] ?? e[2]!;
        if (PUBLIC_BY_DESIGN.test(varName)) continue;
        if (!SECRETY_NAME.test(varName)) continue;
        const line = lineAt(source, e.index);
        if (isCommentedOut(source, e.index)) continue; // a documented counter-example
        if (suppress.suppressed(line, 'CTS031')) continue;
        const key = `${relPath}:${varName}`;
        if (seen.has(key)) continue;
        seen.add(key);
        result.findings.push({
          id: 'CTS031',
          severity: fixtureFile ? 'low' : 'critical',
          title: 'Server secret exposed through a NEXT_PUBLIC_ variable',
          detail:
            `\`${varName}\` is prefixed \`NEXT_PUBLIC_\`, so Next.js inlines its value into the browser ` +
            'bundle at build time. The name says it holds a secret. Every visitor can read it in devtools.',
          fix:
            `Rename it to \`${varName.replace('NEXT_PUBLIC_', '')}\`, read it only in server code (Server ` +
            'Actions, Route Handlers, server components), and rotate the current value.',
          file: relPath,
          line,
          snippet: snippetAt(source, line),
          cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          owasp: 'A04:2025 - Cryptographic Failures',
          meta: { variable: varName },
        });
      }

      // A client component reaching for a service-role client is always wrong.
      if (clientComponent && isScript(file)) {
        const hit = /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|STRIPE_SECRET_KEY/.exec(source);
        if (hit) {
          const line = lineAt(source, hit.index);
          if (!suppress.suppressed(line, 'CTS033')) {
            result.findings.push({
              id: 'CTS033',
              severity: 'critical',
              title: 'Client component references a server-only secret',
              detail:
                `${relPath} carries the \`'use client'\` directive and reads \`${hit[0]}\`. Even if the ` +
                'variable is undefined in the browser today, the reference means the code path was designed ' +
                'to run privileged work in an untrusted context.',
              fix:
                'Move the privileged work into a Server Action or Route Handler and call that from the ' +
                'client component instead.',
              file: relPath,
              line,
              snippet: snippetAt(source, line),
              cwe: 'CWE-668: Exposure of Resource to Wrong Sphere',
              owasp: 'A04:2025 - Cryptographic Failures',
            });
          }
        }
      }
    }

    // Are real .env files kept out of git?
    const gitignore = read(join(ctx.root, '.gitignore'));
    const envFiles = ctx.files
      .map((f) => rel(ctx.root, f))
      .filter((f) => /(^|\/)\.env(\.|$)/.test(f) && !/\.(example|sample|template)$/.test(f));
    if (envFiles.length > 0 && exists(join(ctx.root, '.git'))) {
      const covered =
        gitignore !== null &&
        gitignore.split('\n').some((l) => {
          const t = l.trim();
          return t === '.env' || t === '.env*' || t === '*.env' || t === '.env.*' || t === '.env*.local';
        });
      if (!covered) {
        result.findings.push({
          id: 'CTS032',
          severity: 'high',
          title: '.env file is not covered by .gitignore',
          detail:
            `${envFiles.join(', ')} ${envFiles.length === 1 ? 'exists' : 'exist'} in a git repository ` +
            `and \`.gitignore\` has no rule matching ${envFiles.length === 1 ? 'it' : 'them'}. ` +
            `One \`git add .\` publishes every key ${envFiles.length === 1 ? 'it holds' : 'they hold'}.`,
          fix: 'Add `.env*` to .gitignore (keeping `!.env.example`), then `git rm --cached` any env file already tracked.',
          file: '.gitignore',
          line: 1,
          cwe: 'CWE-538: Insertion of Sensitive Information into an Externally-Accessible File',
          owasp: 'A04:2025 - Cryptographic Failures',
          meta: { envFiles },
        });
      }
    }

    const leaked = result.findings.filter((f) => f.id !== 'CTS032' && f.severity !== 'low').length;
    result.checks.push({
      label: `Secret & client-bundle boundary (${filesScanned} file${filesScanned === 1 ? '' : 's'} inspected)`,
      passed: leaked === 0,
    });
    return result;
  },
};
