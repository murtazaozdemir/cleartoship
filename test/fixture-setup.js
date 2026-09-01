import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const VULNERABLE = join(here, 'fixtures', 'vulnerable-app');
const CLEAN = join(here, 'fixtures', 'clean-app');

/**
 * Fixture state that deliberately is NOT committed.
 *
 * The vulnerable fixture needs a `.env` holding credential-shaped strings and a
 * `.git` directory (CTS032 only fires inside a repository). Committing either
 * would be wrong: the root .gitignore excludes `.env` by design, and a file
 * full of `sk_live_…` strings in a public repo trips secret scanners and looks
 * exactly like the mistake this tool exists to catch. So it is generated here
 * instead, which also keeps the fixture identical on every machine.
 */
export function buildFixtures() {
  const payload = Buffer.from(
    JSON.stringify({
      iss: 'supabase',
      ref: 'abcdefghijklmnop',
      role: 'service_role',
      iat: 1700000000,
      exp: 2000000000,
    }),
  ).toString('base64url');

  writeFileSync(
    join(VULNERABLE, '.env'),
    [
      'NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnop.supabase.co',
      `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.dGhpc19pc19hX2Zha2Vfc2lnbmF0dXJlXzEyMw`,
      'STRIPE_SECRET_KEY=sk_live_51NqAbCdEfGhIjKlMnOpQrStU',
      'OPENAI_API_KEY=sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
      // Providers covered only by the vendored gitleaks ruleset, not by the
      // hand-written patterns — these exercise that path and its entropy gate.
      'NPM_TOKEN=npm_7Kq2Xw9ZbR4tYn6Vm1Pj8Ld3Hs5Gf0Ec7Ua2',
      'LINEAR_KEY=lin_api_9Wq4Zt7Yr2Nk6Bv1Xm8Pd3Lc5Hj0Gf7Se4Ua2Qi6R',
      '',
    ].join('\n'),
  );

  // A bare directory is enough: the scanner only checks that one exists.
  for (const root of [VULNERABLE, CLEAN]) {
    mkdirSync(join(root, '.git'), { recursive: true });
  }
}
