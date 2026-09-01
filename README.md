# ClearToShip

> The 30-second pre-launch security clearance for AI-built & vibe-coded apps.

AI coding assistants write code fast, but they optimise for *"runs without errors"*, not
*"runs without leaks"*. The failure mode is almost never a dangerous line of code — it's an
**absent** one: the session check that was never written, the RLS policy that was never
enabled, the package name the model invented.

`cleartoship` is a static pre-flight check for exactly those gaps. No database connection, no
account, no upload — it reads your repo and exits non-zero if you shouldn't deploy.

```bash
npx cleartoship
```

## What it checks

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS001** | critical | Server Action / Route Handler mutates the database with no session check |
| **CTS002** | high | Action takes caller input and writes it with no runtime schema validation (mass assignment) |
| **CTS003** | critical | `SUPABASE_SERVICE_ROLE_KEY` client built inside a user-reachable action |
| **CTS004** | medium | Authenticated mutation keyed only on a caller-supplied id (IDOR) |
| **CTS010** | critical | Public table with Row Level Security never enabled |
| **CTS011** | low | RLS on with no policies — fail-closed, but the feature is probably broken |
| **CTS012** | critical | Policy grants writes with an always-true predicate |
| **CTS013** | high | Anonymous `SELECT` over a table holding emails, tokens or billing ids |
| **CTS014** | high | Table has a `user_id` column but no policy compares it to `auth.uid()` |
| **CTS015** | medium | `SECURITY DEFINER` function without a pinned `search_path` |
| **CTS016** | medium | API-exposed view running with definer rights |
| **CTS017** | critical | `GRANT INSERT/UPDATE/DELETE … TO anon` |
| **CTS018** | critical | Policy trusts `user_metadata`, which the user can edit themselves |
| **CTS020** | critical | Dependency that **does not exist** on npm/PyPI — a hallucinated import |
| **CTS021** | high | Dependency registered days ago with near-zero downloads (slopsquat shape) |
| **CTS022** | low | Runtime dependency with almost no users |
| **CTS023** | high | Name is one edit from a popular package (`expres` → `express`) |
| **CTS025** | low | Dependency deprecated upstream |
| **CTS030** | critical | Hardcoded provider key — Supabase service-role, Stripe live, OpenAI, AWS, GitHub … |
| **CTS031** | critical | Server secret routed through a `NEXT_PUBLIC_` variable |
| **CTS032** | high | `.env` in a git repo with no matching `.gitignore` rule |
| **CTS033** | critical | `'use client'` component reaching for a server-only secret |

Findings map to **OWASP Top 10:2025** and CWE.

## Usage

```bash
npx cleartoship                          # scan the whole project
npx cleartoship app supabase             # scan specific paths
npx cleartoship --offline                # no registry lookups
npx cleartoship --fix-prompt             # prompt to paste into Cursor / Claude Code
npx cleartoship --json -o report.json    # machine-readable
npx cleartoship --sarif -o results.sarif # GitHub code scanning
npx cleartoship --fail-on high           # stricter CI gate (default: critical)
npx cleartoship --ignore CTS004,CTS022   # skip rules
```

Suppress a single finding inline:

```ts
// cleartoship-ignore CTS001 — invoked only by a cron job, never by a request
export async function reconcileBilling() { … }
```

`// cts-ignore` on its own suppresses every rule on that line.

## Continuous integration

```yaml
# .github/workflows/security.yml
name: ClearToShip
on: [pull_request]

jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx cleartoship --fail-on=critical
```

To feed findings into GitHub's Security tab instead of failing the build:

```yaml
      - run: npx cleartoship --sarif -o results.sarif --fail-on=none
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }
```

## How it works

Four scanners, all static — nothing is uploaded and no database is contacted.

1. **Server Actions & Route Handlers** — parses TS/TSX with Babel, finds every exported
   function reachable over HTTP (`'use server'` modules, inline directives, `app/**/route.ts`
   method exports), then asks whether it authenticates, validates and scopes its writes.
   Recognises `next-safe-action` / `zsa` style wrappers so wrapped actions are not
   double-reported.
2. **Row Level Security** — replays your `.sql` migrations in filename order to build a model
   of the resulting schema (tables, columns, RLS state, policies, grants, views, functions),
   then judges the end state. This is the same class of check as Supabase's own `splinter`
   linter, but static, so it runs on a pull request with no live database.
3. **Dependency hallucination** — resolves every declared dependency against npm and PyPI,
   flagging names that do not exist at all, names registered days ago with no users, and names
   one edit away from a popular package. Results are cached for 24h under
   `~/.cache/cleartoship`.
4. **Secrets & client boundary** — pattern plus verification: candidate JWTs are decoded and
   only reported when the payload actually says `role: service_role`. Values in test fixtures,
   docs and commented-out counter-examples are downgraded rather than reported as breaches.

### Design notes

- **Fail open on uncertainty.** If a registry lookup fails, the package is treated as valid —
  a network blip must never be reported as a hallucinated dependency.
- **Test fixtures are not breaches.** Credentials under `tests/`, `fixtures/`, `docs/` or in a
  commented-out line are reported at `low`, never as blocking criticals.
- **Precision over recall on the noisy rules.** Typosquat matching skips exact matches and
  names shorter than five characters, where one-edit neighbours are meaningless.

## Programmatic use

```ts
import { scan, renderJson } from 'cleartoship';

const result = await scan({ root: process.cwd(), offline: true });
console.log(result.counts); // { critical: 0, high: 2, medium: 1, low: 0, info: 0 }
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clear to ship at the configured `--fail-on` threshold |
| `1` | Findings at or above the threshold |
| `2` | The scanner itself errored |

## Prior art

ClearToShip deliberately occupies the gap between general-purpose scanners and the modern
AI-assisted stack. It is not a replacement for [Semgrep](https://github.com/semgrep/semgrep),
[Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://github.com/google/osv-scanner),
[TruffleHog](https://github.com/trufflesecurity/trufflehog) or Supabase's
[splinter](https://github.com/supabase/splinter) — run those too. It answers a narrower
question those tools don't: *given that an LLM wrote this, what did it forget?*

## License

MIT
