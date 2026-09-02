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

**Next.js server surface** — Server Actions, Route Handlers, client boundary

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS001** | critical | Server Action / Route Handler mutates the database with no session check |
| **CTS002** | high | Caller's payload written to the database as an object — every key they sent becomes a column |
| **CTS003** | critical | `SUPABASE_SERVICE_ROLE_KEY` client built inside a user-reachable action |
| **CTS004** | medium | Authenticated mutation keyed only on a caller-supplied id (IDOR) |
| **CTS040** | high | Client component reads a server-side `process.env` variable |
| **CTS041** | high | `supabase.auth.getSession()` used as a server-side auth check — it does not revalidate the JWT |
| **CTS042** | critical | Webhook endpoint accepts an unsigned, unverified payload |
| **CTS043** | high | Request body spread straight into a database write (mass assignment) |
| **CTS044** | medium | `.passthrough()` / `z.any()` makes the schema decorative |
| **CTS045** | critical | AI SDK client set to `dangerouslyAllowBrowser: true` |
| **CTS046** | high | Cron route with neither `CRON_SECRET` nor a session check |

**Supabase / PostgreSQL** — schema, RLS, storage

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS010** | critical | Public table with Row Level Security never enabled |
| **CTS011** | low | RLS on with no policies — fail-closed, but the feature is probably broken |
| **CTS012** | critical | Policy grants writes with an always-true predicate |
| **CTS013** | high | Anonymous `SELECT` over a table holding emails, tokens or billing ids |
| **CTS014** | high | Table has a `user_id` column but no policy compares it to `auth.uid()` |
| **CTS015** | medium | `SECURITY DEFINER` function without a pinned `search_path` |
| **CTS016** | medium/high | View with definer rights, or a materialized view, exposed over the Data API |
| **CTS017** | critical | `GRANT INSERT/UPDATE/DELETE … TO anon` |
| **CTS018** | critical | Policy trusts `user_metadata`, which the user can edit themselves |
| **CTS019** | critical | `auth.users` republished through a view in the public schema |
| **CTS050** | medium | Overlapping permissive policies — they OR together and only widen access |
| **CTS051** | high | Storage policy lets anyone list every object in every bucket |
| **CTS052** | high | `SECURITY DEFINER` function executable by `anon` |

**Supply chain** — hallucinated and hostile dependencies

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS020** | critical | Dependency that **does not exist** on npm/PyPI — a hallucinated import |
| **CTS021** | high | Dependency registered days ago with near-zero downloads (slopsquat shape) |
| **CTS022** | low | Runtime dependency with almost no users |
| **CTS023** | high/medium | Name is one edit from a popular package (`expres` → `express`) |
| **CTS024** | by CVSS | Dependency version has a **published advisory**, resolved live from [OSV.dev](https://osv.dev). Vulns in `devDependencies` are labeled and held below the gate — a linter CVE never blocks a deploy the way a shipping one does. |
| **CTS025** | low | Dependency deprecated upstream |
| **CTS026** | critical | Registry serves HTTP 451 — the package was pulled for malware |
| **CTS027** | critical | Package was unpublished but still has installs; the name is open to takeover |
| **CTS028** | critical | `postinstall` hook that curls, evals or shells out |

Dependency rules read `package.json`, `requirements.txt` and `pyproject.toml` — **and**
`README.md`, `AGENTS.md`, `CLAUDE.md` and `.cursorrules`, because a hallucinated
`npm install` line gets copy-pasted out of an agent instruction file long before it
reaches a manifest.

**Secrets & client bundle**

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS030** | critical | Hardcoded provider key — Supabase service-role, Stripe live, OpenAI, AWS, GitHub … |
| **CTS031** | critical | Server secret routed through a `NEXT_PUBLIC_` variable |
| **CTS032** | high | `.env` in a git repo with no matching `.gitignore` rule |
| **CTS033** | critical | `'use client'` component reaching for a server-only secret |
| **GL-\*** | high/critical | 219 further credential providers, vendored from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), gated on Shannon entropy |

**Logging, error-handling & deserialization** — the detectable slices of A08/A09/A10

| Rule | Severity | What it catches |
| --- | --- | --- |
| **CTS070** | high/medium | Secret, token or PII (or a whole request body) written to a log (A09) |
| **CTS071** | high/medium | A security check that **fails open** — `catch { return true }` — or swallows its error (A10) |
| **CTS072** | high | Insecure deserialization of untrusted data — `unserialize`, `pickle.loads`, unsafe `yaml.load` (A08) |

**Community ruleset** — 435 additional rules vendored from
[GuardVibe](https://github.com/goklab/guardvibe) (Apache-2.0)

Reported under their upstream `VG###` ids. These cover ground the AST scanners
don't: known-vulnerable framework versions (`next` 14.2.3 is still shipped by a
lot of AI scaffolds and carries CVE-2025-29927, a middleware auth bypass),
Dockerfiles, Terraform, GitHub Actions pinning, prompt injection and MCP tool
runtimes, React Native, Go and shell.

27 upstream rules are **superseded** where ClearToShip's own AST check is more
precise, 6 are **withheld** as measurably noisy, 10 React Native rules are
**skipped as inapplicable** on a project that is not React Native, 9 carry a
**match guard** for a
shape their regex cannot exclude (a `"link": true` lockfile entry has no
integrity hash by design; `querySelectorAll` is not a SQL call; `eval()` inside
a sentence about eval is prose), and 3 name-heuristic rules are
**manifest-only** — they never run over a `package-lock.json`, where they matched
ordinary transitive packages (`fast-glob`, `core-js`) and named nothing anyone
could act on. Each list carries a reason per rule in
`src/scanners/community.ts`. Run `--no-community` to use only ClearToShip's
rules. See [ATTRIBUTION.md](ATTRIBUTION.md).

Findings map to **OWASP Top 10:2025** and CWE.

## OWASP Top 10:2025 coverage — honest version

ClearToShip is not an even, "100% coverage" scanner and does not claim to be —
it is strongest exactly where AI-generated code fails. Coverage by category:

| Category | Coverage | What we detect |
| --- | --- | --- |
| **A01** Broken Access Control | 🟢 Strong | Missing Server Action / route auth, RLS holes, IDOR, definer bypasses |
| **A03** Supply Chain Failures | 🟢 Strong | Hallucinated / slopsquat / typosquat packages, live CVEs (OSV), install hooks |
| **A07** Authentication Failures | 🟢 Strong | `getSession` misuse, weak sessions, JWT (mostly vendored) |
| **A02** Security Misconfiguration | 🟢 Strong | Docker, Terraform, headers, CORS — via the vendored pack |
| **A05** Injection | 🟢 Strong | SQLi, XSS, command injection |
| **A04** Cryptographic Failures | 🟡 Moderate | Hardcoded keys (234 credential patterns), weak hashing |
| **A09** Logging & Alerting Failures | 🟡 Targeted | **Secrets / PII written to logs** (CTS070) — the statically knowable slice |
| **A10** Mishandling Exceptions | 🟡 Targeted | **Fail-open / swallowed error on a security check** (CTS071) |
| **A08** Data & Integrity Failures | 🟡 Targeted | Unverified webhooks (CTS042), **insecure deserialization** (CTS072) |
| **A06** Insecure Design | 🔴 Not statically detectable | Missing threat modeling is an architecture concern — no static scanner covers it, and we don't pretend to |

Two honest points a reviewer would raise, answered up front:

- **A06 and A09 are hard for _any_ static tool.** A06 (Insecure Design) is about
  missing threat modeling — you cannot grep for "the developer didn't consider an
  abuse case." A09 (Logging failures) is largely a runtime/ops concern. Semgrep,
  Snyk and CodeQL have the same limits. ClearToShip covers the *detectable slices*
  (secrets in logs, fail-open error handling) and is honest that the rest needs a
  human threat model and runtime observability, not a scanner.
- **Coverage is uneven on purpose.** The thesis is "the gaps LLM-generated code
  leaves," which cluster in A01/A03/A07/A04 — so that is where the rules cluster.

Running with `--no-community` (first-party rules only) covers **8 of 10**
categories directly (A01, A03, A04, A05, A07, A08, A09, A10); the community pack
adds A02 and broadens A05/A07.



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
npx cleartoship --no-community           # ClearToShip rules only
npx cleartoship --no-gitignore           # also scan what .gitignore excludes
npx cleartoship --markdown               # markdown report (PR comments / summaries)
```

Suppress a single finding inline:

```ts
// cleartoship-ignore CTS001 — invoked only by a cron job, never by a request
export async function reconcileBilling() { … }
```

`// cts-ignore` on its own suppresses every rule at that location. The directive
may sit at the top of a multi-line comment block, so a real justification has
room to be written out.

## Continuous integration

### The CLI (works anywhere, today)

One line in any workflow, on any CI. It needs nothing from GitHub beyond npm:

```yaml
      - run: npx cleartoship --fail-on=critical
```

To feed findings into GitHub's Security tab:

```yaml
      - run: npx cleartoship --sarif -o results.sarif --fail-on=none
      - uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: results.sarif }
```

A copyable workflow is in [`examples/security-cli.yml`](examples/security-cli.yml).

### GitHub Action

> **Not usable from other repositories yet.** The action lives in *this*
> repository, which is currently private, so `uses: murtazaozdemir/cleartoship@…`
> resolves for nobody but its owner — GitHub answers `Unable to resolve action`
> — and it cannot be listed on the Marketplace. Nothing about it is broken; it
> simply needs the repository to be public, and it works the day that happens.
> Until then, use the CLI recipe above. The npm package itself is public and
> unaffected.

Posts a summary comment on every pull request, blocks the merge on critical
findings, and optionally uploads to the Security tab. Copy
[`examples/security.yml`](examples/security.yml) into `.github/workflows/`:

```yaml
name: ClearToShip
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: murtazaozdemir/cleartoship@v0.10.1
        with:
          fail-on: critical
          comment: true
```

| Input | Default | Purpose |
| --- | --- | --- |
| `paths` | *(whole project)* | Files or directories to scan |
| `fail-on` | `critical` | Fail the job at or above this severity (`critical`/`high`/`medium`/`low`/`none`) |
| `comment` | `true` | Post/update a sticky summary comment on the PR |
| `sarif` | `false` | Upload results to GitHub code scanning |
| `offline` | `false` | Skip registry and OSV lookups |
| `working-directory` | `.` | Directory to scan from |
| `version` | *(matches the action ref)* | npm version of the scanner to run; `latest` to always track the newest, `local` to build from the checkout |

Outputs `verdict` (`clear`/`conditional`/`hold`), the per-severity counts
`critical`, `high`, `medium`, `low`, plus `total` and `blocking` (findings at or
above `fail-on`) for use in later steps. The comment is *sticky* — re-runs edit
the same comment instead of piling up.

By default the action runs the scanner version its own ref declares, so
`@v0.10.1` runs `cleartoship@0.10.1` and pinning the ref pins the behaviour. If
that version is not on the registry, it builds from its own checkout instead, so
`uses: …@ref` works against an unpublished commit.

## How it works

Six scanners, all static: your source is read and parsed, never executed, never
uploaded, and no database is connected to.

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
   only reported when the payload actually says `role: service_role`. 15 hand-tuned patterns
   cover the providers that matter most; 219 more come from the vendored gitleaks ruleset,
   each gated on a keyword prefilter and a Shannon entropy threshold so that
   `your_api_key_here` never reads as a breach. Values in test fixtures, docs and
   commented-out counter-examples are downgraded rather than reported.
5. **Known vulnerabilities** — dependency versions are resolved from
   `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` (falling back to the range floor)
   and queried against OSV.dev, the database behind Google's `osv-scanner`. Live data
   beats hand-written version regexes, which go stale the week they are written — so when
   OSV answers, the vendored CVE rules stand down. `--offline` reverses that.

### Design notes

- **Fail open on uncertainty.** If a registry lookup fails, the package is treated as valid —
  a network blip must never be reported as a hallucinated dependency.
- **Test fixtures are not breaches.** Credentials under `tests/`, `fixtures/`, `docs/` or in a
  commented-out line are reported at `low`, never as blocking criticals.
- **Where a file lives changes what a finding costs.** CTS024 already separated a
  CVE that ships from one that only ever runs on your machine; the same reasoning
  now covers the rules that read code. An interpolated query in `scripts/`, a
  swallowed error in a `*.config.ts` — build and maintenance tooling runs with
  credentials its author already holds and never answers a request from the
  internet, so those drop one severity step, with the reason attached to the
  finding rather than applied silently. `bin/` and `migrations/` are deliberately
  excluded: one is a published CLI's entry point, the other is production schema.
  Across five dogfooded repos this moved 21 findings out of `critical` without
  hiding one of them.
- **A bound parameter is not an injection.** `db.prepare(\`UPDATE ${table} SET
  csv = ? WHERE id = ?\`).bind(...)` interpolates an identifier while its values
  go through placeholders — the correct pattern, and the one a SQL-injection
  regex reads as the bug. Both SQL rules now read the whole statement and the
  call chained to it, and stand down when the values are bound. They still fire
  when any interpolation reads from the request, so a query that binds one value
  and concatenates another is reported.
- **A rule that cannot apply here is not run.** The vendored ruleset covers
  ground this project may not stand on: certificate pinning and WebView
  hardening are React Native concerns, and a browser will not let a page pin a
  certificate at all, so those rules are skipped unless the project actually is
  React Native. Likewise the "no request-body size limit" rule, whose own text
  says Next.js already imposes one. The report names what it skipped and why.
- **Mass assignment means the payload arrives whole.** CTS002 and CTS043 fire when
  the object the caller sent reaches the columns — `update(body)`,
  `data: { ...input }`, including one level down where Prisma and Drizzle put it.
  Reading named fields into an explicit column list is the safe pattern and is
  never reported, whether or not a schema library was involved: of 102 findings
  the old, broader rule produced on one dogfooded app, all 102 were that shape.
- **Precision over recall on the noisy rules.** Typosquat matching skips exact matches and
  names shorter than five characters, where one-edit neighbours are meaningless.
- **Your `.gitignore` decides what counts as your project.** Ignored paths are
  not scanned: they never reach a CI checkout, so a finding there is one nobody
  can act on and nobody's pipeline would reproduce. This is usually the
  difference between a usable report and an unreadable one — a repo with a
  gitignored folder of reference apps went from 1,487 findings to 235, and from
  84 seconds to 2. `.env` files are the deliberate exception, since a secret on
  your disk is a secret either way and CTS032 exists to check that the file *is*
  ignored. `--no-gitignore` scans everything, and the report always says how many
  paths were skipped.
- **Auth is followed into the helper it lives in.** Almost no real app repeats the
  session check inside every action — it resolves in `lib/auth.ts`, or in a
  framework helper such as Shopify's `handleSessionToken`, and each action calls
  that. ClearToShip resolves first-party imports (relative paths and `@/`-style
  aliases) and credits a call whose helper authenticates, directly or through
  another helper. Third-party packages are never followed, so a call into
  `node_modules` still proves nothing on its own.
- **A machine endpoint authenticates differently.** Comparing an `Authorization`
  header against a server-side secret is the auth check for a cron or
  webhook route, and a verified provider signature *is* the caller's identity —
  neither is reported as missing authorization.

## Trust

A security tool earns its place by being auditable, so the guarantees are stated
plainly and each one is checkable in a few seconds. `SECURITY.md` has the full
version, including how to report a vulnerability.

- **Read-only on your code.** The only files ClearToShip writes are the report
  you ask for with `--output` and its 24-hour registry cache under
  `~/.cache/cleartoship`. Nothing under the scan root is ever modified.
- **Your code is never executed.** No `child_process`, no `eval`, no dynamic
  import of a scanned file. Everything is text, an AST and regexes — which is
  also why it is safe to point at a repository you have not read yet.
- **No source leaves the machine.** Online, three hosts are contacted and they
  receive package **names and versions** only: `registry.npmjs.org` /
  `api.npmjs.org`, `pypi.org`, `api.osv.dev`. No file contents, no paths, no
  project name. `--offline` disables all three and makes a run a pure local
  computation.
- **No database connection.** The RLS checks read your migration files. There is
  no database driver in the dependency tree.
- **Five runtime dependencies.** Three Babel packages, `commander`,
  `picocolors`. The GuardVibe and gitleaks rulesets are vendored into
  `src/vendor/`, not installed, so they are visible in every diff and pinned by
  construction.

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

## Prior art, and what was taken from where

ClearToShip occupies the gap between general-purpose scanners and the modern AI-assisted
stack. It is not a replacement for [Semgrep](https://github.com/semgrep/semgrep),
[Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://github.com/google/osv-scanner)
or [TruffleHog](https://github.com/trufflesecurity/trufflehog) — run those too. It answers a
narrower question they don't: *given that an LLM wrote this, what did it forget?*

The rule set was designed after surveying the field. What each source contributed:

| Source | License | What was taken |
| --- | --- | --- |
| [supabase/splinter](https://github.com/supabase/splinter) | none stated | The vulnerability classes behind CTS010–019 and CTS050–052. Splinter runs SQL against a live database; these are static reimplementations against migration files. Verified by pointing ClearToShip at splinter's own `test/sql/` fixtures. |
| [slopcheck](https://github.com/mattschaller/slopcheck) | MIT | Three distinctions worth making: HTTP 451 (pulled for malware) ≠ 404 (never existed) ≠ unpublished-with-installs (open to takeover) — CTS026/CTS027. And the idea of reading install commands out of prose and agent instruction files. |
| [guardvibe](https://github.com/goklab/guardvibe) | Apache-2.0 | Coverage gaps: webhook signature verification, cron secrets, mass assignment, `dangerouslyAllowBrowser`, schema escape hatches, `getSession` vs `getUser` — CTS040–046. |

**No rule content was copied.** Every check here is an independent implementation, and the
detection engine is different in kind: ClearToShip parses TypeScript to an AST and replays SQL
migrations into a schema model, where the regex-and-window approach used by several of these
tools cannot express "this function has no auth check anywhere in its body".

That distinction is not just technical pride — it is a licensing constraint. Two of the most
tempting corpora, **TruffleHog** (800+ verified credential detectors) and
**RouteWarden**, are **AGPL-3.0**; lifting their detectors into a commercial product carries
the AGPL's network-use obligations. **semgrep-rules** ships under the bespoke *Semgrep Rules
License v1.0*, which needs reading before any rule is reused. **splinter** and
**supabase-exposure-check** publish no license at all, which means default copyright — ideas
are free, expression is not. Vulnerability classes are facts and cannot be owned; regexes,
queries and rule text can be.

## License

MIT
