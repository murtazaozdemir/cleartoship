# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.13** — linear-time matching for the vendored rules, one
RLS schema per project, CTS014 per command, auth wrappers judged by behaviour.
**v0.13.12** fixed a sticky-PR-comment regression in
0.13.11's Action (a new comment on every run). **v0.13.11** shipped the
2026-09-23 audit: incomplete scans exit 3, tracked files can no longer be hidden
by `.gitignore`, and it is the first release with build-provenance attestations,
which the Action verifies before it runs a downloaded bundle.
[The Action is on the GitHub Marketplace](https://github.com/marketplace/actions/cleartoship)
(since 2026-09-22), under Security / Code Scanning Ready. Every check is in the one free download,
including the RLS, Server Actions and LLM/agent suites, as of v0.13.9.
(They were split into a private package for v0.13.6–0.13.8, which left them in no
downloadable build; v0.13.8 also closed a hole where a scan would run a package of
that name found beside it.) v0.13.6's own release run is red — it ran the old
workflow, which still tried npm, and a re-run uses the workflow as it was at the
tag. The release itself is fine.
Install from
[cleartoship.app](https://cleartoship.app/cleartoship.mjs)
(`curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs && node cleartoship.mjs`);
the same file is on [the GitHub release](https://github.com/murtazaozdemir/cleartoship/releases/latest).
**Not distributed through npm, by decision (2026-09-21):** the maintainer can no
longer use npmjs.com. The package was unpublished on 2026-09-03 and the name is
unclaimed, so anything on the registry under it is **not from this project**:
the docs say so, and the Action and CI no longer run or recommend it.
`release.yml` has no npm publish steps any more (removed 2026-09-21); the
`NPM_TOKEN` secret it used is dead and can be deleted from the repository.
`release.yml` verifies that the release carries a bundle that runs and reports
its version, and `deploy-site.yml` serves that build from the domain and compares
its hash with the release asset after every deploy._
_v0.13.0 and earlier published **unsigned** — npm's registry refuses provenance
from a private source repo. The repository is public now, and `release.yml`
reads its visibility, so 0.13.1 is the first release signed with provenance._

## Where this stands

Twenty-one releases, 0.8.0 → 0.13.10. The calibration work is the point of the project
so far: across a five-repo corpus the tool went from 2,290 findings to a few
hundred, and from 157 criticals to a handful — **every removal verified by
reading the code it was about**, never by adjusting a threshold. Reports that
name a real problem are worth more than reports that cover a table.

0.13.0 added the three agent rules (CTS083/084/085) and made the LLM/agent
surface the headline rather than the fifth section. 0.13.1 was the first signed
release. 0.13.2 raised the Node floor onto Babel 8.

**0.13.3 is the first release fixed by code I did not write.** Scanning
vercel/ai-chatbot, modelcontextprotocol/servers and assistant-ui turned up two
real defects in one afternoon that six repositories of my own never showed: paths
were reported relative to the shell's cwd rather than the scanned repo, and
CTS083 matched `clients.delete(id)` on an in-memory `Set` because the root
pattern accepted a prefix instead of a whole segment. Both were exactly the kind
of thing dogfooding structurally cannot find — my repos all sit beside this one,
and I would never have written `clients` for a Set.

**0.13.5 is a full self-audit, and the self-scan is why most of it was found.**
Ten defects, every one reproduced before it was fixed and covered by a test
after. Three of them fired on other people's correct code — a repository with a
`site/` directory had that whole subtree reported clean without a file being
opened; a library whose README says `npm install <its own name>` before the
first publish got a *critical* hallucinated-dependency finding; and `/.env` or
`.env.local` in a `.gitignore` were both reported as failing to cover the file
sitting next to them, because CTS032 compared the text against five literal
strings instead of asking the matcher this repo already ships. A fourth was
quieter and worse: OSV publishes `severity[].score` as a CVSS *vector*, so
`Number()` returned `NaN` on every GitHub-sourced advisory and a 9.8 and a 5.3
were both reported `high` — the "by CVSS" column was not what happened.

The pattern worth keeping: the CI self-scan read `src` and nothing else, so the
README, the manifests, the shipped Action and the landing page were never
scanned by the tool that scans them for everyone else. Pointing it at all of
them found a credential-shaped literal in a comment written the same afternoon.

**0.13.9 re-ran the calibration on a fresh, seeded sample of 155 public repos**
(the prior corpus was lost when the machine crashed mid-session; nothing
committed was lost, only the scratch data). Hardcoded credentials (CTS030):
of 96 critical PostgreSQL connection-string findings, 63 were a default
password on localhost and 18 were templates — only 5, across 2 repos, were a
real password to a remote host; 222 → 51 findings. CTS001 (missing auth on a
Server Action or route handler that writes) got the same treatment: one
finding read per repo, 60 of 77 wrong. Fixed at the cause — a helper that
provably does nothing outside the process (new `src/scanners/effects.ts`),
signature and credential-header checks recognised more widely, an
authorization helper credited when its result gates the write before it
happens. **Verified by reading what the fix removed, not just what it kept**:
of 60 sampled removals, 2 were real bugs the first version of the fix had
hidden along with the noise (a caller-set `x-actor-role` header read as
authorization; an approval flag read from a row the caller's own request body
selected) — both restored, both have regression tests now. 732 → 603
findings on the full corpus, all 17 confirmed real findings still reported.
Also found and fixed in the same pass: the three registry/OSV-dependent
tests had been silently skipping on every run, local and in CI, since at
least 73abec9 — the probe that decides `online` sat below other tests in the
file and starved on the event loop before its own timeout fired.

**0.13.10 is the first release found by dogfooding a sibling project.**
Scanning `app A` (live on the Shopify App Store) with the newly
calibrated tool, then verifying its maintainer's fixes actually landed,
turned up two more scanner bugs that the 155-repo corpus never surfaced: a
`cleartoship-ignore` comment that silently didn't apply because a real
statement sat between it and the line it was suppressing, and a regex false
positive in the vendored "JWT algorithm none" rule (VG105) — it matched a
function's own declaration as a call when a helper shared the wrapped
function's name, and separately backtracked across nested parens in a
`jwt.verify` call's secret argument and missed the real options object.
Fixed with a `MATCH_GUARDS` entry rather than touching the vendored file,
verified against both the fixed code and the actual pre-fix vulnerable
version pulled from that repo's own git history. Also listed [the Action on
the GitHub Marketplace](https://github.com/marketplace/actions/cleartoship)
this release — the Developer Agreement acceptance was the last blocker, and
`action.yml`'s description turned out to be 83 characters over the
Marketplace's limit. The first attempted fix broke `action.yml` outright (an
unquoted colon reads as a YAML mapping key); the `Action integration test`
workflow caught it within a minute, before it reached a tag.

**The 2026-09-23 full audit (shipped as 0.13.11) found the
worst failure class this project exists to prevent — "clear" on code it never
read — in eight separate places, in this tool itself.** A committed `.gitignore`
could hide a tracked file (a PR adds `app/backdoor.ts` to `.gitignore` and the
scan is 🟢, exit 0); a `test/fixtures/x/package.json` named `minimist` switched
off the CVE and registry checks for the root's real `minimist@1.2.0`; a 40 KB
`a.b.b.b…` chain overflowed the stack and killed three whole scanners, taking a
real CTS001 in another file with it, and still exited 0; `.ts` files were
parsed with JSX on, so a `<string>x` cast made the file unparsed and the run
clear; unreadable files, files over the 2 MB cap and files the community ruleset
thought too big (400 KB–2 MB) were all silently skipped. Now every one of those
is `incomplete`, and **an incomplete run exits 3** unless `--allow-incomplete`
is passed; the Action fails on it by default. `.git/index` is parsed (v2–v4, no
child process) so a tracked file is always scanned. Detection gaps found in the
same pass and fixed: Pages Router API routes, `export { fn }` / `export default
fn` / `cache(async …)` / NextAuth `export { handler as POST }` were never
analysed; an auth call counted wherever it sat — after the write, in a
`NODE_ENV === 'test'` branch, in a closure never called, or as `if (session)
return`; Supabase's own default policy name "Enable read access **for all**
users" was parsed as `FOR ALL` (critical false positive) and a name containing
" to " swallowed the role list (missed critical); FORCE was read as ENABLE;
restrictive policies were judged as grants. The untrusted-input side: CTS031 and
vendored rules printed full secrets beside CTS030's redacted copy (now one
redaction pass over every finding); filenames and install scripts could inject
links, images and @-mentions into the PR comment and ANSI into the terminal;
lockfiles and `.gitignore` were read through symlinks (a `.gitignore ->
/dev/zero` ate 2 GB in two seconds); VG678 went 8 KB → 8.5 s (bounded override,
now 8 ms, same match positions on ~1.5M checked); a hostile `.gitignore` glob
spun past two minutes (linear matcher, 0 differences from the old one over 200k
fuzzed cases). Supply chain: releases now carry build-provenance attestations
from a publish job that never runs `npm ci`, the Action verifies the bundle's
attestation and version before running it, every action is SHA-pinned, and the
Cloudflare token no longer sits in the env of `npm ci`. And the landing page had
said `@v0.8.0` since 0.8.0 — the version-pin check only read the README; it now
reads `site/public/*.html` too. **Verification:** 101 → 205 tests, every new one
failing before its fix; each audit PoC re-run against the merged build; the
Server Actions changes run before/after on ten real Next.js repos here, which
caught and fixed two CTS004 false positives the first version introduced in
app A. Self-scan down to five lows; the self-scan also found the last
bug of the pass — the comment lexer did not know regex literals, so a backtick
in `/`\s*,/` opened a phantom template string in `community.ts` and VG105
fired on a sentence a hundred lines later.

**Shipping 0.13.11 was its own lesson in the rule the release skill opens
with.** Every run was green, and the release still had nothing on it as far as
two consumers could tell: for about two minutes after the draft was published,
GitHub served the release's embedded asset list empty while the assets endpoint
and the download URLs already had all three files. The site redeploy that
release.yml dispatches landed inside that window, failed with "no assets to
download", and left cleartoship.app on 0.13.10; the release job's own verify
step read the same list and passed only by timing. Both now read the assets
endpoint or the download URL, with retries (90a8d96), and a redeploy was
checked by hash against the attested asset, not by exit code. Then the Action
integration test on an open Dependabot PR found a second 0.13.11 bug: the sticky
PR comment's author lookup ran `me=$(gh api user --jq .login || true)`, and on
an HTTP error `gh api` prints the error body to stdout, `--jq` or not — so the
default token's 403 left `me` holding a JSON blob, no comment matched, and every
run posted a new one. 0.13.12 tests the exit status instead. The test that
caught it asserts exactly one comment, which is the assertion that could fail.

**0.13.13 closed the limits the audit had left open on purpose, and the
biggest one turned out to be six times larger than the audit thought.** The
audit counted ~35 super-linear vendored patterns; fuzzing all 435 active rules
on their own trigger words found 209 over 50 ms at 400 KB and 125 over 8 s —
`eval.*\(` alone spent 50 s in one uninterruptible `exec`, and a 396 KB file of
`eval` repeated kept 0.13.12 busy for more than 15 minutes. Rewriting 200
patterns by hand was not credible, so the vendored patterns V8 backtracks on
(382 of 435) now run on a memoizing matcher that takes V8's paths in V8's order
and remembers every (state, position) that failed: same matches, linear time.
Worst rule now 126 ms at 400 KB, all growing linearly; 0 differences from V8
over 27,391 matches in 129 MB of real code. Pointing the same matcher at the
gitleaks rules took a 396 KB one-identifier file from 10.8 s to 133 ms (two
patterns nest `[\w.-]{0,50}?` inside itself) — and running the existing suite
over it found a bug in the matcher before it shipped: it cached where the next
required text sat and reused that cache when the same text was searched again
from the start, so the **second of two files with identical content got no
community or gitleaks findings at all**. Proven by a test that fails without
the fix. The other limits: the RLS model is now one schema per project (a
whole-repo scan had mixed this repo's two fixtures, inventing a CTS050 on one
and dropping a CTS014 on the other), and CTS014 is judged per command, so an
`auth.role() = 'authenticated'` policy OR'd beside an `auth.uid()` one is
reported; Prisma's `migration_lock.toml` now marks non-Postgres migrations,
which removed 11 false CTS010 criticals from app C's SQLite app. Auth
wrappers are judged by what their definition does — iron-session and next-auth
v5 `auth()` attach a session without requiring one, so they no longer count as
auth on their own — and unknown package wrappers still credited by name are
now named in a warning. A guest-only action (`if (session) redirect(...)`) is
low only while everything it does is what a sign-up does; the two bugs a name
list once hid, `register` hardcoding an Admin role and `leads` running paid
enrichment, stay critical and are pinned by tests. **Verified:** 205 → 238
tests; before/after on 11 real repos differs only by app C's 11 removed
false criticals, with scan times unchanged.

**The 2026-10-13 full audit: eleven defects, and the worst class was again a
file or a rule that was never read at all.** Four of them were silent coverage holes,
every one reachable by naming a file. `looksGenerated` skips machine-generated
code on purpose — a Prisma client ships its own credentials and its own
`queryRawUnsafe` — and it skipped it *silently*: `app/actions/admin.gen.ts` and
`src/generated/client/admin.ts`, byte-identical to an `app/actions/admin.ts`
reported critical beside them, were left out of a 🟢 report that named neither.
There is a `Generated files skipped (n)` line now that names them, passing like
the skipped build directories rather than incomplete, since making it
incomplete would fail every Prisma project's CI. **HTML was not read at all**:
`.html` was not in `SCAN_EXTS`, so a `public/index.html` with a Supabase
service-role JWT and an `sk_live_` key in an inline `<script>` produced nothing
and said nothing — and this project's own self-scan has listed `site` since
0.13.5 while opening none of its four landing pages. **Five vendored rules
could never match any file**: VG517/518/520 are registered for `toml` and
VG750/753 for `firestore`, and `languagesFor` answered neither, so `.toml` files
were read by the walk and then skipped by the community scanner for having no
language, and no `.rules` file was read at all — all five counted as active in
the rule count the report prints, two of them critical. A test now asserts that
no vendored rule's language set is unreachable, and `firestore.rules` /
`storage.rules` make a repository a Firebase one, because the two rules that
read them are otherwise skipped as "not a Firebase project".

**Then four rules reporting on correct code, two of them critical.** A route
that calls `auth()`, returns 401, reads the caller's own `is_admin`, returns 403
and only then promotes somebody — the shape VG1008's own `fixCode` asks for —
got **two criticals**: VG1008, whose name is "Admin Role Elevation Without
Authorization Check" and whose pattern contains no notion of one, and VG154,
because an access-control gate has the same read-check-write shape as a credits
race. CTS001 read the same function and correctly said nothing, so the report
contradicted itself and would have failed the user's build at the default
`--fail-on=critical`. Both are guarded now, on VG1025's precedent; upstream's own
benchmark has a test named *"skips when requireAdmin guard is present"* that the
rule failed, and it passes. VG012 ("XSS via innerHTML") fired on 17 of 23 real
sites across eleven repositories: ten were `<style dangerouslySetInnerHTML={{
__html: css }}>` (shadcn's own `chart.tsx` among them), others a concatenation of
nothing but string literals, a value already through `sanitizeHTML` / `escHtml` /
DOMPurify — including guardvibe's own `fixCode` string demonstrating the fix —
and `showing ? '<path …/>' : '<path …/>'`, whose condition is a name and whose
two values cannot be anything else. A `<style>` element's CSS text, an
all-literal expression and one passed through an escaper are not HTML sinks; a
bare identifier still is, because proving that `userHtml` holds a module
constant is dataflow, and assuming it would drop the finding. VG999 duplicated
CTS081 line for line (13 times in the sweep) and is superseded.

**And two rules that described a different problem than the one they found.**
CTS012 told an always-true INSERT policy that "any signed-up user can overwrite
or delete every other user's rows" — an INSERT policy cannot, PostgreSQL needs
an UPDATE or DELETE policy for that. It is split per command now: critical when
anon-facing, or when an ownership column means the caller can attribute the row
to somebody else, and high for an append-only table with no such column, which
is the common correct shape of exactly that policy. CTS050 reported a widening
between two policies whose predicates are the same text — app F's
`uploads_own_prefix_insert` and `uploads_user_folder_insert`, identical `with
check`, one superseding the other across migrations — when the OR of a predicate
with itself is that predicate; it was also comparing clauses PostgreSQL does not
apply to the command in hand (a `FOR ALL` policy's `WITH CHECK` under SELECT).
The last two defects were quieter: every scanner built `Suppressions` from the
source alone, though the class takes the file path and its own comment says
scanners pass it — so the per-language path was dead outside its unit tests and
every check ran the fallback, where `//`, `#` and `--` all open a comment
whatever the file is, and `curl https://x cts-ignore` in a shell script
suppressed that line. All six call sites pass the path, and `commentStyleFor`
learned JSON-with-comments, TOML and HCL, which `secrets.ts` had been
compensating for on its own. Finally two README counts were wrong — "435
additional rules vendored" is the count that *runs* (468 are vendored, and the
same README's own per-category table counts all 468) and "21 carry a match
guard" was 22 — so `RULE_COUNTS` is exported and a test asserts the prose
against the code, the same move `check-version-pins.sh` makes for versions.

**The eleventh was the registry answering in a way that looks healthy**, which
is the failure the release skill opens with, in the one place it had not been
looked for. npm serves **HTTP 200** for a fully unpublished name — the packument
carries `time.unpublished` and an empty `versions` map — and `lookupNpm` read
the status rather than the content: `exists: true`, zero versions, and
`time.created` then made it *recent*, so the verdict was CTS021, "newly
published, barely used". The example is this project's own name, unpublished
2026-09-03, which is how the audit found it: scanning `README.md` on its own
reported the sentence that warns people off installing `cleartoship` as a
barely-used dependency of this repository. The truth is CTS027, critical, and it
already existed — an install of such a name fails, and the name is free for
anyone to claim and inherit the installs that still ask for it. The 404-plus-
traffic path had always said so; the 200 path never reached it. (The full
self-scan was never affected: `package.json` declares the name, so it is "defined
by this repository itself, so not looked up" — verified again with a cold cache.)

**Verification:** 238 → 252 tests; 12 of the 14 new ones fail against the
pre-fix build, and the other two are the true positives each fix had to keep
(VG1008 on an ungated `update({ is_admin: true })`, VG154 on the credits
race). Before/after over eleven real repositories (app A,
app C, app D, app B, app F, app E, app G, guardvibe,
splinter, dep-hallucinator, gitleaks): −17 VG012, −13 VG999, −1 VG1008, −1
CTS050, +6 VG012 on app G's HTML dashboards, which are newly read and really
do write `innerHTML=cpuTopHtml` built by concatenating scan data. **Every
removal was verified by reading the code it fired on**, and 2,291 → 2,313 files
scanned with the times unchanged. That sweep ran `--offline`, so the registry
fix is covered by a test that stubs `fetch` and asserts the facts rather than by
the corpus. The self-scan went 64 → 68 files — it reads
the landing pages now — and stayed 🟢 on the same five lows, after the first
HTML-reading run reported a `high` on `site/public/index.html`'s own
`innerHTML`, which was the escaped-constant false positive above. Not released
yet: the work sits on the branch `audit-2026-10-13`, unpushed, and reaches
users only once it is merged and a tag ships it.

**The 2026-10-21 full audit: the same two failure classes, one layer further
out — text the scanner decoded into mojibake, and ecosystems whose conventions
it did not know.** Every read in the tool was `utf8`, so a UTF-16LE `.env` —
what PowerShell's `>` redirect writes — decoded to NUL-riddled garbage no
pattern can match, counted as scanned, and said nothing; and a UTF-8 BOM in
front of `package.json` made `JSON.parse` throw inside collectors that swallow
the error, which switched off the entire dependency surface — hallucination,
typosquat, CVE and install-hook checks — while the report said "no dependencies
declared", passed, complete. Every read now goes through one BOM-aware decoder
(UTF-16LE/BE decoded, UTF-8 BOM stripped), and a manifest that exists but
cannot be parsed makes the run incomplete rather than clean. The other
never-read files: `.svelte`, `.vue` and `.astro` were not in `SCAN_EXTS` at all
— `SKIP_DIRS` has named `.svelte-kit` and `.nuxt` since it existed, so those
users were always expected while every line of their components went unread;
the same `sk_live_` key that was a critical in a `.ts` file produced nothing in
all three. They are read now as the HTML-shaped documents they are (secrets
plus the 7 html rules; the AST scanners skip them like inline `<script>` in
`.html`, the same documented limit). A `.env` whose *parent directory* is
gitignored was never reached although `SCAN_EVEN_IF_IGNORED` exists for exactly
ignored `.env` files — the walk now peeks one level into each directory the
ignore rules skip. And the manifests the tool read but asked nothing about:
`requirements-dev.txt` and `requirements/*.txt` were never collected (only the
exact name was), `[tool.poetry.group.*.dependencies]` and PEP 735
`[dependency-groups]` never matched the pyproject parser, and pnpm v9's quoted
scoped entries (`'@babel/core@7.24.0':`) resolved to nothing, so OSV was asked
about range floors instead of the versions actually installed.

**Rules on correct code, the sweep's second half.** The biggest cluster was
VG010/VG123 ("SQL injection"): three criticals on a QuickBooks integration
whose query strings are QBQL sent URL-encoded to Intuit's HTTP API —
`MAXRESULTS`/`STARTPOSITION` are keywords no SQL driver parses, and that API
has no parameterized form to recommend instead; two more on
`PRAGMA table_info(${quoteIdent(table)})`, where the interpolation *is* the
escaping — credited now when every hole is a SQL quoting call, with HTML
escapers deliberately excluded and bare identifiers still reported, the line
VG012 drew; and two on a rule-definition file's own `description:` strings,
cleared by refusing matches that sit inside a string literal. VG123 duplicated
VG010 on all 24 of its findings — upstream's own tests call VG010 "the concat
rule (which dedup-takes-over)" — and is superseded. VG001/VG062 ("hardcoded
credentials") reported a redaction helper's own replacement string
(`password="[REDACTED]"`), a docs sample whose body is `1234567890abcdef`
twice, a value ending in the ellipsis its author cut it with, and — on a login
route — `DUMMY_PASSWORD_HASH = '$2b$12$…'`, the standard timing-equalization
idiom: a PHC-format hash is a verifier, not a credential anyone can present.
VG060 ("weak *password* hashing") fired on `hashlib.md5(hostname + mac)`
deriving a stable device id; it now requires a password within sight of the
call. VG154 ("check-then-act race") hit four times, none a race worth the
word: count-based rate limiters that reject at the limit and append the row
being counted (overshoot bounded by in-flight requests is the accepted
property of every soft limiter), and pages that count one table and save
another, which is load-then-save. Same table with an update — the credits
race — stays reported, pinned by the 0.13.13 test. And an `sk-ant-…` key was
reported twice on its line, once correctly and once as "Hardcoded OpenAI API
key", because the OpenAI pattern had no exclusion in front of 24 free-form
characters.

**Third: test conventions from outside the JavaScript world.** `_test.go`,
`testdata/`, `test_*.py` and `conftest.py` were in neither of the two
non-production path definitions (secrets.ts's and paths.ts's — which had
drifted identically, the cost of one idea living in two places), so 187 of
gitleaks' own fixture keys were criticals while the identical string in a
`.test.ts` would have been low. Both lists know them now. And the RLS scanner
never placed findings by path at all, though community, logic and agent all
do: supabase/splinter's `test/sql/` lint fixtures — SQL whose *job* is to
contain the defect — carried 18 criticals and a HOLD verdict; they are low
with a stated reason now, and splinter scans CLEAR. `migrations/` remains
deliberately absent from the path classes: migrations are the production
schema.

**Verification:** 252 → 274 tests; 18 of the 20 behavioural tests fail against
the pre-fix build, and the two that pass are the keep-cases each fix had to
preserve (VG010 on a bare interpolated identifier, VG001 on an opaque value
under a credential name). Before/after over the same eleven repositories:
2,159 → 2,067 findings, criticals 401 → 151, **zero findings added**, and
every removal read: −24 VG123 (each a duplicate of a VG010 on the same line,
which stays), −28 VG010, −13 VG001, −10 VG062, −4 VG154, −4 VG060, with 187
CTS030 and 18 splinter RLS findings demoted to low on test paths. splinter
went HOLD → CLEAR, dep-hallucinator HOLD → CONDITIONAL; what stays is real or
honestly undecidable — gitleaks' `cmd/generate` keys are realistic by
construction, and app C's one remaining VG010 interpolates variables whose
QBQL markers the match cannot see, the bare-identifier line again. Self-scan
🟢 on the same five lows, 68 files. Not released: the work sits on
`audit-2026-10-21`, stacked on the unreleased `audit-2026-10-13`; one 0.13.14
release ships both.

**The 2026-10-28 full audit went where the last one said it had not looked —
the ~180 untriaged corpus `high` findings and `report.ts` — and the worst thing
it found was a guarded rule standing beside an unguarded copy of itself.**
VG408 ("Unsafe innerHTML Usage") matches `dangerouslySetInnerHTML={{ __html:`;
VG012 ("XSS via innerHTML") matches `innerHTML` followed by `=` or `:`, and
`dangerouslySetInnerHTML` *ends* in `InnerHTML`. So every VG408 match is a
VG012 match at the same position — 15 of 15 across the seven dogfooding repos,
and by construction, since VG408 requires a `{` after the `=`, which is exactly
what VG012's `(?!['"]<)` lookahead lets through. The 2026-10-13 audit spent a
whole pass teaching VG012 the difference between an HTML sink and a `<style>`
element's CSS text, an all-literal expression and a value already through an
escaper. VG408 carried no guard, so it reported all of it again under a
different id: **eight `<style dangerouslySetInnerHTML={{ __html: css }} />` on
app C and shadcn's own `chart.tsx` on app B — the exact findings that
audit cleared** — plus three `sanitizeJsonLd(…)` calls and three lines where it
only repeated what VG012 had already said. Fourteen findings, not one of them a
true positive VG012 does not already report. A guard beside an unguarded copy
of itself does nothing, and nothing in the build said so; it is superseded now,
the third instance of that shape after VG999→CTS081 and VG123→VG010.

**Then four rules whose name describes a problem their pattern cannot see** —
the VG1008 gap again, in four more places. VG120 is titled "SSRF via
User-Controlled URL" and its description says "user-controlled input is passed
directly to fetch()", but what it matches is `fetch(` plus any bare identifier.
That made `export default { fetch(request, env, ctx) { … } }` — the Cloudflare
Workers entry point, the most common shape there is — a high-severity SSRF
finding on a *method definition*, and the delegation one line below it too; a
three-argument `fetch` is never WHATWG `fetch`, which takes two. It reported
app E's `fetchNoOpenRedirect`, which calls `assertFetchableImageUrl`, sets
`redirect: 'manual'`, bounds the chain at three hops and re-validates every
`Location` — code that implements what the rule's own `fix` text asks for. And
it reported a URL built on an origin no caller can move: the pattern already
refuses `fetch("https://…")` written inline, and one `const` in between defeats
it, which is how it is normally written (`const endpoint =
"https://…/api/run"`, or `` `${base}/v3/company/${realmId}/query` `` over a
literal base). The origin is resolved up to four assignments back now, through
ternaries and concatenations, crediting a literal or env-derived scheme+host —
**and the host specifically, not the scheme**, which is the line that matters:
`https://${shop}/admin/api/…` where `shop` is a column from a database row
stays reported, and in `run-saved-query.ts` line 133 clears while line 167, six
lines of near-identical code away, does not. VG1021 ("AI Tool Schema Enum Built
From User Input") fired seven times on `case "enum": return "≡";` — a switch
over a JSON-Schema type name picking an icon, where the `"enum":` is a case
label and the lowercase identifier the pattern wants is the keyword `return`.
VG964 asked six Next.js **route handlers** to `import 'server-only'`; a
`route.ts` cannot be imported by a client component, which is the entire hazard
that rule exists for, so the import would guard nothing — the seventh finding,
a shared `src/lib/session.js` that really is importable from both sides, stays.
VG1006 ("Supabase select('*') Exposes All Columns") reported eight
`select('*', { count: 'exact', head: true })` — Supabase's documented way to
count rows, which returns **no rows at all**; the pattern stops at the `'*'`
and never reads the second argument. The eight real `select('*')` fetches
beside them are untouched.

**The renderers dropped findings they were handed, and told GitHub a run had
succeeded when it had not.** `renderMarkdown` partitioned findings into
critical|high and medium|low by naming the severities, so an `info` finding —
the Supabase anon key, asked for with `--min-severity info` — appeared in
neither table while the "lower-severity findings" count said one fewer than it
had; `renderFixPrompt` dropped them outright. Both are partitioned by what is
*not* blocking now, so a renderer can rank a finding last but cannot lose one.
Worse, the SARIF had no `invocations` block at all: an incomplete scan uploaded
to code scanning as an ordinary successful analysis, showing what was found and
nothing about what was never read — and with `allow-incomplete` or
`fail-on: none` the job is green too, so this was the last surface that could
have said so. It carries `executionSuccessful` and a notification per reason
now. And the Markdown had no size bound while the Action posts it as a PR
comment: GitHub refuses a body over 65,536 characters with a 422, which at
~125 characters a row is about 535 findings — a number the 155-repo corpus
reached twice (603 and 732) off nothing stranger than a large lockfile matched
against OSV. The 422 landed in `|| echo "::warning::Could not post… (does the
token have pull-requests: write?)"`, so the one surface a reviewer reads showed
nothing and blamed the wrong cause. It bisects down to a row count that fits
and says how many are not shown, keeping the heading, the counts and the
incomplete warning always.

**Three of this audit's own fixes were wrong first, and the corpus caught all
three** — worth recording, because each was an over-credit, the direction that
hides real findings rather than adding noise. The Workers-handler check asked
whether a `) {` followed within 120 characters, which an ordinary
`if (!response.ok) {` on the next line satisfies — that cleared an app B
edge function's `fetch(imageUrl)` on a value straight out of `searchParams`.
The arity check counted arguments with `[^(),]{1,40},` twice, and a character
class does not stop at an object literal, so `fetch(url, { ...opts, signal })`
read as three arguments — app G's `fetchTimeout`, on a bare parameter. Both
are read off the matching close paren now. And the forward lookup for a
module-level const declared below its use was unanchored, so a `const url =
new URL(request.url)` in a later function vouched for an earlier function's
`fetch(url)`; it is `^`-anchored to column 0. The first version of the origin
resolver also credited `` `https://${host}/path` `` on the literal `https://`
prefix alone, which would have hidden exactly the database-row host above. All
four are pinned by keep-case tests.

**Verification:** 274 → 299 tests; **15 of the 25 new ones fail against the
pre-fix build, and all 10 that pass are keep-cases** — the true positives each
fix had to preserve, three of them pinning the over-credits above. Before/after
over seven real repositories (app C, app F, app E, app A,
app D, app B, app G), 1,638 files, run back-to-back on the same
checkouts: **452 → 385 findings, criticals 9 → 9, highs 194 → 148, zero
findings added**, scan times unchanged (−31 VG120, −15 VG408, −8 VG1006,
−7 VG1021, −6 VG964). **Every removal was read**, and what stays is real or
honestly undecidable: app C's `downloadAndParseJSONL(url)` and app E's
LinkedIn `uploadUrl` take a URL from an external API's response, app F's
bridge follows a `Location` header to an arbitrary host and writes the result
into its own install directory, and the database-row host stays critical to the
rule's purpose. No verdict changed on any repo — these were noise, not
verdict-flipping bugs, which is the honest summary. Self-scan 🟢 on the same
five lows, 68 files — after the first build added a sixth: the tool reported
**this audit's own new code**, a `[\w-]+(?:\.[\w-]+)+` hostname pattern, as
VG153 ReDoS. It was bounded in practice (it only ever sees ≤400 characters) but
rewritten without the nesting rather than suppressed, since running the vendored
patterns through a linear matcher is the thing 0.13.13 exists for. The
identifiers this audit interpolates into dynamically built patterns are also
re-checked against `^[A-Za-z_$][\w$]*$` at the point of use rather than trusting
every caller. One live-corpus lesson: a first before/after showed "+1 finding"
that turned out to be `app E's invariants test` being **edited by
another session while the scan ran** (mtime four minutes old, a VG153 line
moving 5434 → 5443 → 5540), which is why the final sweep was run with both
builds back-to-back. Not released: the work sits on top of `audit-2026-10-21`,
itself stacked on the unreleased `audit-2026-10-13`; one 0.13.14 ships all
three.

**0.13.14 ships all three audits (2026-10-29).** `main` fast-forwarded onto
`audit-2026-10-28` — six commits, 22 files, +2,853/−54 — so the 2026-10-13,
2026-10-21 and 2026-10-28 audits all go out under one version instead of
accumulating further; the three audit branches were ancestors of the tip, so
nothing had to be merged by hand. Bumped `package.json`, both root `version`
fields in `package-lock.json`, and the six doc literals the pin check asserts.
One version literal that the check deliberately *does not* match was stale
anyway — README prose reading "so `@v0.13.13` runs ClearToShip 0.13.13" as a
generic illustration of ref pinning — and it is version-free now (`@vX.Y.Z`)
rather than bumped, which is the drift the check exists to catch, one line
outside its reach.

**The whole release gate was run locally before the tag, not just at the end.**
Version pins 6/6 at v0.13.14; `npm ci` 0 vulnerabilities; **299 tests pass, 0
fail, and — run file by file — 0 skipped in all 17 files**, which is the check
worth naming here, because three network-gated tests once skipped silently on
this machine for months; the three new audit files contribute 61 of the 299
(audit-coverage 14, audit-oct21 22, audit-oct28 25). Self-scan run with CI's
exact argument list, online and without `--allow-incomplete`: **exit 0, 🟢 CLEAR
TO SHIP, 68 files, the same 5 low-priority notes**, reaching OSV.dev (12
resolved versions) and npm (12 packages), so it was complete rather than exit-3
incomplete. All three release assets built and all four of `release.yml`'s
pre-signing assertions reproduced by hand: the bundle reports `0.13.14`, it
carries its Apache licence text, `cleartoship-standalone.tgz` ships
`package/LICENSES/`, and `cleartoship-0.13.14.tgz` exists. Also checked a
stale-file trap that the workflow's `cp standalone/cleartoship.mjs` would not
have caught on its own: `bundle.mjs` writes `bin/cleartoship.mjs` and copies it
up (line 121), and the two hashes are identical, so the bare file cannot be a
leftover from an earlier build.

**Shipped and verified, 2026-10-29 09:15 UTC.** `v0.13.14` is published,
not draft, with all three assets at the byte sizes the local build produced
(428,670 / 557,032 / 2,377,500). All four rows of the release skill's table
were checked rather than read off a green run, and two of them independently:
`gh release view` lists the assets; the downloaded bundle runs and reports
`0.13.14`; `gh attestation verify` exits 0 and its predicate names
`.github/workflows/release.yml` at `refs/tags/v0.13.14` with source digest
`cfef22a`, so the signature is tied to this workflow and this tag rather than
merely existing; `curl https://cleartoship.app/cleartoship.mjs | shasum -a 256`
is `0c4c2ad…871c`, which is the release asset's hash, and `deploy-site.yml`'s
own post-deploy comparison reported the same sha256 from the runner. The Worker
moved to version `b5f53e42-4293-495b-a8f1-6d81424f6dd5`, confirmed by the
workflow's `wrangler deployments list` read-back rather than by the deploy step
exiting 0, and the live footer pill reads `v0.13.14`. **The release bundle is
byte-identical to the one built here** — same `0c4c2ad…871c` — so the tag
reproduced the local build exactly. And it was run, not just version-checked:
the downloaded bundle scans this repo to the same 🟢, same 68 files, same 5
low-priority notes, same 402 community rules.

**One coordination note worth keeping.** A second session was working in this
repo at the same time and committed the version bump out from under this one —
`e597239`, at 05:08:47 local, while the self-scan was still running. Its
content was byte-for-byte the working tree this session had already gated
(including the version-free `@vX.Y.Z` README line), and its message is
accurate, so it was kept rather than rewritten; this session's own commit was
reworded, since it then held only `TODO.md` while still claiming the bump. The
check that caught it was reading `git status` after `git add -A` and seeing one
file where seven were expected — not something a test would have failed on.
Worth remembering with the audit's other concurrency surprise: the same
overlap produced the phantom "+1 finding" from a file edited mid-scan.

**2026-11-12 — `VG530` was fired by checksum verification, and the cause was two
defects in one regex.** Reported by the portfolio auditor against a build script
that does the *opposite* of pipe-to-shell: it downloads to a file with `curl -o`,
checks a SHA-256 against a hardcoded digest, and only then unpacks — which is
exactly what the rule's own `fix` text recommends. The rule called it critical
anyway. Upstream's pattern is
`(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh|…)`, and it takes both of its
defects to produce the match: `[^|]*` is a negated class, so the span crosses
newlines and attaches the *next* line's pipe to this line's `curl`; and the
interpreter alternation carries no trailing `\b`, so `| shasum -a 256 -c -`
matches as `| sh`, ending mid-word. `| sha256sum -c` goes the same way, so the
rule fired on checksum verification in any shell script anywhere.

Fixed as a **corrected pattern** rather than a match guard, in a new
`PATTERN_FIXES` map beside `PATTERN_OVERRIDES` — and the distinction is the
point. `PATTERN_OVERRIDES` exists to bound backtracking and promises to match at
*exactly* upstream's positions, which `test/rules-audit.test.js` checks position
by position; a correction deliberately matches somewhere else, so it cannot live
there. A `MATCH_GUARDS` filter could not do this job either: a guard only rejects
a match the pattern already found, and by then `lastIndex` has moved past
everything that match swallowed — so a guard would have dropped the false
positive and taken any real `curl … | bash` inside that 1,277-character span
with it. `effectivePattern()` is now the one place that decides which pattern a
rule runs with, and a test holds the two maps disjoint.

The span fix alone was not enough, which is the part worth recording. On a
second script the unbounded span had run **32 lines**, from the word "curl"
inside `echo "🔨 Building … for curl installer"` down to a `| bash` far below,
and reported the finding on the echo; correcting the span merely *moved* that
finding to the real line — `echo "   curl -fsSL … | bash"`, a build script
printing an install command for a human to copy. Printing a command is not
running one, so that needs the guard after all: VG530's new `MATCH_GUARDS` entry
suppresses a match inside a string whose last preceding command is `echo`,
`printf` or `print`. Narrowly that, not "inside a string" — `bash -c "curl … |
bash"` and `ssh host "curl … | bash"` are strings too and both really do fetch
and run it, and both are pinned by tests.

**Verified by sweeping all 272 shell scripts on this machine with both
patterns.** Upstream matched in 12 files; the corrected one matches in 10, and
the three it stopped matching were all false (the checksum script, the 32-line
echo span, and a comment in a vendored reference repo that read "Libcurl is the
library for curl"). Nothing new matched anywhere — `fixed matched, upstream did
not: 0` — so the fix removed false positives without buying them with a missed
finding. End to end through the scanner the two genuine ones are still reported
critical (`curl -s …coverity_scan.sh | bash`, and golangci-lint's
`curl -sSfL … | sh -s --`, where `\b` has to accept `sh` followed by a space),
the eight `# curl … | bash` usage comments stay suppressed as comments, and both
original reports now scan to **0 VG530 findings**. Ten new tests, including the
two-line shape the reporter asked for verbatim plus `| sha256sum -c`; the suite
is 228 tests, 219 passing, the 9 failures all pre-existing `EPERM` on `.env`
fixtures from this session's sandbox (identical 9 on a stashed tree). Self-scan
unchanged: 🟢, 68 files, 5 low-priority notes.

**2026-11-12 — the portfolio auditor's 21 open findings on this repo, judged.**
Nobody had ever said whether they were real; the ledger could not tell an
undecided finding from an unseen one, so all 21 were being re-raised every run.
Five classes. **Seven were real and are fixed**: five dead `import type` names
(six, in fact — `secrets.ts` had both `Finding` and `ProjectContext` dead while
the finding named only the first), each verified to occur exactly once in its
file with no `export type` re-export, which is the check `HANDOFF.md` demands
before touching an unused-import finding; and one `SC2116`, the useless
`$(echo "$bad")` in `check-version-pins.sh:24`, replaced with `${bad}` after
running the failure branch against a two-mismatch fixture and getting
byte-identical output and the same exit 1. That one had already survived an
automated shellcheck safe-fix pass on the same file (`4f0b4fc`), so the
autofixer saw it and left it. The `unpushed-commits` finding was accurate and is
resolved: those five were the automated safe-fix commits, each of which said in
its own message that it was *not* verified against this app's tests, and they
went out with the VG530 fix after the suite had been run over all of them
together. All three went back as **re-check requests** rather than as `fixed`
claims, which is what that ledger accepts — a self-reported fix is refused there
by design, and it once recorded two live critical secrets as fixed because the
file had merely been gitignored.

`VG1070` (four `npm ci` steps with no `--ignore-scripts` / `--expect-provenance`)
is **accurate and waived, not dismissed**. What a dependency's install script can
do is bounded by what it can reach, and both workflows holding a credential
already keep it away from `npm ci` on purpose: `release.yml` splits into a build
job with a read-only token and a publish job that never checks out repository
code, and `deploy-site.yml` keeps the Cloudflare token out of job-level env for
the same stated reason. The flag is still worth adding and is below — but it is
not the one-liner the finding implies, because `esbuild`'s platform binary
arrives through an install script and `npm run bundle` has to be proven to still
work first. Shipping a release that cannot bundle is worse than the risk it
closes.

**The `over-500-lines` class is the one where reading the rule changed the
answer.** Ten files, cited as `Rule 26 step 6`, and the citation is exactly
right — step 6 *is* "a check lists source files over 500 lines and fails on any
new one, and files already over the line go on an allowlist with their current
size as a ceiling". So the findings are the first half of a rule this repo has
only half of, and the remedy is the ratchet, not ten splits: step 1 says files
are split by responsibility and the line count is only the smoke alarm, and nine
of the ten are one responsibility each (one scanner per file, one report
renderer, one file walk, one gitignore matcher) with none of step 1's triggers
firing. The row was **split**, because the tenth is real on step 1's own terms:
`community.ts` is 2,973 lines holding two unrelated jobs, and about 1,400 of
them are a general-purpose regex engine — pattern parser, compiler, and a
backtracking matcher that memoises failed `(state, position)` pairs — which
knows nothing about security rules and has its own narrow surface
(`matcherFor`, `linearInIrregexp`, `LinearMatcher`) already covered by its own
test file. Both halves went back as `open` with their reasons rather than
`waived`: waiving records acceptance, and neither is accepted. Both are below.

The judgement trail is `AUDIT-REPLY.json`, committed. `AUDIT-BRIEF.md` is
gitignored and must stay that way — it lists the file and line of every unfixed
finding here, and **this repo is public**, which makes it a map worth more to
someone hostile than the findings are. The auditor's own notices get the same
treatment for a different reason: they quote other, private apps by name, which
the rule at the top of `CLAUDE.md` forbids writing down here at all. The auditor
had this backwards — it warned that the brief needed gitignoring *because this
repo is private*. It is not.

**2026-11-12 — Rule 26 step 6 is now built, and the ratchet is the point.**
`scripts/check-file-sizes.sh` plus a checked-in ceiling table
(`scripts/file-size-ceilings.txt`), wired into `ci.yml` as its own
`file-sizes` job. It fails on two things: a tracked source file crossing 500
lines that is not on the allowlist, and an allowlisted file growing past the
size it was pinned at. Thirteen files are pinned — the ten `src/` ones the
auditor found, plus `test/scan.test.js` (1,424), `test/audit-core.test.js`
(509) and `site/public/index.html` (520), which the auditor had also reported
and which were waived rather than measured. `community.ts` went on the list at
**3,049**, not the 2,968 recorded a few paragraphs above: the VG530 fix added
85 lines, which is exactly the creep this gate exists to catch.

All four behaviours were proven rather than assumed, by making the check fail
on purpose: a new 501-line file errors and exits 1; appending 20 lines to
`report.ts` errors with `grew to 591 lines, past its ceiling of 571` and exits
1; cutting `report.ts` to 520 emits a `::notice::` asking for the ceiling to be
tightened and still exits 0; and a row for a file that does not exist emits a
notice to drop it. The last two are what keeps the list from rotting — good
news must not turn the gate red, which is the always-red-gate failure mode
another app in this portfolio pinned its dependency-audit gate at `critical` to
avoid, but it must not be silent either.

Scope is the git index, so a gitignored file cannot fail the gate. That is
deliberate and it resolves a disagreement with the auditor: it had reported
`marketing.html` (588 lines, gitignored) and 27 oxlint/size/deps findings
inside `standalone/` (a 2.3MB generated esbuild bundle, also gitignored) as
open findings against this app. Neither is hand-written and neither ships from
this tree. `src/vendor/` is excluded for a different reason — it is a faithful
copy of upstream and re-vendoring is a straight overwrite, so splitting it is
not an available move — and `test/fixtures/` because its shape is dictated by
what the rules must detect. A new job was added rather than a step inside
`version-consistency`, because that job's name is a status check and renaming
it would quietly break any branch protection requiring it. `actionlint` passes;
the self-scan over `scripts/` and `.github/` is clear; the suite is unchanged
at 228 tests.

**2026-11-12 — `VG1070` is closed for real, and the plan for it was wrong in
two places.** All four `npm ci` steps now carry `--ignore-scripts`
(`ci.yml:32`, `ci.yml:46`, `deploy-site.yml:47`, `release.yml:60`), so the
finding that was `waived` last week is now `fixed`: a self-scan of `.github`
returns **0** `VG1070` findings, and the whole-repo self-scan dropped from five
low notes to one.

The entry that planned this said `--expect-provenance` was "the cheap half" and
should go first. **There is no such npm flag.** `npm config get
expect-provenance` returns `undefined`, it appears nowhere in `npm help ci`, and
npm accepts it silently and exits 0 — so shipping it would have been a flag that
looks like supply-chain hardening and verifies nothing, which is worse than not
having it. The mechanism that does exist is `npm audit signatures`, now its own
`supply-chain` job: measured here, **29 of 29 packages have verified registry
signatures and 16 carry attestations**. It reaches `registry.npmjs.org` and
Sigstore's TUF root, so a Sigstore outage fails that job — the same trade the
self-scan already makes with npm and OSV, and the comment says to re-run rather
than delete the step.

The entry was also wrong about the risk: it said `esbuild`'s platform binary
comes through an install script and that the bundle had to be proven first.
Proven, and the premise no longer holds — esbuild 0.28 ships
`@esbuild/darwin-x64` as an *optional dependency*, not a postinstall download.
A clean `git archive` of HEAD with `npm ci --ignore-scripts` ran `npm run build`
and `npm run bundle` to a 2,324 KB standalone bundle, and the suite there passed
identically. `deploy-site.yml` was the one worth being careful with, since
breaking it stops the site updating: `wrangler` 4.135.0 installs and reports its
version under `--ignore-scripts`, with `workerd-darwin-64` arriving the same
optional-dependency way.

Two smaller things fixed alongside, both in CI's own output rather than in what
ships. `check-version-pins.sh` built its `::error::` annotation from a
newline-separated list, and GitHub renders only the *first* line of an
annotation — so with three wrong versions in the docs it showed
`docs name v0.7.1` and silently dropped the other two *and* the "but
package.json declares" clause, the half of the sentence saying what the right
answer is. Reproduced on a fixture before the fix and after: it is now one line
naming all three. And `deploy-site.yml`'s third retry loop named a counter it
never read, which tripped `SC2034` on every `actionlint` run; renamed to `_`,
so `actionlint` is now clean across all four workflows and a real warning will
not be buried under a known one. The other two loops do read their counter and
were left alone.

**2026-11-12 — a live-route XSS was being reported at `low`, and the item that found it was
pointing the wrong way.** The open item above proposed wiring `adjustForPath` into the four
scanners that skip it (`server-actions.ts`, `secrets.ts`, `dependencies.ts`,
`auth-helpers.ts`). Taking it through the calibration bar killed the idea and surfaced a real
defect underneath it.

`pathClass` classified any path containing a `docs/`, `examples?/`, `demo/`, `samples?/` or
`stories/` directory as `non-production`, which forces the severity to `low`. In Next.js those
are **route segments**: `app/docs/page.tsx` is the page served at `/docs`. Measured on a
two-file project with the identical `dangerouslySetInnerHTML` sink in each file:
`app/billing/page.tsx` reported `VG012` at **high**, `app/docs/page.tsx` reported it at **low**,
with the note *"Path looks like tests, fixtures or docs, so the severity is reduced."* Same for
an unauthenticated destructive Server Action: `critical` in `app/billing/`, and it would have
dropped to `low` in `app/docs/` the moment `server-actions.ts` started calling the helper. That
is the worst failure this scanner has available — not a false alarm someone argues with, but a
real one they never see, carrying a sentence that explains why it was quiet.

So the directory markers are split rather than extended. `NON_PRODUCTION_STRONG` keeps the ones
that mean the same thing anywhere — the `tests?`/`specs?`/`e2e`/`fixtures?`/`mocks?` family with
its affixes, `__tests__`, `cypress`, `playwright`, `testdata`, Go's `_test.go` and `testdata/`,
pytest's `test_*.py`/`conftest.py`, and the `.test.`/`.spec.`/`.stories.`/`.fixture.` **file**
suffixes. `NON_PRODUCTION_WEAK` holds the ambiguous directory names, and a weak marker loses to
`ROUTE_ROOT` (`^(src/)?(app|pages)/`). A `*.stories.tsx` file stays non-production wherever it
sits, because the file suffix is reliable even where the directory name is not; `demo-billing/`
was already production and still is.

`test/path-class-route-roots.test.js`, 6 tests. It was run against the pre-fix build first and
**3 of the 6 fail there**, which is the only evidence that a regression test is testing
anything; the other 3 are the regression guards for behaviour that had to stay put. It asserts
values rather than the absence of the worst case — `adjustForPath('critical',
'app/docs/actions.ts').severity === 'critical'` and an empty note, not `notEqual(..., 'low')` —
because this repo already lost a year to a CVSS assertion that only ruled out `low`. The
existing `pathClass` block in `test/scan.test.js` passes untouched, including
`app/e2e-tests/login.ts`, `src/app/api/document-samples/route.ts` and
`src/features/demo-billing/index.ts`. Suite 234 tests, self-scan unchanged at one low note.

One thing this did not change and is worth stating: the repo's own
`test/fixtures/vulnerable-app/` holds a full deliberately-vulnerable `app/` tree, and it still
classifies `non-production` — the strong marker matches first, before the route root is ever
consulted. A fixture tree is not anybody's route.

**2026-11-12 — the scanner was certifying a no-op, and a rule that cannot fire on its own
subject is now withheld.** Two classes came back from the portfolio, each reported by the
session that owns the code it fired on, each having read the file.

`VG1070` is the serious one. Upstream's pattern accepts **two** flags as satisfying it,
`--expect-provenance` and `--ignore-scripts`, and its `fix` text recommends the first one
first. There is no `--expect-provenance` flag: `npm config get expect-provenance` returns
`undefined`, it is absent from `npm help ci`, and npm takes the unknown flag silently and exits
0 (npm 10.9.2). Measured on a two-job workflow before the fix: `npm ci --expect-provenance`
produced **no finding** and the bare `npm ci` produced one. So an app following this tool's own
advice added a string that hardens nothing, the rule went quiet, and the green check was the
harm — worse than saying nothing. Reported independently by two apps here on the same day with
the same evidence, which is what settled it rather than one report.

Fixed in both halves. `PATTERN_FIXES.VG1070` drops the fake flag from the lookahead, so only
`--ignore-scripts` silences the rule; both lines of that workflow are now reported. And a new
mechanism, `TEXT_FIXES` in `src/scanners/community-text.ts`, corrects a vendored rule's
*words* — name, description, `fix`, `fixCode` — because a prose defect and a pattern defect are
different bugs: one reports the wrong line, the other sends the reader somewhere useless. The
corrected text names `--ignore-scripts`, points at `npm audit signatures` as the separate
provenance check (a step, not a flag), and says outright that `--expect-provenance` is not a
flag rather than quietly dropping it, since an app may already have it in CI. The scanner's own
note now states the count, so a reader comparing a finding against upstream GuardVibe's text is
told the wording is ours.

`VG146` is withheld rather than guarded, which is the more honest of the two. It is "Unquoted
.env Value with Special Characters" declared `languages: ["shell"]`, and `languagesFor` returns
`shell` only for `.sh`/`.bash` — so a `.env` file never reaches this scanner and **the rule
cannot fire on its own subject**. What it matched was `REPO=$(cd "$(dirname "$0")/../.." && pwd)`
and `BASE=${FOP_BASE:-HEAD}` in shell scripts: command substitution and parameter expansion,
where quoting them as the fix instructs would break the script. Read the file it fired on before
judging, per the calibration bar — `#!/bin/sh` on line 1, the flagged lines exactly as reported.
It fires on nearly every one of a 272-script corpus that sets a variable. A `MATCH_GUARDS` entry
was written first and then deleted: with `.env` unreachable, a guard would leave a rule that
looks active, can never match, and inflates the match-guard count. Withholding states it.
Reviving it means giving dotenv files a language token of their own, not feeding them to the
shell ruleset.

**The 500-line ratchet caught its own author twice**, which is the first evidence it does
anything. `community.ts` went to 3,153 and the gate failed; the answer was not to raise the
ceiling on its third day but to move the calibration out, so `community-text.ts` (71 lines) and
`community-patterns.ts` (119 lines, `PATTERN_FIXES` + `PATTERN_OVERRIDES` + `effectivePattern`,
re-exported so existing imports keep working) now hold it and `community.ts` is **2,968** — 81
lines below where this change started. It caught a second edit after the ceiling was tightened
mid-change, which is the lesson for using it: set the ceiling once, at the end.

Tests: `test/vg1070-and-vg146.test.js`, 6 tests, **4 of which fail against the pre-fix build**.
They assert line numbers rather than counts (a count passes whichever two lines it picked) and
assert the corrected text names the real remedy. Suite 240 tests.

**One pre-existing flake found and not fixed:** `test/redos-overrides.test.js`'s
"the audit-named rules grow linearly" asserts on wall-clock time and fails intermittently —
`VG102: 0.0 ms at 32 KB, 24.0 ms at 128 KB`, where the small measurement rounding to zero makes
the ratio meaningless. It appeared in 2 of 5 runs, and in the **unchanged** code as well as the
changed, confirmed by stashing. A timing assertion in a suite that is otherwise deterministic
teaches people to re-run on red, which is how a real failure gets waved through. It belongs in
`## Open` and is there now.

**2026-11-12 — the scanner was reading 7,454 files out of a virtualenv, and 98.6% of one app's
findings came from it.** Came out of a performance report: a 42-app portfolio sweep had gone
from a documented ~2m20s to **829s**, with one app accounting for 358s. The caller flagged it
without attributing it, which was right — and it turned out to be this scanner's.

`SKIP_DIRS` in `src/utils/files.ts` names `.venv` and `venv`, matched by exact name. That app
had a `.venv-convert/` beside its ordinary `.venv/`. `.py` is in `SCAN_EXTS`, so every file in
it was opened and run through the Python community rules. Measured directly on that app, before
and after, rather than reasoned about:

| | wall | findings | inside the virtualenv |
|---|---|---|---|
| before | 86s | 645 | **636** |
| after | 5s | 9 | 0 |

**17x faster, and 636 findings that were all in code nobody there wrote.** The caller
independently remembered "636 findings out of a `.venv-convert/` tree" from an earlier run,
which is the same number from the other side.

The fix is a `pyvenv.cfg` test on each directory before descending, because PEP 405 requires
that file: a directory is a virtualenv exactly when it has one. That matters for the bar
`SKIP_DIRS` has to meet — everything on it must be regenerable in *any* repository, not just
one of ours, because `site` and `_reference` were once on that list and every user with a
`site/` directory had the whole subtree reported clean without a file being opened. A name test
cannot do this job: `env/` is too ambiguous to skip blind, and that is the same conclusion this
folder's own `CLAUDE.md` records for the auditor's classifier, reached there first.

`test/virtualenv-skip.test.js`, 3 tests, **2 of which fail against the pre-fix build**. The
third is the guard that must pass both ways: `env/` and `environment/` with no `pyvenv.cfg` are
somebody's source and are still read. The skip is also asserted to be *named* in
`skippedDirs`, because "no findings" must never be indistinguishable from "nothing was read".

**Followed up the next day, and the scope of the fix is narrower than it first looked — worth
recording because the correction is the useful part.** A portfolio sweep for `pyvenv.cfg` outside
`.venv`/`venv` found **five** misnamed virtualenvs holding ~23,000 `.py` files between them, and
the obvious reading was that this fix saved all five. It does not. Measured by diffing the
scanner's own `fileCount` between the pre-fix and post-fix builds on each one:

| | files read, before → after | findings |
|---|---|---|
| the app measured above | 7,740 → 226 | 645 → 9 |
| the other four | unchanged (0 delta each) | unchanged |

Only one app was ever reading its virtualenv. Two of the other four have the directory
**gitignored**, and the walk already refuses to descend into an ignored directory — which is
where most of this scanner's saving has always come from. The remaining two are not git repos
and their venvs were still not read, with the counts merely moving between
`gitIgnoredCount` and `skippedDirs`. **A `.py` file count is not the same question as "was it
opened"**, and treating the two as interchangeable is how the five-app number appeared.

That makes the marker test *more* clearly right rather than less, which is the part to keep: the
four that cost nothing were covered **by luck of configuration**, not by anything structural.
Gitignore is a choice each repository makes; `pyvenv.cfg` is a fact about the directory. A repo
that forgets to ignore its venv, or has no git at all, gets the same 7,500-file read — and that
is the case a marker catches and a name never will.

One ceiling moved **up** for this: `files.ts` 591 → 615. A `pyvenv.cfg` test belongs in the file
whose job is file collection, and Rule 26 step 1 is explicit that files are split by
responsibility rather than by line count — a new file for one 6-line predicate would be the
worse mistake. `scripts/file-size-ceilings.txt` now carries a short log of upward moves and
their reasons, since that is the one direction the gate exists to resist. In the same day
`community.ts` went 3,049 → 2,968 by moving calibration out, so the ratchet is net tighter.

**2026-11-13 — `CTS070` called an upstream error payload a request body, and the fix was to
re-word it rather than drop it.** Reported through the auditor by the session that owns app B, on
a service-role read helper whose failure path is `const body = (await res.json().catch(() =>
({}))) as { code?: string; message?: string }` followed by `console.error(…, body)`. The rule's
`BODY_EXPR` is `/(?:^|\.)(body|rawBody|payload)$/`, and the leading `(?:^|\.)` means it matches a
*bare* local named `body` — so the finding went out with its central sentence, "whatever a caller
put in the request body — passwords, tokens, personal data", describing an object no caller ever
touched. That is the `VG1070` failure in a different costume: not a missed bug, but a true-looking
sentence that is false about the code it is printed next to.

Suppressing it would have been wrong, though, which is why this took a provenance check rather
than a narrower regex. PostgREST returns `details` and `hint` alongside `code` and `message`, and
`details` can quote the offending row; the `as { code, message }` cast narrows the *declared* type
without narrowing what arrives over the wire. So the body really is worth not dumping — the class
and the remedy were wrong, not the concern. It now reports at `low` as "Upstream response body
written to logs", and the fix text says to log `res.status` and `body.code` rather than "redact
the field", which was advice that did not apply.

The side is resolved from the binding chain, not from the identifier's name, because **the name is
the ambiguous part**: `await res.json()` and `await request.json()` are the same call shape, and
both results get called `body`. `bodySide()` walks `body` → `await res.json().catch(…)` → `res` →
`await fetch(…)`, which needs the `TSAsExpression`, the `await` and the `.catch()` all unwrapped
before the receiver is visible, and then takes `fetch` as the decisive signal rather than guessing
from `res` vs `req`. An unresolvable chain returns `'unknown'` and keeps the original wording, so
the fail-safe direction loses no detection; `meta.side` now carries `request`/`upstream`/`unknown`
so a consumer can filter on it. Six tests, five of which fail against the pre-fix build — the
sixth is the fail-safe guard, which must pass both ways by construction. On app B the single
real-world instance moved `medium`/"Request body" → `low`/"Upstream response body", and no other
`CTS070` in that app changed. Suite 243 → 249, the same 9 sandbox `.env` `EPERM` failures as
before; `logic.ts` 334 → 447, still unlisted and under the 500 ceiling.


**2026-11-13 — the ReDoS growth test was measuring the machine, not the matcher.**
`test/redos-overrides.test.js` asserted `b < 8 * a + 20` with `a` and `b` in milliseconds, and it
flaked in 2 runs out of 5 **against unchanged code** — proved by stashing the working tree and
watching it fail anyway. The mechanism: where the prefilter rejects early, `a` is a fraction of a
millisecond, so the bound collapses to roughly 20 ms and a single GC pause clears it. That is
worse than having no test, because a red run with no cause teaches you to re-run rather than to
look — the same lesson as a green push that is not a deploy, pointed the other way.

`LinearMatcher` now carries a `steps` counter, incremented once per executed instruction, so the
growth property is asserted on **work done** instead of elapsed time. Measured with
`REDOS_REPORT=1`: the worst growth across all 35 measurable (rule, shape) pairs is **4.001x for a
4x input** — linear to three digits, where quadratic would be 16x. So the bound is now `4.1 * a +
16`, which is both deterministic and far tighter than the 8x it replaces. Five consecutive runs,
no variation.

Two things this surfaced that are worth more than the fix. First, **25 of the 60 pairs execute
zero instructions**, because the prefilter or required-substring test rejects the input before the
program runs at all, and for `VG1070` that is true of every shape — so step counts say nothing
about prefilter cost, and the absolute 1-second wall-clock ceiling is kept as the only thing
covering it. It is a 1 s bound on single-digit-millisecond work, which is why it was never the
part that flaked. Second, the test now asserts the **measurable-pair count** itself: if a future
change let the prefilter swallow everything, all 35 step assertions would pass vacuously and the
test would report green while checking nothing. A vacuous assertion and a skipped test are the
same failure.

That last guard caught its own author immediately. The first draft set it to 16, measured with a
standalone re-implementation of the test's `fragments()` helper — which generates different
adversarial inputs, so the number was wrong by more than 2x and the test failed on its first run
with `35 of 60 pairs exercised the matcher, expected 16`. **Measure with the real harness, not a
replica of it.** `cost()` also went from best-of-three to a single timing, since its only
remaining job is a 1-second ceiling; that is roughly a third off the test's runtime.

**What the counter costs, and why the measurement does not deserve more confidence than this.**
It is one integer increment per executed instruction, in the hottest loop in the codebase, so it
was worth measuring rather than waving through. A/B on a 541-file app, three scans each:
`39.07 / 30.56 / 27.11 s` without it against `26.34 / 26.56 / 25.77 s` with it. The instrumented
build is *not* 1.3 s faster — nothing about adding an increment can speed a scan up. The
uninstrumented arm ran **first in both passes** and absorbed the cold-cache cost, which is visible
as the 39 → 30.6 → 27.1 slide inside that arm on its own. So the experiment was biased in the
change's favour and can only support an **upper bound**: no visible regression, the arms differing
by less than the run-order swing within one arm. That is the same cold-first-run artifact this file
records two entries above, in the correction sent to the auditor about a 6.2x portfolio speedup —
it showed up here in my own favour, which is the reason to discount it rather than bank it. A point
estimate would need alternating order with the first run of each arm discarded; it was not worth
another three minutes for an effect this far under the noise.

One ceiling moved up: `community.ts` 2,968 → 2,973, for the counter. Instrumentation for a class
belongs on that class, and the five lines cannot be moved anywhere that makes sense — the fourth
time this gate has caught its own author, and the second time the right answer was to raise the
number and say why rather than to move code.


**2026-11-13 — `CTS010` fired on a SQLite schema because its comments explained that it was
SQLite.** Reported through the auditor by the session that owns app B: six `CTS010` findings
("Public table with Row Level Security disabled", `critical`) on a Cloudflare **D1** schema. D1 is
SQLite — it has no row-level security and `ALTER TABLE … ENABLE ROW LEVEL SECURITY` is not a
statement it has — so **no edit to that file could ever have cleared the finding**. That is worse
than a false positive: a false positive wastes an afternoon, an unsatisfiable one teaches you the
scanner cannot be cleared.

The expected fix was to build dialect detection. Reading the code first showed it already exists:
`postgresSqlFiles()` judges every `.sql` file on its own and excludes the ones that are not
Postgres, with a documented bias toward *including* on doubt, because "dropping a Postgres file on
a guess is a clean report on unread code". The gap was narrower and funnier than a missing feature
— it judged the dialect from the **whole file, comments included**, so the schema read as Postgres
*because its comments explain that it is not*:

```
--      `has_role(auth.uid(),'admin')`. There is no auth.uid() here. Their
--   4. No gen_random_uuid(). The Worker supplies ids with crypto.randomUUID().
```

The first makes `PG_RLS_IDIOMS` match on `auth.uid(`, which skips the exclusion branch outright;
the second would have vetoed the SQLite reading anyway through `POSTGRES_ONLY`. Both are prose
about what the file deliberately does **not** do. Same class as the VG530 false positive and the
`-main` directory tell: a pattern reading a comment as code. `spans.ts` already carried that
lesson in its own doc comment — "every comment in them read as code and a vendored rule fired on a
sentence" — about this repo's own source.

So the fix is one line of behaviour: the dialect test now runs on `blankSqlComments(src)` rather
than `src`. That helper went into `utils/sql.ts`, beside `readBalanced`, using the existing
`lexSpans` lexer rather than a second comment scanner — which matters for the case a hand-rolled
stripper gets wrong, a `--` inside a string literal, asserted directly. **`rls.ts` grew by zero
lines**, because folding the import into the existing `utils/sql.js` line avoided raising a third
ceiling in one day; the file sits exactly at its 1,249 ceiling and that was the right forcing
function rather than an obstacle.

Measured: app B goes from **6 `CTS010` findings to 0**, and the D1 schema now produces no finding
of any kind, while that app's genuine `supabase/migrations/*.sql` findings (`CTS050`, `CTS052`,
`CTS015`) all still fire. Four tests; the regression one fails against the pre-fix build with
`expected no findings on the D1 schema, got CTS010`, and the two "nothing lost" tests — a real
Postgres table with RLS off still `critical`, and Postgres-only syntax in code still winning over
an RLS idiom that appears only in prose — pass both ways by design. Suite 249 → 253.

**What was deliberately not done, and why it is not a dodge.** The reported remedy was "detect the
dialect and skip or re-word". Re-wording was the wrong half: `CTS010` is a PostgreSQL/Supabase RLS
rule, and on a D1 schema there is no RLS to report on, so exclusion is the designed behaviour
rather than a suppression. The genuine concern the reporting session raised — after their cutover
the Worker is the only line, and nothing checks that it filters by caller — is real and is **not
this rule's subject**. It would need a rule about Worker-layer authorization, which does not exist.
That is a candidate, recorded in `## Open`, and it deliberately does not point at the
authorization-map artifact that app happens to keep: `/Users/Shared/CLAUDE.md` forbids shaping this
tool's rule set around this portfolio, and a rule satisfied by one app's filename is exactly that.
Dialect-correctness, by contrast, is general — telling any D1 user to enable RLS is wrong for every
D1 user.


**2026-11-13 — `CTS015` and `CTS052` judged a function from one migration instead of from the
series.** Reported through the auditor by the session that owns app B as two symptoms of one
defect. A Postgres function's current definition is the **last** one in timestamp order across the
whole migrations directory, and a later `DROP FUNCTION` means there is no current definition at
all. `rls.ts` already replays migrations in order and already models `DROP POLICY` that way — but
it pushed the *function* findings as it met each statement, so a definition a later migration
replaced or dropped still reported. The finding's subject did not exist once the series finished
replaying: `CTS052` on a zero-argument `get_admin_user_ids()` with an anon grant that a later
migration deletes, and `CTS015` on the migration that pins `search_path` on that same zero-argument
function, one file before it is dropped. Dead text in both cases.

The fix is a `FunctionLedger` in a new `src/scanners/sql-functions.ts`: declarations, drops,
grants and revokes accumulate during the replay, and **nothing is reported until the series has
finished**. `functionBodies` was already last-wins, which is why the policy-judgement side of the
scanner was always right and only these two emissions were wrong.

**Arity is load-bearing, not decoration, and the real file proves it.** The replacing migration
does `DROP FUNCTION IF EXISTS public.get_admin_user_ids();` — arity 0 — in the *same file* where it
creates `get_admin_user_ids(user_ids UUID[])` at arity 1 and grants `anon` EXECUTE on it. Keyed by
bare name, that `DROP` would have deleted the live function's finding too, turning a false positive
into a **false negative on a genuine issue**. Postgres identifies a function by name and argument
types; full type resolution does not pay for itself, because a `CREATE` carries names, types and
defaults while a `DROP` carries bare types, so matching them is guesswork precisely where guessing
wrong loses a finding. Arity separates the overloads that matter, and where it cannot — two
same-arity overloads with different argument text — the ledger **keeps** the finding rather than
dropping it, because keeping one that should have gone costs attention while dropping one that
should have stayed costs a vulnerability.

Measured on app B: `CTS015` goes to **0** (its subject is deleted), and `CTS052` goes from the dead
`20260419120000` file to **the surviving `20261109010000` one, where it is a true positive** — that
migration really does grant `anon` EXECUTE on a `SECURITY DEFINER` function, and I read the file to
confirm it rather than inferring. So this removed two dead findings and kept the live one, which is
the outcome that distinguishes resolution from suppression. Seven tests; five of the six
behavioural ones fail against the pre-fix build, and the sixth passes both ways by design, because
it asserts the direction where the series makes things *worse* (a pinned function replaced by an
unpinned one) — the old code caught that by accident and the new one catches it on purpose.

**What the findings now refuse to claim.** The surviving definition is what the *repository* says
and says nothing about what is deployed. The reporting session measured their production database
still answering the old wide zero-argument RPC for an anonymous caller **three days after** the
replacing migration was committed, because it had never been applied. So the text reads "after the
migration series replays" and "both the grant and the definition survive the migration series",
and a test asserts the findings do **not** contain "in your database", "currently deployed" or "is
live". A scanner that reads files may not claim evidence about a running system.

`rls.ts` ended up **1,257 → 1,243 lines**, below its old 1,249 ceiling, by moving the two statements
that *undo* ledger state into the module that owns the state — the split that was missing is
exactly why `DROP POLICY` was modelled and `DROP FUNCTION` never was. The gate emitted its
shrink notice and the ceiling was tightened to 1,243, so for once today the ratchet moved the right
way.


**2026-11-13 — the linear-time matcher moved out of `community.ts`.** Rule 26 step 7, the planned
refactor that had been sitting in `## Open` since the file passed 3,000 lines. `community.ts` went
**2,973 → 1,623** and the new `src/scanners/linear-regex.ts` is 1,383. The seam turned out to be
clean enough to cut in one pass: the engine occupied one contiguous block and shared exactly
**three names** with the rest of the file — `LinearMatcher`, `linearInIrregexp`, `matcherFor` —
re-exported from `community.ts` because the ReDoS and override tests import them from there. Zero
TypeScript errors on the first cut, which is the measurement that says the boundary was real and
not something imposed: the scanner decides *what to look for*, the engine decides *how to look*,
and nothing else crossed between them.

**Verified as a refactor, not as a change.** A test suite passing proves the tests still pass; it
does not prove the output is the same. So both builds scanned the same 541-file app and their
findings were hashed: **162 findings, SHA-256 `307d8591…` identical on both sides.** That is the
assertion a pure move deserves, and it is cheap — a sorted `id|severity|file|line|title` list
through `sha256`.

**The split tripped its own guard, exactly as predicted.** The gate failed with *"linear-regex.ts
is 1383 lines, over the 500-line limit, and is not on the allowlist"* — step 7 asks for the split,
step 6 fails on any new file over 500, and a giant cut in two lands two files over the line. That
tension was described to the rulebook session earlier the same day, with a prescription: each half
gets its own entry at its measured size in the same commit, with the reason logged, and the **sum
is not the thing guarded**, because a sum lets one half grow while the other shrinks and still
reports green. The gate's own error message already said the same thing. Applying it here: the sum
went 2,973 → 3,006, **+33 lines (1.1%)** of header and import, which is the price of the seam and
sits inside the 0.2–6.7% range measured on two earlier splits.

One limitation of the gate found while doing this, worth knowing rather than fixing: it reads the
**git index**, so a brand-new file is invisible until it is staged. That is deliberate — it is what
stops a gitignored local file failing the gate — but the side effect is that a local run on a fresh
untracked file reports "all allowlisted" and the failure only appears after `git add`. It did not
hide anything here, because the file was staged before the commit, and CI stages everything by
definition. Worth remembering before trusting a green local gate on new code.

## Open

- **New rule candidate: row-level authorization on a database that has no RLS.** Surfaced by the
  `CTS010` dialect fix above (2026-11-13). Once a SQLite/D1 schema is correctly excluded from the
  Postgres RLS scanner, nothing checks the thing that actually matters there: that the single
  application layer in front of the database filters every query by the caller's identity. On
  Postgres the engine can be made to enforce it and `CTS010`-`CTS019` check that it is; on D1 the
  engine cannot, so the guarantee lives entirely in code that no rule currently reads.
  Shape it would need: for each table reachable from a Worker, is there a query path that does not
  constrain rows by an authenticated subject. That is a dataflow question, not a pattern, which is
  why it is a candidate and not a quick win — and it is the honest reason the `CTS010` fix *removed*
  a finding without replacing it. **It must not be satisfiable by naming a documentation file.** One
  app in the portfolio keeps an authorization map and it would be trivial to let its presence clear
  the rule; `/Users/Shared/CLAUDE.md` forbids shaping this tool's rule set around this portfolio,
  and a check satisfied by a filename is a box to tick rather than a control.


- **The whole `critical` tier, walked: 233 findings, 2 real (0.9%).** Reported 2026-11-08 by the
  caller running the scanner over 42 projects, who decided every one with a written reason.
  `VG010` 113, `CTS001` 27, `VG014` 24, `CTS030` 19, `VG414` 10, `VG011` 6, `VG001` 34. **The two
  real findings were both `CTS030`** — a Supabase `service_role` key and a database password that
  had been committed and pushed, which is exactly the finding a scanner should exist to produce.
  So the instinct is right and the precision is not, and the one rule that earned its severity is
  the one resting on a **verifiable external fact** (is this file tracked? was it ever committed?)
  rather than on the shape of a line of code.

  Four more rules, each with the same cause as the two already reported below:

  - **`VG414` is labelled SSTI and is not finding SSTI.** Server-side template injection is when
    input becomes the template *source*. All ten findings were Jinja2 `| safe` applied to a
    *value* inside a static template file — which is an XSS question, a real one, but a different
    one. Seven of the ten passed through a custom filter that escapes every text segment before
    adding any markup; the rest were app-authored SVG constants, documentation strings, and a
    stylesheet read off disk (CSS cannot be HTML-escaped and still work). Re-labelling this
    would help more than re-tuning it.
  - **`VG011` "Command injection risk" fires on list-form `subprocess.run([...])`**, which is the
    *recommended* form — there is no shell to interpret anything. All six were literal argv,
    constant paths, or object attributes. Worth requiring `shell=True`, a `os.system`, or a
    string-form command before calling it command injection.
  - **`VG014` "Dynamic code execution" cannot see a test harness.** 21 of 24 were the standard
    way to unit-test a function with no module boundary: read the project's own source file and
    `new Function` / `vm.runInContext` / `eval` it. One more was a HuggingFace
    `from_pretrained()` weights load, which only executes code with `trust_remote_code=True`.
  - **`CTS001`'s own title says "appears public by design"**, and 14 of its 27 were `/login`,
    `/logout`, `/register`, `/forgot-password`, `/reset-password`, `/verify-email` — endpoints
    that *cannot* require a session. Five were public contact forms. Of the four read
    individually, one was a deprecated stub returning 410, one was gated by a one-time token
    plus IP rate limiting, one by Cloudflare Turnstile that fails closed, and one by a license
    key that is itself the credential. A rule that flags an auth endpoint for lacking auth needs
    a path-aware exception before anything else.

  **And one that is about this repo, not the rules: the scanner reports its own test corpus.**
  Scanning `cleartoship` itself produced 13+ findings inside `test/fixtures/vulnerable-app/` and
  `test/fixture-setup.js` — the deliberately insecure fixtures and fake secrets the suite needs
  in order to prove the rules fire. Four `CTS001`, seven `CTS030`, one `VG014`, one `VG010`. Every
  one is the scanner catching its own bait. A default exclusion for `test/fixtures/`, or a
  shipped ignore file, would fix it for this repo and for any user who vendors fixtures the same
  way — and it is the first thing a new user scanning a security tool's own repo would hit.

  **Re-measured 2026-11-12, and the diagnosis has changed — this is now a half-applied
  mechanism, not a missing one.** `src/utils/paths.ts` already does what the entry above asked
  for: `pathClass` returns `non-production` for `tests?|specs?|fixtures?|mocks?|__tests__|
  examples?|docs?|demo|samples?|testdata` and the Go/pytest spellings, and `adjustForPath` forces
  those to `low` with the reason stated in the finding rather than suppressing it — the demote,
  don't-exclude choice the entry below recommends. So the leverage item is built. What is not
  built is applying it everywhere: **`adjustForPath` is called by 4 scanners
  (`community.ts`, `rls.ts`, `logic.ts`, `agent-logic.ts`) and by none of `server-actions.ts`,
  `secrets.ts`, `dependencies.ts` or `auth-helpers.ts`.** A self-scan (`node dist/cli.js --json
  --offline .`) returns 203 findings, of which 187 are `low` and **all 16 that are not are inside
  `test/fixtures/vulnerable-app/`**: 8 critical (`CTS003`, `CTS001` x3, `CTS042`, `CTS033`,
  `CTS028`), 6 high (`CTS002` x2, `CTS043` x2, `CTS041`, `CTS046`), 2 medium (`CTS004`,
  `CTS044`). None of the 16 carries the path note, which is the tell: the adjustment never ran
  for them. Eleven distinct rules, and every one of them is owned by a scanner that skips the
  call. `CTS028` may be a deliberate exemption — the `paths.ts` doc comment says `CTS024` does
  its own ships-vs-dev-only separation for dependency CVEs — so that one needs a decision rather
  than a call added. The fix is a severity change in shipped output, so it goes through the
  calibration bar in the release skill rather than in passing.

  **Taken through that bar the same day, and the premise turned out to be backwards — see the
  narrative entry above.** Wiring `adjustForPath` into the remaining four scanners would have
  introduced a false negative worse than the noise it removed, because the demotion was already
  too aggressive: `pathClass` read `app/docs/`, `app/examples/`, `app/demo/` and `pages/docs/` as
  `non-production`, and in Next.js those are **routes**. Fixed in the other direction instead.
  What is still genuinely open here is the narrower question this started from — whether the four
  scanners should call `adjustForPath` at all now that the classifier is safe on route roots. The
  argument for it is consistency; the argument against is that a fixture tree is the only place
  it would change anything in this repo, and `test/fixtures/` is better served by the default
  exclusion discussed above than by demoting eleven rules one at a time. `CTS028` still needs a
  decision rather than a call added.


- **Two critical rules, 147 findings, 0 true positives — the pattern, not just the rules.**
  Reported 2026-11-08 by the same caller running the scanner over 42 projects. `VG010` (113,
  reported below) and `VG001` "Hardcoded credentials" (34) were both worked through finding by
  finding. Nothing in either was real. The two failures have the same shape, which is why this
  is one entry rather than two:

  **The rule matches the name of a thing, not the thing.** `VG001`'s clearest case is a map of
  credential *form fields* to DOM selectors — `sesAccessKey: '<a CSS selector>'` — in a file whose
  next line is the same strings as a selector list, and with no `AKIA`/`ASIA` anywhere in it. Also
  `api_key_name`, which holds the *name of which key to use*. `VG010` does the same thing with SQL,
  matching a `querySelectorAll('select, option, …')` argument.

  **Test fixtures are 26 of the 34.** A test that logs in needs a password in it; that is not an
  exposure. The sharpest example is in *this repo*: `test/audit-oct21.test.js:252` holds a fixture
  containing a fake `apiKey` so the scanner can be tested for detecting one — and it reports its
  own bait as a critical finding against itself.

  **The one change with the most leverage: know what a test path is.** `test/`, `tests/`,
  `__tests__/`, `*.test.*`, `test_*.py`, `*-test.*`. Not silence — a hardcoded credential in a
  test is worth `low`, or an `info` line saying how many were suppressed, because a real key does
  sometimes get pasted into a test. But `critical` is wrong, and at 26 of 34 it is most of the
  class. The same filter would help every rule of this family, not only `VG001`.

  **Second: require the match to be a value, not an identifier.** If the matched string is a
  variable or property *name* (`sesAccessKey`, `api_key_name`, `smtpHost`), the finding is about
  naming, not about a secret. Checking the right-hand side has a credential's shape — length,
  charset, a known prefix such as `AKIA`, `sk-`, `ghp_`, `eyJ` — would drop the rest of this class.

  For the record, the four findings that were *not* dismissed were accepted rather than denied:
  local demo-seed and screenshot-capture scripts that really do hardcode a dev password, waived on
  the condition that they stay local. So the rule's instinct is sound; its precision is not.

  The caveat from the entry below still applies: this is one portfolio, and a rule tuned for zero
  false negatives will reasonably accept false positives. The number worth weighing is that across
  147 consecutive critical findings a reviewer learned to skip the severity entirely.


- [ ] **Four findings reported from an outside caller's audit, 2026-10-28/29** (an outside app —
      MV3 Chrome extension + local Node bridge + a Cloudflare Worker — run as
      `node dist/cli.js --offline bridge extension d1`, 99 files, 2.7s, 47 findings:
      3 critical, 27 high, 3 medium, 14 low. **All 47 were checked by hand against the source
      and all 47 are false positives for that app**, which is the context for the first item):
      - **The XSS family is 19 of the 27 HIGHs, and they are all one correctly-escaped file.**
        `VG852` (9), `VG012` (8) and `VG121` (2) all land on the same six-file side panel, which
        has exactly one `escapeHtml` (escaping `& < > " '`) applied to every attacker-reachable
        value; the remaining interpolations are numbers, literal ternaries, or fragments already
        escaped when built. This is the **sink-level** limitation already filed above from the
        app G audit, but the proportion is the new information: a 🔴 HOLD verdict in which
        70% of the high findings are one correct file is a verdict a reader learns to discount,
        and the documented next step (`--fix-prompt`, "hand the fixes to your AI editor") would
        point an agent at correct code and invite it to change it. Worth considering whether a
        sink whose inputs all pass through a single-argument escaper in the same file can be
        downgraded, or at least counted once per file rather than once per sink.
      - **`VG020` "wildcard dependency" reads `engines`.** Two findings, both
        `bridge/package.json:8`, which is `"engines": { "node": ">=20" }` — a runtime constraint,
        not a dependency range. A `>=` in `engines` is the normal way to write that field, so
        this will fire on a large share of Node projects. Probably wants scoping to
        `dependencies` / `devDependencies` / `peerDependencies`.
      - **`VG010` SQL injection reads a CSS selector.** `extension/adapters/base.js:157` builds a
        `querySelectorAll('select, textarea, …')` string. The word `select` plus string
        concatenation is enough to return CRITICAL, and CRITICAL is what sets the HOLD — so a
        DOM query in a browser extension with no database anywhere in it decides the verdict.
        The other `VG010` is `d1/worker.js:66`, which interpolates a frozen `COLUMNS` literal and
        never input; that one is at least a real SQL string.
      - **`dist/` has to be built before the documented command works.** The published
        instruction is `node dist/cli.js`, and on a fresh checkout `dist/` does not exist, so the
        first run fails. `npm run build` first. Either the docs should say so or the CLI should
        say it when `dist/` is missing.

      Two things that worked well and are worth not losing: scoping by path
      (`cleartoship bridge extension d1`) cleanly excluded a vendored upstream that the project
      does not patch — which took 474 findings down to 47 — and the PASS lines that say what was
      skipped and why (`.gitignore` entries, build dirs) are the reason it was obvious the run
      had not quietly missed anything.

- [ ] **Three findings reported from the app G audit, 2026-10-28** (an outside
      app, run as `node dist/cli.js --offline` over 44 files, 2.8s):
      - **`VG120` SSRF — two false positives on a Cloudflare Worker.**
        `src/worker.js:10` is a generic `fetchTimeout(url, opts)` helper whose
        every caller passes `` `${env.SUPABASE_URL}` `` plus a fixed path, so the
        host is never user-controlled; a taint check would clear it. Worse,
        `src/worker.js:262` is `async fetch(request, env)` — the **Worker's own
        default export handler**, not an outbound request at all. Matching the
        method name `fetch` on a Workers entry point will fire on every Worker
        ever written, so this one is likely to recur across the portfolio.
      - **`VG146` "Unquoted .env Value" fires on shell scripts.**
        `macos/release.sh:17,19,26` and `public/install.sh:39,49,54`. These are
        `.sh` files assigning shell variables, not env files. Probably wants
        scoping to `.env*`.
      - **`VG012` is sink-level, so it cannot confirm a fix.** It flags
        `X.innerHTML = <non-literal>`, which stays flagged whether or not the
        inputs are escaped — the count was 7 before that app's XSS fix and 7
        after. The real defect was 9 unescaped interpolations feeding those
        sinks, which the scanner did not enumerate. It worked well as a pointer
        to *where to read*; it is not a signal of whether the taint is handled.
        Worth considering whether the finding can say "sink reached by a
        non-literal; check the inputs" rather than "XSS via innerHTML".
      - **Severity note on `CTS030`.** It returned CRITICAL, and so 🔴 HOLD, for a
        real secret in a `.env` that is gitignored, untracked and absent from
        every commit in every branch — the documented way that app's
        `wrangler dev` gets real secrets. The finding is correct; the severity
        cannot currently distinguish "secret in a committed file" from "secret in
        a gitignored local dev file", which is the difference between an incident
        and normal practice.
- [ ] **Maintainer-only settings the audit turned up** (not doable from the
      repo): **enable immutable releases** (release.yml publishes via a draft,
      so it is compatible), **delete the dead `NPM_TOKEN` secret**, and add a
      **Cloudflare rate-limit rule** on `/license/*` and `/webhooks/*`.
- [ ] **Found in the 2026-10-13 audit, deliberately not fixed yet.** CTS004
      ("authenticated but not owner-scoped", medium) says "any logged-in user can
      pass another tenant's id" about a route gated on `requireAdmin()`, where
      acting on someone else's row is the point. Fixing it properly needs the
      auth model to distinguish *authorization* from *authentication*, not a
      vocabulary match — a name list in this exact area has already hidden two
      real bugs — so it is recorded rather than patched. VG1008 still reports
      alongside CTS001 on an ungated admin write (same line, two criticals);
      kept because it also covers the authenticated-but-not-admin case CTS001
      rates lower. VG012 cannot prove `safeHtml` or `buildHTML()` is sanitised,
      so those stay reported. And an HTML file is read for credentials and by the
      7 HTML-language vendored rules, not by the JS AST scanners: an inline
      `<script>` in a `.html` is not analysed for CTS001/CTS070/CTS080-085.
      Since 2026-10-21 the same applies to `.svelte` / `.vue` / `.astro`
      single-file components: read for secrets and the html rules, their
      script blocks not AST-analysed.
- [ ] **Known limits still open after 0.13.13.** SQL inside a `DO $$ … $$`
      block is not parsed, so policies created there are invisible (a false
      CTS014 on app F's `forum_comment_likes`). A gate-only SELECT
      (`auth.role() = 'authenticated'`) on a table that is really private is not
      reported unless a scoped SELECT policy sits beside it — deliberate, to
      stay quiet on member-readable tables. Custom roles (`to
      supabase_auth_admin using (true)`) still trip the whole-table CTS014.
      Unknown package auth wrappers are credited by name, with a warning. The
      per-rule time budget has a ~2× margin on this machine (worst rule 126 ms
      per 400 KB vs 250 ms), so a slow runner could still see it fire.
- [ ] **Billing stays dormant (free in beta).** The Worker's webhook, key-id and
      missing-secret bugs were fixed in the audit, and migration
      `0002_license_per_subscription.sql` must be applied remotely
      (`wrangler d1 migrations apply cleartoship-licenses --remote`) before any
      payment is taken. There is no `/admin/license/issue` route and no
      client-side license verifier; both would have to be written first.
      `currentPeriodEnd()`'s field-name fallback still needs checking against
      whatever Stripe API version a real account is pinned to.
- [ ] **Get it in front of people, as early as possible.** Publish and publicize
      now; there is no minimum number of users to reach first (decided 2026-09-21).
      Every calibration decision so far was made against my own six repositories,
      which remains the biggest weakness in the tool's judgement, but the way to
      fix it is more people running it and reporting what comes back wrong, not
      recruiting a set number of testers before launching.
      **In progress 2026-09-22:** a Show HN post and a dev.to writeup are drafted
      (the CTS001 calibration story — 60 of 77 sampled findings were wrong, two
      real bugs hidden by the first version of the fix, both caught by reading
      what the fix removed). Neither is posted yet — blocked on logging into
      Hacker News and dev.to in the browser; nothing else is stopping it.
- [ ] **CTS001 still has real false-positive classes left, found but not fixed
      2026-09-22.** Of 60 sampled false positives from the 155-repo corpus, 24
      cleared with the false-positive fix that shipped (v0.13.9); the other 36
      are left on purpose, not by oversight:
      - **Name-based "public by design" cases** (analytics beacons, apps with no
        auth model at all, intake/lead forms) — only separable by route name
        today, and a name-list heuristic already hid two real bugs in this same
        pass (`register` hardcoding an Admin role, `leads` running paid
        enrichment), so widening it needs care, not just more names.
      - **Clerk middleware that already protects `/api`** — needs the
        `middleware.ts` matcher and `createRouteMatcher` public-route list
        actually parsed, not guessed at.
      - **Signature/auth checks delegated to a helper that itself calls an
        external service** (a Supabase REST call, a DB-backed API-key lookup)
        — not credited today because the scanner only follows first-party
        helpers, never into what they call out to.
- [ ] **New rule candidate, found during the same pass, not CTS001's job.**
      Unauthenticated `execa.command(\`...${formField}\`, { shell: true })` —
      direct shell-command injection from a request field, seen on a real public
      playground repo. Worth its own rule rather than folding into an existing
      one; not scoped yet.
- [ ] **Lockfile-vulnerability false positives, not yet triaged.** 148 of 154
      repos in the corpus still get a HOLD verdict, almost entirely from real
      `package-lock.json` / `pnpm-lock.yaml` versions matched against OSV — the
      overall verdict barely moved across the whole CTS001/CTS030 calibration
      pass. Unknown yet how much of that 148 is genuine (most likely) versus a
      severity-mapping or dev-dependency-splitting bug like the ones CTS024
      already exists to fix. Needs the same read-the-code treatment the other
      rules got; hasn't started.

- [ ] **Where the 2026-10-21 audit did not look — scope for the next one.**
      That pass went where the yield was (the walk/read layer, the dependency
      collectors, the vendored-rule guards, corpus triage of every critical on
      the seven real apps plus sampled removals on the fixture repos). It did
      NOT re-read `report.ts`'s five renderers beyond a skim, the
      `server-actions.ts` / `auth-helpers.ts` pair, the site Worker, or
      `action.yml` and the workflows — all last audited 2026-10-13 or
      2026-09-23 — and it triaged highs only where a critical led there, so
      the ~180 corpus highs (app C 59, app F 45, app E 39) have
      never had the read-the-code pass the criticals got. The next audit
      should start from one of those rather than re-walking this one's ground.
      **Done 2026-10-28** — see the entry above: the renderers and the ~180
      highs were the two it took. `server-actions.ts` / `auth-helpers.ts`
      (3,286 lines) is still the one nobody has re-read since 2026-10-13.
- [ ] **Three things the 2026-10-13 audit noticed and did not act on.**
      (The first sentence of this item was lost when `fb24b85` wrote over its
      opening line; restored here from the commit that introduced it.) 8
      vendored rules
      carry an `API:`-prefixed OWASP label (the API Security Top 10, a
      different list) that the README's OWASP table does not mention, so those
      rules' category reads as unmapped. Now that `site/public` HTML is
      actually read, static-site rules like VG142 (missing Subresource
      Integrity on a CDN `<script>`) can fire on landing pages where the CDN is
      a deliberate choice — no noise on this repo's four pages, but worth
      watching on the first user who scans a marketing site. And
      `/license/verify` on the Worker is unauthenticated by design (anyone can
      ask whether a key is valid); the mitigation is the Cloudflare rate-limit
      rule already listed in the maintainer-settings item above, not a code
      change.
- [ ] **Noticed in the 2026-10-21 audit, deliberately not acted on.**
      `bun.lock` / `bun.lockb` and `uv.lock` are not read by `resolveVersions`,
      so bun- and uv-only projects have their OSV queries made with range
      floors rather than installed versions — checked, but imprecise. A `.env`
      nested *deeper* than one level inside a gitignored directory is still
      never read (the peek is one `readdir` per skipped directory, by design).
      A UTF-16 file *without* a BOM still decodes as mojibake — PowerShell
      writes the BOM, so the no-BOM case was left. The non-production path idea
      lives in two places (`secrets.ts` `NON_PRODUCTION_PATH` and `paths.ts`
      `NON_PRODUCTION`) and they drifted identically once already; folding
      secrets onto `pathClass()` changes which secrets findings get demoted
      (paths.ts accepts affixed names like `transfer-tests/`), so it needs its
      own read-the-removals pass, not a refactor commit. `meta.resolvedFrom`
      on CTS024 always says `lockfile-or-range` — the ternary that was meant to
      distinguish them is decided after the lookup it reports on. And
      gitleaks' `cmd/generate/config/rules/*.go` keeps ~90 criticals: those
      sample keys are realistic by construction (that is their job), no path
      convention marks them, and a scanner that special-cases one repo's layout
      is shaping itself around its corpus.
- [ ] **Noticed in the 2026-10-28 audit, deliberately not acted on.**
      **`action.yml` runs the whole scan two or three times** — once for
      `--json`, once for `--markdown`, and again for `--sarif` when it is
      asked for. That is 2–3× the wall clock and 2–3× the registry and OSV
      traffic on every CI run, and worse than the cost: **the severity gate is
      computed from the JSON run and the PR comment is rendered from a
      different one**, so if the two disagree — a registry that answers once
      and times out the next — the comment and the verdict are from different
      scans. The fix is a CLI that writes several formats from one scan (a
      `--write <format>:<path>` option), then one invocation in the Action;
      that is a feature, not an audit patch, so it is recorded rather than
      half-built at the end of a pass.
      **VG926's name does not match what it matches.** "Next.js / React Server
      Components DoS" fires on `"react": "^19.2.4"` with no requirement that
      the project has Next.js or RSC at all — app F is a Vite SPA with
      no `next` dependency and no Server Functions, and got 5 highs, 3 of them
      on `package-lock.json` and 2 on the `package.json` beside it, so the
      same dependency is reported twice. The version range is correct and
      reachability analysis is deliberately out of scope, so this is a
      severity-and-wording problem rather than a false positive; it also only
      appears with `--offline`, since `GUARDVIBE_CVE_RULE_IDS` stand down once
      OSV has answered. Both halves (framework-gating a CVE rule, and
      de-duplicating a version rule across a manifest and its lockfile) need
      their own read-the-removals pass across the whole CVE ruleset.
      **`verdictOf` is documented as "the one place the verdict is decided"
      and `renderTerminal` still decides it again** from `scan.counts` inline.
      The two agree today, checked case by case; it is one idea in two places,
      which is how `NON_PRODUCTION` drifted.
- [ ] **Six new VG012 findings on app G, nothing written down yet.** The
      sweep read app G's HTML dashboards for the first time and they really
      do assign `innerHTML` from strings concatenated out of scan data
      (`innerHTML=cpuTopHtml`). Per the convention, new findings on one of my
      own apps belong in `security-scans/<date>-<time>.md` in *that* repo, not
      here — decide whether these are worth a report (the data is local machine
      telemetry, not attacker-controlled input) and write it there if so.
- [ ] **Where the 2026-10-28 audit did not look — scope for the next one.**
      That pass took the renderers and the corpus highs, which is what the last
      one left. What is still unread: **`server-actions.ts` /
      `auth-helpers.ts`, 3,286 lines between them, last audited 2026-10-13**
      and skipped by two audits running — the largest unexamined surface in the
      tool, and the one behind CTS001/CTS004, whose known false-positive
      classes are still open above. The site Worker and the workflows *were*
      re-read this time and nothing new came out of them: the Worker verifies
      Stripe signatures with SubtleCrypto, ignores stale events by `created`,
      re-reads the subscription rather than trusting the payload, and repeats
      the age check at the write; every third-party action is SHA-pinned, there
      is no `pull_request_target`, and `release.yml` is default-deny with
      per-job grants. Also untouched: the **~150 remaining highs** after this
      pass (app C 42, app F 38, app E 30) — this audit read every
      *cluster* of three or more and the singletons are unexamined — and the
      **mediums have never been triaged at all** on any repo.
- [x] **app C's hardcoded Shopify token is written up.** Reported at
      `/Users/Shared/app C's security-scan report` per the
      convention: a live `shpat_…` Admin API token for a development store,
      hardcoded as a `process.env.X || "shpat_…"` fallback in two server
      modules and a bare `const` in three scripts, duplicated across the
      `Shopify/ShopifyApp/` copy (10 source locations), plus two
      `.claude/settings.local.json` permission entries that embed it in an
      allowlisted `curl`. Not in any git history today — the app C root is
      not a repo and `saas/.env.local` is correctly ignored — which is exactly
      why it is worth fixing before either folder becomes one.

## Later — recorded, not being worked on

- **Trademark "ClearToShip".** The code is MIT and the package is public, so the
  licence deliberately lets anyone copy, modify and sell it — that is the trade,
  and it is the same one gitleaks and GuardVibe made with this project. What MIT
  does *not* grant is the name, and a trademark is the only protection here that
  actually works: a fork may take every line and still cannot call itself
  ClearToShip, which leaves the discoverability with the original.
  **Parked deliberately, not forgotten.** At zero users there is nothing to pass
  off and nobody to confuse, which is what a trademark protects against. The
  moment to file is when the name starts carrying weight — real users, a
  Marketplace listing, or the first time somebody else ships something built on
  this. Revisit then rather than on a date.

## Settled

- **No npm distribution, as of 2026-09-21.** ClearToShip ships as a GitHub Release
  plus `cleartoship.app/cleartoship.mjs`. The Action resolves the release bundle,
  then a checkout build, and never `npx`es the name — with the name unclaimed, that
  would be code execution for whoever registered it. The scanner still *queries*
  the npm registry, because checking a user's dependencies against it is the
  feature; when it cannot, the run says so and is never "clear".

- **Node floor: `^22.18.0 || >=24.11.0`,** as of 0.13.2. That is Babel 8's own
  range copied exactly rather than approximated — a looser `>=22.18` would claim
  Node 23 and 24.0–24.10 work, and Babel 8 does not support them. Node 18 and 20
  are dropped. CI tests the declared floor (`22.18.0`) alongside the latest 22
  and 24, so a claim the code cannot meet fails the build rather than a user's.
  Worth being clear why the exactness matters here rather than being pedantry:
  had the range been wrong, the tool would have installed happily and then failed
  at *parse* time — and an unparsed file produces **no findings**, not an error.
  A scanner's worst failure is reporting clean on code it never read.
  ⚠️ **Local dev needs a newer Node than this machine's default.** `node` on the
  PATH here is v22.14, below the floor. **Homebrew's v26 no longer runs** (as of
  2026-10-29): the bottle links `libada.3` and `libsimdjson.33`, the Cellar has
  ada-url 4 and simdjson 5, and it dies in dyld before printing a version — so
  `export PATH="/usr/local/opt/node/bin:$PATH"` now buys a broken interpreter
  rather than a newer one. `brew reinstall node` builds from source on this
  macOS/Intel pair (no bottle), which takes long enough that it is not the
  unblocking move. What 0.13.14 was built with instead: the official
  `node-v22.23.4-darwin-x64` tarball, checksum-verified against nodejs.org's
  `SHASUMS256.txt`, unpacked outside the repo and put on the PATH for the
  build — and v22 is what `ci.yml` and `release.yml` set anyway, so it matches
  the release runner more closely than v26 did.

## Deliberately not covered, and why

These are decisions, not gaps waiting to be filled. Adding a rule for any of
them would be box-checking, which is the failure mode this project exists to
avoid.

- **OWASP A06 (Insecure Design).** Missing threat modelling is an architecture
  concern that no static read detects. Revisit only if a genuinely high-signal
  design-flaw pattern turns up.
- **OWASP LLM05 (Data & Model Poisoning).** Needs training-pipeline and dataset
  provenance. Nothing in a web app's source tree answers it.
- **Strengthening A04 / A02 first-party.** Parked on purpose rather than by
  neglect: five repos were triaged and no real gap showed up. Speculative rules
  are how a scanner becomes noise.

## Deliberately not built

- **A cross-finding risk graph** correlating web findings with LLM findings.
  It is an existing category, and a *Critical* assembled out of two mediums is
  exactly the false-positive behaviour that eight releases went into removing.
- **An auto-fix PR bot.** `--fix-prompt` and SARIF already cover the useful part
  at none of the cost.
- **Broader generic SAST/SCA.** Saturated, free at the entry point, and not a
  reason anyone would choose this tool.

## Pricing

**Everything is free while ClearToShip is in beta (decided 2026-09-21).** The
RLS, Server Actions and LLM/agent suites had been split into a private
`cleartoship-rules-pro` repository for a planned $5/month Pro tier. They are back
in this repository, MIT licensed, and ship in the free bundle. Why: a separate
package cannot be installed now that npm is out, so an unpublished paid tier
delivered nothing; the tool's headline features (the agent surface) were missing
from the download; and the same rules had been public under MIT since v0.4.

The private repository and the license-issuing Worker under `site/` (D1 database,
Ed25519 token signing, Stripe webhook code) remain, dormant, in case a paid tier
is ever wanted. Nothing charges anyone. No price is set — $5/month was only ever a
plan — and what is free now stays free.

## Contributing

The most useful bug report here is a **false positive, with the code that caused
it**. A rule that fires on correct code is a worse bug than a rule that misses
something: one wastes your afternoon and teaches you to ignore the tool, the
other you never knew about. Removing false positives is what most of this
project's history is actually made of, and every removal so far was verified by
reading the code it was about rather than by loosening a threshold.

Second most useful: a **missed finding**, with the code it should have caught.

New rules are welcome, but the bar is deliberately high — a rule that cannot
name a specific wrong thing a developer would act on does not go in, however
well it maps to a compliance table.

## Audit trail — bugdetect

Written by `bugdetect`, which audits this app from /Users/Shared/bugdetector.
Each line is a machine-made change or a recorded decision, not a task.

- 2026-11-09 — oxlint safe-fix applied by bugdetect to 2 file(s): src/scanners/dependencies.ts, src/scanners/server-actions.ts. 5 finding(s) were open in them (eslint(no-unused-vars), unicorn(no-new-array), unicorn(prefer-string-starts-ends-with)); which closed is settled by the next audit run. Not verified against this app's tests.
- 2026-11-09 — oxlint safe-fix applied by bugdetect to 5 file(s): src/scanners/auth-helpers.ts, src/utils/ast.ts, src/utils/modules.ts, src/utils/redact.ts, test/rules-audit.test.js. 5 finding(s) were open in them (unicorn(prefer-string-starts-ends-with)); which closed is settled by the next audit run. Not verified against this app's tests.
- 2026-11-09 — oxlint safe-fix applied by bugdetect to 1 file(s): src/report.ts. 2 finding(s) were open in them (eslint(no-control-regex), eslint(no-useless-escape)); which closed is settled by the next audit run. Not verified against this app's tests.
- 2026-11-09 — oxlint safe-fix applied by bugdetect to 1 file(s): src/scanners/community.ts. 3 finding(s) were open in them (eslint(no-unused-expressions), eslint(no-useless-escape), unicorn(no-new-array)); which closed is settled by the next audit run. Not verified against this app's tests.
- 2026-11-09 — shellcheck safe-fix applied by bugdetect to 1 file(s): scripts/check-version-pins.sh. 2 finding(s) were open in them (SC2086, SC2116); which closed is settled by the next audit run. Not verified against this app's tests.
