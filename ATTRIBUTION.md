# Attribution

ClearToShip vendors and adapts work from other projects. This file records what,
from where, and under which licence.

## Vendored code

### GuardVibe — `src/vendor/guardvibe/`

- Source: https://github.com/goklab/guardvibe
- Copyright 2026 GokLab
- Licence: Apache License 2.0 — full text in `LICENSES/guardvibe-Apache-2.0.txt`,
  upstream NOTICE in `LICENSES/guardvibe-NOTICE.txt`

468 security rules are vendored verbatim under `src/vendor/guardvibe/rules/`.
Each file carries a provenance header. Rule content is **unmodified**; the only
changes are the added headers and an aggregating `index.ts` written by this
project.

Modifications, as required by Apache-2.0 §4(b), are made at runtime in
`src/scanners/community.ts` rather than in the vendored files:

- **27 rules are superseded** by ClearToShip's own AST and schema checks, which
  reason over a whole function body or a replayed migration rather than a fixed
  character window. Running both would double-report the same defect and import
  the less precise location. Each is listed with the rule that replaces it.
- **5 rules are withheld** as measurably noisy in this tool's context — for
  example `VG543`, which matches `; DROP|DELETE|INSERT …` anywhere in a `.sql`
  file and therefore fires on the normal shape of every migration. Each is
  listed with its reason.
- Findings in test, fixture and documentation paths are reported at `low`.

Every vendored finding carries `meta.source: "guardvibe"` and its attribution
string, so provenance survives into JSON and SARIF output.

## Ideas adopted, code not copied

These informed the rule set. No code, regex or rule text was taken.

| Project | Licence | What it informed |
| --- | --- | --- |
| [supabase/splinter](https://github.com/supabase/splinter) | none stated | The vulnerability classes behind CTS010–019 and CTS050–052. Splinter queries a live database; ClearToShip reimplements these statically against migration files. |
| [slopcheck](https://github.com/mattschaller/slopcheck) | MIT | Distinguishing HTTP 451 (pulled for malware) from 404 (never existed) from unpublished-with-installs (open to takeover) — CTS026/CTS027 — and reading install commands out of prose and agent instruction files. |

## Deliberately not used

| Project | Licence | Why |
| --- | --- | --- |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | 800+ verified credential detectors, and the most tempting corpus here. AGPL's network-use clause reaches a hosted service, so adopting any substantial part of it would put that obligation on ClearToShip. This is a licensing decision, not a technical one — it can be revisited by choosing to release under AGPL. |
| [RouteWarden](https://github.com/elicosilva/RouteWarden) | AGPL-3.0 | Same. |
| [semgrep-rules](https://github.com/semgrep/semgrep-rules) | Semgrep Rules License v1.0 | A bespoke licence whose terms need reading before any rule is reused; the repository's LICENSE file is a single line pointing at semgrep.dev/legal/rules-license. |
| [supabase-exposure-check](https://github.com/bscript/supabase-exposure-check) | none stated | No licence file means no licence granted. |

Taking a part rather than the whole does not change any of this: copyright and
the AGPL both apply to substantial portions, not only to entire programs. What
is genuinely free to take is the *idea* — the class of vulnerability, the fact
that a check is worth making. Expression (regexes, queries, rule prose) is not.
