# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.1** (npm `latest`)._
_v0.13.0 and earlier published **unsigned** — npm's registry refuses provenance
from a private source repo. The repository is public now, and `release.yml`
reads its visibility, so 0.13.1 is the first release signed with provenance._

## Where this stands

Ten releases, 0.8.0 → 0.13.1. The calibration work is the point of the project
so far: across a five-repo corpus the tool went from 2,290 findings to a few
hundred, and from 157 criticals to a handful — **every removal verified by
reading the code it was about**, never by adjusting a threshold. Reports that
name a real problem are worth more than reports that cover a table.

0.13.0 added the three agent rules (CTS083/084/085) and made the LLM/agent
surface the headline rather than the fifth section.

## Open

- [ ] **The Node floor.** Babel 8 + commander 15 need Node ^22.18. The code is
      ready — 40/40 tests pass against Babel 8 — and the only open question is
      which Node versions to drop.
- [ ] **List the Action on the Marketplace.** `uses: murtazaozdemir/cleartoship@vX`
      resolves now that the repository is public; the Marketplace listing itself
      is a checkbox on a release and still needs doing. The `npx cleartoship` CI
      recipe in the README works everywhere regardless.
- [ ] **A user who is not me.** Every calibration decision so far has been made
      against my own repositories. That is the biggest single weakness in the
      tool's judgement, and no amount of further dogfooding fixes it.
- [ ] **Trademark "ClearToShip".** The code is MIT and the package is public, so
      the licence deliberately lets anyone copy, modify and sell it — that is the
      trade, and it is the same one gitleaks and GuardVibe made with this project.
      What MIT does *not* grant is the name. A trademark is the only protection
      here that actually works: a fork may take every line and still cannot call
      itself ClearToShip, which leaves the discoverability with the original.
      Worth filing sooner rather than later now that the repository is public.

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

**Free while in beta.** No tiers, no number.

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
