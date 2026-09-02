# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.0** (npm `latest`, published 2026-09-02)._
_Releases publish **unsigned**: npm's registry refuses provenance from a private
source repo, and `release.yml` turns signing on by itself the day that changes._

## Where this stands

Nine releases, 0.8.0 → 0.13.0. The calibration work is the point of the project
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
- [ ] **A third-party GitHub Action.** `uses: murtazaozdemir/cleartoship@vX`
      cannot resolve while this repository is private, and it cannot be listed on
      the Marketplace. The `npx cleartoship` CI recipe in the README works
      everywhere today and carries the load until that changes.
- [ ] **A user who is not me.** Every calibration decision so far has been made
      against my own repositories. That is the biggest single weakness in the
      tool's judgement, and no amount of further dogfooding fixes it.

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

Not open to outside contributions yet — the repository is private. The npm
package is public and unaffected: `npx cleartoship`.

Bug reports, once that changes, are most useful as a **false positive with the
code that caused it**. A rule that fires on correct code is a worse bug than a
rule that misses something, and it is the class of problem this project spends
most of its time on.
