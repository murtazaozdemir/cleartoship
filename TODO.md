# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.2** (npm `latest`)._
_v0.13.0 and earlier published **unsigned** — npm's registry refuses provenance
from a private source repo. The repository is public now, and `release.yml`
reads its visibility, so 0.13.1 is the first release signed with provenance._

## Where this stands

Eleven releases, 0.8.0 → 0.13.2. The calibration work is the point of the project
so far: across a five-repo corpus the tool went from 2,290 findings to a few
hundred, and from 157 criticals to a handful — **every removal verified by
reading the code it was about**, never by adjusting a threshold. Reports that
name a real problem are worth more than reports that cover a table.

0.13.0 added the three agent rules (CTS083/084/085) and made the LLM/agent
surface the headline rather than the fifth section. 0.13.1 was the first signed
release. 0.13.2 raised the Node floor onto Babel 8.

## Open

- [ ] **List the Action on the Marketplace.** `uses: murtazaozdemir/cleartoship@vX`
      resolves for anyone now, and `action.yml` already carries the branding a
      listing requires. What is left cannot be scripted: there is no
      `marketplace` field on the release object and `/marketplace_listing` is not
      writable, because publishing means **accepting the GitHub Marketplace
      Developer Agreement**. That is a legal acceptance, so it has to be done by
      hand on the release page. The `npx cleartoship` recipe in the README works
      everywhere regardless, and on any CI, not just GitHub.
- [ ] **A user who is not me.** *The one that actually matters.* Every
      calibration decision so far has been made against my own six repositories,
      which is the biggest single weakness in the tool's judgement, and no amount
      of further dogfooding fixes it — I would only be re-testing the same code
      against the same assumptions. The cheapest way to fix it is to run the
      scanner over somebody else's Next.js + Supabase + AI-agent codebase and
      walk them through the report, in exchange for permission to fix whatever
      comes back wrong. Five of those would teach more than the next five rules.

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
  PATH here is v22.14, below the floor. Homebrew's v26 satisfies it:
  `export PATH="/usr/local/opt/node/bin:$PATH"` before `npm install` or `npm test`.

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
