# CLAUDE.md — cleartoship

## This repo is PUBLIC — anonymise at write time

Calibration notes, audit entries, test comments and TODO items here describe real
apps that are **private**. A bug report needs the *shape* of the problem, not whose
repo it came from, so write the label and never the name: `app C's query builder`,
not the app's actual name. The same goes for file paths inside those apps — a path
to a security-scan report is worth more to someone hostile than the finding is.

`.feedback-key.md` maps the labels to the real apps and is **gitignored**; it must
stay that way. `guardvibe` is not one of them — it is the vendored upstream library
in `src/vendor/guardvibe/`, public by its own licence.

This is written as a rule because the opposite happened: 59 mentions of seven
private app names, across `TODO.md`, two test files, a shipped source comment, a
workflow and a release skill, sat on the public `main` for eleven days (2026-10-28
to 2026-11-08). They were cleaned forward rather than by rewriting history —
force-pushing would have changed every SHA on a repo that ships a GitHub Action
with 14 release tags, and it would not even have removed the old commits from
GitHub, which stay reachable by SHA until Support garbage-collects them. Cheaper
not to write the name in the first place.

## Recording progress

When real progress happens here — a fix shipped, a release cut, a calibration
pass completed, a bug found and fixed — extend `TODO.md`'s `## Where this
stands` section with a new paragraph in the same voice, in the same commit (or
a small follow-up). It's a dated, chronological narrative running from 0.8.0
to the present; that's the durable answer to "where are we at" for anyone
reading this repo later, including a future session with no memory of how the
work happened. Don't let a terse commit subject line, or a chat reply that
only exists in someone's terminal history, be the only record.

Say what shipped, what broke, and what verification actually happened —
match the existing entries' density: real numbers, the actual code shape a
bug had, not just "fixed a bug."

`## Open` is for what's unresolved; keep it current too — remove or update an
item once it's actually done rather than leaving it stale.

## Browser automation on this repo — a real near-miss, not a hypothetical

**2026-09-22, GitHub Marketplace listing:** before touching anything, the
Chrome profile named "Default" — the one approved for this work — turned out
to be signed into GitHub as a completely unrelated account (`client-template`),
not the account that owns this repo. Every browser action stopped there: no
click, no navigation past checking identity, until the right account was
confirmed signed in and re-verified against real account data (the actual
repos in the sidebar), not just the name typed in chat. Nothing was done
under the wrong account — the check caught it before the first click.

The lesson this is worth recording, not just having happened once: a profile
*name* someone gives you is not proof of *which account* is signed into it.
Verify the signed-in identity directly (an account switcher, a dashboard
showing real account data — never trust an avatar or a typed name alone)
before any action that touches an account, every time, even when the profile
was named explicitly and confidently. GitHub's own Security Log
(`github.com/settings/security-log`) is the durable, independent record of
what actually got signed or logged in on this account, whatever this repo's
own docs say happened — check it if there's ever doubt after the fact.

---

## Where The Logs Live

**Two surfaces, and the busiest one never reaches a log.**

- **Workers Logs for `cleartoship`** — on via `"observability": { "enabled": true }` in
  `site/wrangler.jsonc`. **Search:** Cloudflare dashboard → Workers & Pages → `cleartoship` →
  **Logs**, or `npx wrangler tail cleartoship --format pretty`. **Retention:** the plan's
  window — no Logpush.
  ⚠️ **It covers `/webhooks/*` and `/license/*` only.** `run_worker_first` lists exactly those
  two prefixes, so ordinary landing-page traffic is served as a static asset and **never invokes
  the script** — those requests are not in this log at all. The zone's Analytics is the only
  record of them. This is also why there is no `/health` route: adding one means changing
  `run_worker_first`, which is a routing change to test with `wrangler dev` first.
- **D1 `cleartoship-licenses`** holds licences and Stripe webhook state. An application record,
  not a log.
- **The CLI and the GitHub Action** — a scan writes its findings to stdout, `--json -o <file>` or
  `--markdown`, and **keeps no log of its own run**. Rule 7 step 17 asks a command-line tool for
  one log file per run with private permissions; that does not exist yet.

**What is not built yet** is listed under *2026-11-06 — Rule 7 step 17* in this app's `TODO.md`. Keep that list and this section in step: this is the only place that says where the logs live.
