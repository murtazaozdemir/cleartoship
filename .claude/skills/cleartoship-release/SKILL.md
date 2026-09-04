---
name: cleartoship-release
description: How to ship ClearToShip and verify that it actually shipped — releases, tags, npm publishing, the Cloudflare landing page, version pins in the docs, self-scan coverage, and the rule-calibration bar. Use this whenever the work touches releasing, publishing, tagging, bumping a version, a failing or suspicious CI run, `release.yml` / `ci.yml` / `deploy-site.yml` / `action.yml`, the npm package, the GitHub Action, the site/ Worker, or adding or loosening a scanner rule — and also when a run looks green but you have not yet seen the artifact it was supposed to produce, which is the case this exists for.
---

# Shipping ClearToShip

The governing idea, and the reason for everything below: **a green step is not a
shipped artifact.** Every outage this project and its sibling `aistoreaudit`
have had looked like success from inside CI. Nothing here is theoretical — each
rule is followed by the incident that produced it.

So the habit to build is: after anything meant to ship, go and look at the thing
that was supposed to change. Not the exit code, not the checkmark — the artifact.

## Verify the artifact, not the step

| What you did | What proves it worked |
| --- | --- |
| Published to npm | `npm view cleartoship@<version> version` returns that version |
| Deployed the landing page | `npx wrangler deployments list --name cleartoship` shows a *new* version id |
| Cut a GitHub release | `gh release view v<version>` lists the expected assets, and one downloads and runs |

If you cannot state which command you ran to confirm it, it is not confirmed.

This table is for ClearToShip only. The sibling app `aistoreaudit` has the same
rule and its own commands, and `/Users/Shared/CLAUDE.md` is where those live —
read them there rather than copying them here. One operational fact in two
places is how the stale one survives, which is the same failure this repo keeps
fixing in its own docs.

**Why.** On 2026-09-03 the `v0.13.4` release run reached `Check the npm token`,
failed 401, and skipped publish, registry-verify and the GitHub Release. The job
was red, but the more dangerous shape is the quiet one: `aistoreaudit` twice ran
stale code in production for days — once because GitHub billing killed runs in
~2 seconds *before the job started*, swallowing two releases whole, and once
because a missing `CLOUDFLARE_API_TOKEN` failed in ~8 seconds while four commits
piled up undeployed. Both looked fine from the commit list.

A registry answer can lie by looking healthy, too. When `cleartoship` was
unpublished, `https://registry.npmjs.org/cleartoship` still returned **HTTP 200**
— with `versions: {}` and empty `dist-tags`. Check the content, not the status.

## Releasing

The tag is the release. `release.yml` fires on `push: tags: ['v*']` and nothing
else — merging to `main` publishes nothing.

1. Bump `package.json` (`npm version <x.y.z> --no-git-tag-version`).
2. Update every version literal in the docs — see below.
3. Commit, then tag and push the tag.
4. Watch the run, then **verify the artifact** per the table above.

Order matters inside the job, and it is deliberate: the GitHub Release is
created **before** the npm publish. Keep it that way. It used to be the last
step, so when the token check failed the release was skipped with it, and the
one distribution channel that does not depend on npm was left hostage to npm
succeeding. `v0.13.5` tagged, failed at the token, and left a bare tag with
nothing to download. After the reorder the same failure produced a working,
downloadable release.

The publish step is idempotent (it checks whether the registry already serves
the version), and so is the release step (it uploads to an existing release
rather than erroring). This is on purpose: a tag is expected to be **re-run**
after a credential is fixed, without needing a new version number.

### Distribution has three paths, and they are not interchangeable

- `npx cleartoship` — the npm package. Needs npm to be serving it.
- `npx github:murtazaozdemir/cleartoship` — builds on install via the `prepare`
  script. Needs npm for the five runtime dependencies, but not for this package.
  `prepare`, not `prepublishOnly`: npm runs `prepare` on git installs.
- `cleartoship-standalone.tgz` from the latest release — one bundled file,
  `dependencies: {}`, nothing left to resolve.

The standalone artifact must stay behaviourally identical to the package it
stands in for; the suite asserts they produce the same findings. A fallback that
behaves differently from the tool you tested is not a fallback.

## Version literals in the docs

`action.yml` resolves its own version at runtime rather than naming one, because
that line was twice left stating the previous release during a bump. Prose
cannot do that, so `ci.yml` and `release.yml` assert it instead: every
`cleartoship@vX.Y.Z` and `releases/download/vX.Y.Z` in `README.md` and
`examples/security.yml` must equal `package.json`.

When adding a new versioned URL to the docs, either extend that assertion or —
better — use a version-free URL, which is why the standalone asset is named
without a version so `/releases/latest/download/` works forever.

## Self-scan coverage

CI scans `src site examples scripts .github` plus the manifests and docs, not
`src` alone. That matters because the README, `package.json`, `action.yml` and
the landing page are all part of what this publishes.

**Why.** While CI scanned only `src`, the tool reported a false positive on its
own README — `npx cleartoship` read as a suspicious new dependency — through a
whole release, because the file was never scanned. Widening the scan immediately
caught a credential-shaped literal in a source comment written that same
afternoon.

Never add a project-specific directory name to `SKIP_DIRS` in
`src/utils/files.ts`. `site` and `_reference` were once on that list, which meant
every user with a `site/` directory had that entire subtree reported clean
without a single file being opened. Everything on that list must be regenerable
in *any* repository, not just this one.

More generally: when the scanner declines to read something, say so in the
report. Gitignored paths, skipped directories, oversize files and truncated
match lists are all counted and surfaced, because "no findings" must never be
silently indistinguishable from "nothing was read".

## Changing a rule

The bar for this project is unusual and worth respecting.

**Removing a false positive: read the code it fired on.** Never loosen a
threshold to make a finding go away. Every removal in this project's history was
verified by reading the actual code that triggered it, and that is what makes
the report trustworthy. A rule that fires on correct code is a worse bug than a
rule that misses something — one wastes an afternoon and teaches people to
ignore the tool.

**Adding a rule: it must name a specific wrong thing a developer would act on.**
Mapping neatly onto a compliance table is not sufficient. Several categories are
*deliberately* uncovered (`TODO.md` lists them with reasons); adding rules for
them would be box-checking, which is the failure mode this project exists to
avoid.

**Write the assertion that could fail.** The CVSS severity mapping was dead for
a year — OSV publishes `severity[].score` as a vector string, so `Number()`
returned `NaN` and every advisory defaulted to `high`. The test meant to catch
that asserted `notEqual(severity, 'low')`, which passes whether the mapping works
or not. Assert the value, not the absence of the worst case.

**A test that skips is a test that is not running.** Three network-gated tests
skipped silently on the maintainer's machine for months and were only observed
passing when a CI run happened to surface them. If a test can skip, know what
makes it skip and confirm it runs somewhere.

## Local environment

`node` on the PATH is below this project's floor (`^22.18.0 || >=24.11.0`, which
is Babel 8's own range copied exactly). Use Homebrew's:

```bash
export PATH="/usr/local/opt/node/bin:$PATH"
```

This is not pedantry. Below the floor, Babel fails at *parse* time — and an
unparsed file produces no findings, not an error. The worst failure available to
a scanner is reporting clean on code it never read.
