# CONTEXT.md — cohort-walker

## What this repo is

`cohort-walker` is a continuous-monitoring drift detector for the
Limitless ecosystem cohort. It walks the four canonical cohort roots
(`flagships/` / `engines/` / `infrastructure/` / `foundation/`),
classifies each member by substrate language, and probes for the
seven invariant markers a fully-onboarded R174 5-of-5 cohort member
would expose.

`cohort-walker` is one of three cohort tooling binaries — the other
two are `cohort-map` (one-shot SVG renderer of current membership)
and `lore-mark-verify` (cold-stamp / cold-verify CLI for individual
mark payloads). All three share the canonical KAT-1 hex pin and the
same exit-code numbering so a regulator running multiple tools sees
consistent verdicts.

## What this repo is NOT

- **Not a compliance verdict engine.** A FAIL row signals a
  byte-equality difference worth a human review. It does NOT signal
  fraud, negligence, or breach. The R166 liability footer printed on
  every report makes this explicit and is REQUIRED on the regulator-
  handoff boundary.

- **Not authoritative for "this flagship is on the cohort train".**
  Membership is decided by the godfather cohort review process; the
  walker only reports what's on disk at scan time. A flagship can be
  legitimately absent from a cohort row (doc-only repo, deprecated,
  intentionally not yet onboarded). The R69a HUMAN ESCAPE clause
  invites override entries in `docs/cohort-overrides.md`.

- **Not a substitute for `cohort-map`.** `cohort-map` is the
  marketing / investor / deck-quality renderer of *current*
  membership. `cohort-walker` is the CI-grade drift gate against a
  *stored baseline*. The two share the KAT-1 anchor but answer
  different questions.

## Design constraints

1. **Pure stdlib.** Zero non-stdlib imports across the entire
   binary, mirroring the cohort canonical posture (`limitless-rs`,
   `limitless-jvm`, `limitless-ts`, `limitless-py` all stdlib-only).

2. **Cheap.** A full scan of all four roots (~370 members) runs in
   under 30 seconds on a developer laptop. The marker probe is a
   substring grep capped at 1 MiB per source file.

3. **Substrate-portable test posture.** Tests use `t.TempDir` for
   every fixture; no test reaches out to the on-disk Limitless
   monorepo. Run `go test ./...` from a fresh clone and every test
   passes.

4. **Stable exit-code numbering.** Numbering matches
   `lore-mark-verify` + `cohort-map`. CHANGING THESE BREAKS
   DOWNSTREAM AUTOMATION.

## Cohort-package shape (eat own dogfood)

`cohort-walker` is itself a cohort member at R174 5-of-5 from
inception:

- `cohort/legal/liability_footer.go` — R166 LIABILITY_FOOTER_CONST
- `cohort/observability/loud_once.go` — R143 LOUD-ONCE-WARNING wire
- `cohort/firewall/stale.go` — R150 IsStale predicate + 7 sentinel
  TODO constants
- `cohort/audit/trail.go` — R154 audit-row shape (Outcome
  constrained to R115's three-state enum)
- `cohort/escape/escape.go` — R69a HUMAN ESCAPE clause + tag
- `cohort/identity/identity.go` — R151 KAT-1 hex pin
  (`239a7d0d...`) + L43 Version (`lore@v1:`)

The R151 pin is byte-identity-asserted against a `crypto/hmac`
recomputation in `walker_test.go::TestKAT1Recompute_HMACByteEquality`.
Any drift fails the build.

## R-rule impact

This repo's first commit is the saturator-1/3 for
**R-COHORT-WALKER-AUTOMATED-DRIFT-DETECTOR** (BR1 Q3 strategic bet).
It composes with the I31 cardinality stress test (one-shot vs
continuous monitoring) — I31 answers "can the cohort sustain N×
membership?", cohort-walker answers "is the cohort drifting today?".

## Honest limitations

- **Substrate detector misses some flagships.** Detection is
  manifest-first then source-extension fallback. A flagship with no
  manifest and no recognised source extension scans as
  `substrate: unknown`. The baseline snapshot shows ~15 such
  flagships, mostly doc-only or in-flight. This is by design — a
  false positive on substrate is worse than `unknown`.

- **KAT-1 pin probe is a substring grep.** A flagship that
  intentionally renders the hex into multiple substrings (e.g. for
  documentation) would scan as "not pinned". The canonical pin
  pattern is a literal 64-char hex; flagships that deviate get
  a WARN-class drift verdict.

- **Wire-format drift detector is heuristic.** It only fires when
  bare `"v1:"` or `"lore-v1:"` candidates appear *near* a mark /
  mirror / lore token. False negatives are possible; the test
  `TestMarkers_DriftDetection_BareV1Prefix` documents the contract.

- **INDEX-LIE detector covers Rust + Go only.** Other substrates
  use different module-declaration conventions; adding coverage is
  cheap (a new `detectXXXLies` function) but out of scope for the
  saturator-1 ship.

## Operator handoff

The initial baseline lives at
`cohort-snapshot-2026-05-28.json`. It was taken mid-infra-marathon
and captures the pre-infra-uplift state of 368 cohort members. The
GitHub Actions workflow `cohort-drift-check` is `workflow_dispatch`
only and uploads the markdown report + JSON delta as build artefacts.
