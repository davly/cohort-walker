# cohort-walker

Continuous-monitoring drift detector for the Limitless ecosystem cohort.

`cohort-walker` walks the four canonical cohort roots
(`flagships/` / `engines/` / `infrastructure/` / `foundation/`),
classifies each member by substrate language, and probes for the seven
invariant markers a fully-onboarded R174 5-of-5 cohort member would
expose:

| # | Marker | R-rule |
|---|--------|--------|
| 1 | `mirrormark` package or equivalent file presence | R143 + R151 anchor |
| 2 | KAT-1 hex byte-identity pin (`239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`) | R151 |
| 3 | L43 wire-format prefix `lore@v1:` literal | L43 / R151 |
| 4 | R143 LoudOnce wiring (`LOUD-ONCE-WARNING` literal) | R143 |
| 5 | R150 `IsStale` predicate | R150 |
| 6 | R166 `LIABILITY_FOOTER` constant | R166 |
| 7 | `foundation/pkg/*` thin-shim usage | foundation Wave-N |

`cohort-walker` complements the one-shot `cohort-map` SVG renderer
(`davly/limitless-cohort-map`): `cohort-map` produces a deck-quality
poster of *current* cohort membership; `cohort-walker` runs continuously
against a stored baseline and *flags drift*. They share the canonical
KAT-1 hex pin so any future divergence between "the map says X" and
"the walker found Y" is itself caught by both tools' kat-1-check
sub-commands.

## Install

```sh
go install github.com/davly/cohort-walker/cmd/cohort-walker@latest
```

## Usage

```sh
# 1. Take a baseline snapshot.
cohort-walker scan --out cohort-snapshot-2026-05-28.json

# 2. Later — compare current cohort to baseline (CI gate).
cohort-walker verify --baseline cohort-snapshot-2026-05-28.json

# 2b. Structured verify verdict (exit_code + summary + R154 audit_row) as JSON.
#     captured_at on the audit row mirrors the scan, so it is byte-stable under
#     a fixed clock (SOURCE_DATE_EPOCH / --no-timestamp). Exit code is unchanged.
cohort-walker verify --baseline cohort-snapshot-2026-05-28.json --json

# 3. Human-readable drift report (includes the absolute "Below R174 5-of-5"
#    census naming every chronically-incomplete member, not just changed ones).
cohort-walker report --baseline cohort-snapshot-2026-05-28.json --out drift.md

# 4. Machine-readable delta JSON.
cohort-walker scan --out current.json
cohort-walker diff --baseline cohort-snapshot-2026-05-28.json --current current.json

# 5. KAT-1 self-check (re-derives the cohort anchor).
cohort-walker kat-1-check

# 6. Deterministic scan — suppress the wall-clock captured_at so two scans of
#    an unchanged tree are byte-identical (for committed snapshots / the
#    determinism gate). SOURCE_DATE_EPOCH is honored when the flag is omitted.
cohort-walker scan --no-timestamp --out current.json
```

The only wall-clock field in a snapshot is `captured_at`. `--no-timestamp`
zeroes it (`0001-01-01T00:00:00Z`); otherwise an integer `SOURCE_DATE_EPOCH`
(seconds since the Unix epoch) pins it for reproducible builds. Both make
`scan` output byte-for-byte stable run-to-run — mirroring `receipt` /
`groundtruth`.

## Exit codes

Numbering deliberately mirrors `lore-mark-verify` and `cohort-map` so a
regulator running all three sees consistent verdicts.

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | drift FAIL — KAT-1 lost / wire-format drift / INDEX-LIE / marker regression |
| 2 | drift WARN — substrate change / dropped member / missing R174 5-of-5 (only emitted under `--strict`) |
| 3 | stale baseline |
| 5 | KAT-1 drift |
| 6 | usage error |
| 9 | internal error |

## Cohort packages (R174 5-of-5)

`cohort-walker` is itself a cohort member and eats its own dogfood. It
ships the canonical six cohort packages under `cohort/`:

- `cohort/legal` — R166 LIABILITY_FOOTER constant
- `cohort/observability` — R143 LoudOnce wire
- `cohort/firewall` — R150 IsStale predicate
- `cohort/audit` — R154 audit-row shape
- `cohort/escape` — R69a HUMAN ESCAPE clause
- `cohort/identity` — R151 KAT-1 hex pin

Every drift report `cohort-walker` emits ends with the R166 liability
footer + R69a human-escape clause, so operators and regulators reading
the report cannot mistake an automated drift scan for an authoritative
compliance verdict.

## GitHub Actions

A workflow template lives at `.github/workflows/cohort-drift-check.yml`.
It is `workflow_dispatch`-only (operator-triggered) by design — auto-
trigger on push would generate false-positive drift because the cohort
baselines live in sibling repos. The template uploads the markdown
report + JSON delta as build artefacts and posts a summary to the run
panel.

## R-rule impact

- **R-COHORT-WALKER-AUTOMATED-DRIFT-DETECTOR** — saturator 1/3 (BR1 Q3
  strategic bet). Composes with the I31 cardinality stress test
  (one-shot vs continuous monitoring).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
