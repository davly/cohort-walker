// Package escape hosts the R69a HUMAN-ESCAPE wire for cohort-walker.
//
// R69a HUMAN-ESCAPE requires every flagship that emits a machine verdict
// likely to be acted on by a human (CI fail, regulator audit row) to
// include an explicit human-escape clause: a one-line invitation to
// override the automated verdict when the human reviewer has knowledge
// the machine does not. For cohort-walker, the escape is:
//
//   - Some flagships are intentionally not yet on the L43+R151 train
//     (e.g. doc-only repos, deprecated cohorts).
//   - The walker has no way to know "intentionally" — its only signal
//     is presence. R69a says: tell the human reviewer they may override.
//
// The escape string is a literal constant so a grep across the cohort
// finds every R69a wire without ambiguity.
package escape

// HumanEscape is the literal text appended to every drift-report row
// that crosses the regulator-handoff boundary.
const HumanEscape = `[R69a HUMAN ESCAPE]
A human reviewer with cohort context MAY override this automated verdict
by adding an entry to docs/cohort-overrides.md with rationale and date.
Overrides are themselves audited via the R154 audit-row pipeline.`

// Tag is the machine-readable discriminator downstream automation greps.
const Tag = "R69a_HUMAN_ESCAPE"

// IsOverridable returns true for verdicts that may legitimately be
// overridden by a human reviewer. PASS is never overridable (we do not
// turn a PASS into a FAIL via override — that would be auditor capture).
// FAIL and SKIP are overridable.
func IsOverridable(outcome string) bool {
	switch outcome {
	case "FAIL", "SKIP":
		return true
	default:
		return false
	}
}
