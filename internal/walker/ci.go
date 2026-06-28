// ci.go — CI exit-code adapter. The GitHub Actions workflow template
// calls `cohort-walker verify` which runs Scan + Diff against the
// stored baseline and exits with one of these stable codes. Numbering
// mirrors lore-mark-verify + cohort-map so a regulator running multiple
// tools side-by-side sees consistent verdicts.
package walker

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/davly/cohort-walker/cohort/audit"
)

// VerifyAuditRuleTag is the R154 rule-tag stamped on the audit_row emitted by
// `verify --json`. Drift verification is a material decision (a PASS verdict
// feeds the cohort-invariant story shipped to regulators), so it earns an
// R154 audit row.
const VerifyAuditRuleTag = "R154-COHORT-DRIFT-AUDIT"

// VerifyAuditActor is the fixed actor recorded on the verify audit row.
const VerifyAuditActor = "cohort-walker"

// Stable CI exit codes. CHANGING THESE BREAKS DOWNSTREAM AUTOMATION.
// Numbering mirrors lore-mark-verify + cohort-map (see README "Exit codes").
const (
	ExitOK            = 0
	ExitDriftFail     = 1
	ExitDriftWarn     = 2 // only emitted in --strict mode; default treats WARN as OK
	ExitStaleBaseline = 3
	ExitKAT1Drift     = 5 // kat-1-check recompute diverged from the pinned anchor
	ExitUsage         = 6 // bad / missing flag or unknown subcommand
	ExitInternal      = 9
)

// CIConfig drives the verify command.
type CIConfig struct {
	StrictWarn   bool // promote WARN to fail
	JSON         bool // emit the structured CIResult instead of the human verdict line
	Roots        []string
	BaselinePath string
}

// CIResult is the structured output for the JSON ci sub-mode.
type CIResult struct {
	ExitCode int       `json:"exit_code"`
	Summary  Summary   `json:"summary"`
	Audit    audit.Row `json:"audit_row"`
}

// VerifyCI reads the baseline, scans, diffs, prints the chosen format,
// and returns the exit code. With cfg.JSON it emits the structured CIResult
// (exit_code + summary + R154 audit_row); otherwise the single-line human
// verdict.
func VerifyCI(cfg CIConfig, baseline *Snapshot, current *Snapshot, stdout io.Writer) int {
	rep := Diff(baseline, current)

	// Decision: exit 1 on any FAIL; exit 2 on any WARN under StrictWarn.
	exit := ExitOK
	switch {
	case rep.Summary.HasFail():
		exit = ExitDriftFail
	case cfg.StrictWarn && rep.Summary.Warn > 0:
		exit = ExitDriftWarn
	}

	if cfg.JSON {
		// Machine-readable structured verdict. Errors writing JSON are
		// ignored for the same reason the human Fprintf below ignores them:
		// VerifyCI's return value is the drift verdict, not an IO status.
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(buildCIResult(cfg, rep, exit, current))
		return exit
	}

	// Print a single-line human verdict so a CI log scrubber can see
	// what happened without reading the full markdown report.
	fmt.Fprintf(stdout, "cohort-walker verify: fail=%d warn=%d info=%d pass=%d → exit %d\n",
		rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Info, rep.Summary.Pass, exit)

	return exit
}

// buildCIResult assembles the structured verify verdict. The audit_row's
// captured_at is taken from the current snapshot's CapturedAt (which already
// honours SOURCE_DATE_EPOCH / --no-timestamp), so the JSON is byte-identical
// run-to-run for a fixed FS + clock input — the same determinism contract as
// scan. Subject is the baseline path when known, else "cohort".
func buildCIResult(cfg CIConfig, rep *DiffReport, exit int, current *Snapshot) CIResult {
	subject := cfg.BaselinePath
	if subject == "" {
		subject = "cohort"
	}
	var capturedAt time.Time
	if current != nil {
		capturedAt = current.CapturedAt
	}
	reason := fmt.Sprintf("fail=%d warn=%d info=%d pass=%d",
		rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Info, rep.Summary.Pass)
	return CIResult{
		ExitCode: exit,
		Summary:  rep.Summary,
		Audit:    audit.NewRowAt(VerifyAuditRuleTag, VerifyAuditActor, subject, Outcome(exit), reason, capturedAt),
	}
}

// Outcome converts an exit code to an audit.Outcome enum.
func Outcome(exitCode int) audit.Outcome {
	switch exitCode {
	case ExitOK:
		return audit.OutcomePass
	case ExitDriftFail, ExitDriftWarn, ExitStaleBaseline:
		return audit.OutcomeFail
	default:
		return audit.OutcomeSkip
	}
}
