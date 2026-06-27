// ci.go — CI exit-code adapter. The GitHub Actions workflow template
// calls `cohort-walker verify` which runs Scan + Diff against the
// stored baseline and exits with one of these stable codes. Numbering
// mirrors lore-mark-verify + cohort-map so a regulator running multiple
// tools side-by-side sees consistent verdicts.
package walker

import (
	"fmt"
	"io"

	"github.com/davly/cohort-walker/cohort/audit"
)

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
// and returns the exit code.
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

	// Print a single-line human verdict so a CI log scrubber can see
	// what happened without reading the full markdown report.
	fmt.Fprintf(stdout, "cohort-walker verify: fail=%d warn=%d info=%d pass=%d → exit %d\n",
		rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Info, rep.Summary.Pass, exit)

	return exit
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
