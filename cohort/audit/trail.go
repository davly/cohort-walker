// Package audit hosts the R154 R-ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION
// audit-trail row shape for cohort-walker.
//
// R154 requires every flagship that interacts with regulated data classes
// (or in cohort-walker's case, regulated-cohort-membership claims) to emit
// an audit row per material decision. Drift detection IS a material
// decision: a "PASS" verdict on a flagship contributes to the cohort
// invariant story shipped to regulators; a stale or wrong PASS is a
// downstream-impact risk.
//
// Each Row is byte-identical-shape across the cohort: rule-tag +
// timestamp + actor + subject + outcome + optional reason. Outcome is
// constrained to the R115 single-enum rejection-outcome trio so an audit
// reader does not face ad-hoc string verdicts.
package audit

import "time"

// Outcome is constrained to R115's three-state enum.
type Outcome string

const (
	OutcomePass Outcome = "PASS"
	OutcomeFail Outcome = "FAIL"
	OutcomeSkip Outcome = "SKIP"
)

// Row is the canonical audit-trail row.
type Row struct {
	RuleTag    string    `json:"rule_tag"`
	CapturedAt time.Time `json:"captured_at"`
	Actor      string    `json:"actor"`
	Subject    string    `json:"subject"`
	Outcome    Outcome   `json:"outcome"`
	Reason     string    `json:"reason,omitempty"`
}

// NewRow constructs an audit row with the current-clock timestamp. Tests
// use NewRowAt to inject a clock.
func NewRow(ruleTag, actor, subject string, outcome Outcome, reason string) Row {
	return NewRowAt(ruleTag, actor, subject, outcome, reason, time.Now().UTC())
}

// NewRowAt is the clock-injected constructor used by tests.
func NewRowAt(ruleTag, actor, subject string, outcome Outcome, reason string, at time.Time) Row {
	return Row{
		RuleTag:    ruleTag,
		CapturedAt: at.UTC(),
		Actor:      actor,
		Subject:    subject,
		Outcome:    outcome,
		Reason:     reason,
	}
}
