package walker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/davly/cohort-walker/cohort/audit"
)

// ci_test.go covers cw-verify-json-audit: `verify --json` must surface the
// previously-built-but-unwired CIResult (exit_code + summary + R154 audit_row)
// from VerifyCI, and the human verdict line must still be the default.

// TestVerifyCI_JSON_EmitsCIResult drives a marker-loss snapshot pair through
// VerifyCI with JSON enabled and asserts the full CIResult shape: the exit code
// matches the FAIL verdict, the summary carries the FAIL, and the R154
// audit_row pins the rule-tag / actor / subject / outcome.
func TestVerifyCI_JSON_EmitsCIResult(t *testing.T) {
	// gamma loses the loud_once marker between snapshots -> a marker_lost FAIL.
	prev := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{HasLoudOnceWiring: true}},
	}}
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{}},
	}}

	var buf bytes.Buffer
	code := VerifyCI(CIConfig{JSON: true, BaselinePath: "base.json"}, prev, cur, &buf)
	if code != ExitDriftFail {
		t.Fatalf("marker_lost must drive ExitDriftFail (%d); got %d", ExitDriftFail, code)
	}

	var got CIResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("verify --json output is not valid CIResult JSON: %v\nbody=%s", err, buf.String())
	}
	if got.ExitCode != ExitDriftFail {
		t.Fatalf("CIResult.exit_code want %d, got %d", ExitDriftFail, got.ExitCode)
	}
	if got.Summary.Fail < 1 {
		t.Fatalf("CIResult.summary.fail must be >=1; got %+v", got.Summary)
	}
	if got.Audit.RuleTag != VerifyAuditRuleTag {
		t.Fatalf("audit_row.rule_tag want %q, got %q", VerifyAuditRuleTag, got.Audit.RuleTag)
	}
	if got.Audit.Actor != VerifyAuditActor {
		t.Fatalf("audit_row.actor want %q, got %q", VerifyAuditActor, got.Audit.Actor)
	}
	if got.Audit.Subject != "base.json" {
		t.Fatalf("audit_row.subject want baseline path, got %q", got.Audit.Subject)
	}
	if got.Audit.Outcome != audit.OutcomeFail {
		t.Fatalf("audit_row.outcome want FAIL, got %q", got.Audit.Outcome)
	}
	// captured_at is taken from the current snapshot (deterministic).
	if !got.Audit.CapturedAt.Equal(fixedTime()) {
		t.Fatalf("audit_row.captured_at want %v (current snapshot), got %v", fixedTime(), got.Audit.CapturedAt)
	}
	// The raw JSON must carry the documented field name.
	if !strings.Contains(buf.String(), `"audit_row"`) {
		t.Fatalf("structured output missing audit_row field:\n%s", buf.String())
	}
}

// TestVerifyCI_JSON_CleanOutcomeAndSubjectDefault confirms a clean (PASS) run
// emits exit 0 with a PASS audit row, and that an empty BaselinePath falls back
// to the "cohort" subject.
func TestVerifyCI_JSON_CleanOutcomeAndSubjectDefault(t *testing.T) {
	m := Member{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}}
	prev := &Snapshot{CapturedAt: fixedTime(), Members: []Member{m}}
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{m}}

	var buf bytes.Buffer
	code := VerifyCI(CIConfig{JSON: true}, prev, cur, &buf)
	if code != ExitOK {
		t.Fatalf("clean verify want ExitOK (%d); got %d", ExitOK, code)
	}
	var got CIResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid CIResult JSON: %v\nbody=%s", err, buf.String())
	}
	if got.Audit.Outcome != audit.OutcomePass {
		t.Fatalf("clean run audit outcome want PASS, got %q", got.Audit.Outcome)
	}
	if got.Audit.Subject != "cohort" {
		t.Fatalf("empty BaselinePath must default subject to %q, got %q", "cohort", got.Audit.Subject)
	}
}

// TestVerifyCI_JSON_Deterministic proves the structured output is byte-identical
// across two runs over the same snapshots (the HARD determinism contract).
func TestVerifyCI_JSON_Deterministic(t *testing.T) {
	prev := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}},
	}}
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{}},
	}}
	var a, b bytes.Buffer
	VerifyCI(CIConfig{JSON: true, BaselinePath: "base.json"}, prev, cur, &a)
	VerifyCI(CIConfig{JSON: true, BaselinePath: "base.json"}, prev, cur, &b)
	if a.String() != b.String() {
		t.Fatalf("verify --json must be byte-identical run-to-run:\nA=%s\nB=%s", a.String(), b.String())
	}
}

// TestVerifyCI_DefaultStillHumanLine guards the non-JSON default: the
// single-line human verdict (not JSON) is emitted when cfg.JSON is false.
func TestVerifyCI_DefaultStillHumanLine(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "gamma", Cohort: "flagships", Markers: Markers{KAT1HexPinned: true}}}}
	cur := &Snapshot{Members: []Member{{Name: "gamma", Cohort: "flagships", Markers: Markers{}}}}
	var buf bytes.Buffer
	VerifyCI(CIConfig{}, prev, cur, &buf)
	if !strings.HasPrefix(buf.String(), "cohort-walker verify: fail=") {
		t.Fatalf("default mode must emit the human verdict line; got %q", buf.String())
	}
	if strings.Contains(buf.String(), `"audit_row"`) {
		t.Fatalf("default mode must NOT emit JSON; got %q", buf.String())
	}
}
