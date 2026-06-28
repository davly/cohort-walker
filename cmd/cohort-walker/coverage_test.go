package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davly/cohort-walker/internal/walker"
)

// coverage_test.go closes the CLI/verdict-layer gaps named in cw-cli-coverage:
// cmdReport (markdown + census render), cmdDiff (machine-readable JSON delta +
// its error paths), the end-to-end marker_lost / marker_gained verify exit
// codes (marker_lost MUST exit non-zero), and the --roots resolution layer
// (resolveRoots / defaultEcosystemBase). All tests drive run() (or the
// unexported resolvers) over temp fixtures; none touch the live tree.

// freshBaselineJSON builds a schema-valid snapshot file body with a fresh
// captured_at (1h ago) so the verify staleness firewall passes. members is the
// raw JSON for the "members" array contents.
func freshBaselineJSON(members string) string {
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	return fmt.Sprintf(`{"schema_version":%q,"captured_at":%q,"roots":[],"members":[%s]}`,
		walker.SchemaVersion, ts, members)
}

// --- cmdReport --------------------------------------------------------------

// TestCLI_Report_RendersMarkdownWithCensus drives `report` end-to-end over a
// temp fixture and asserts the markdown body, the cohort-census table, and the
// mandatory liability footer are all present. The baseline matches the scanned
// member exactly, so the deltas section reports no drift.
func TestCLI_Report_RendersMarkdownWithCensus(t *testing.T) {
	root := mkRootWithGoMember(t)
	flagships := filepath.Join(root, "flagships")
	baseline := filepath.Join(t.TempDir(), "base.json")
	mustWrite(t, baseline, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{}}`))
	outFile := filepath.Join(t.TempDir(), "report.md")

	var out, errb bytes.Buffer
	code := run([]string{"report", "--baseline", baseline, "--out", outFile, "--roots", flagships}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("report want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	body := readFile(t, outFile)
	for _, want := range []string{
		"# cohort-walker drift report",
		"## Cohort census (current snapshot)",
		"| flagships | go | 1 |", // alpha is the sole flagships/go member
		"NOT LEGAL ADVICE",       // R166 liability footer
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("report markdown missing %q:\n%s", want, body)
		}
	}
	// Baseline equals the scanned member, so no drift.
	if !strings.Contains(body, "_No drift detected._") {
		t.Fatalf("expected no-drift marker; report:\n%s", body)
	}
}

// TestCLI_Report_StdoutWhenNoOut covers the default-to-stdout branch of
// cmdReport / openOut.
func TestCLI_Report_StdoutWhenNoOut(t *testing.T) {
	root := mkRootWithGoMember(t)
	baseline := filepath.Join(t.TempDir(), "base.json")
	mustWrite(t, baseline, freshBaselineJSON(""))

	var out, errb bytes.Buffer
	code := run([]string{"report", "--baseline", baseline, "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("report want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	if !strings.Contains(out.String(), "# cohort-walker drift report") {
		t.Fatalf("report stdout is not the markdown body: %q", out.String())
	}
}

func TestCLI_Report_MissingBaselineFlag_IsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"report"}, &out, &errb); code != walker.ExitUsage {
		t.Fatalf("report with no --baseline want exit %d, got %d", walker.ExitUsage, code)
	}
	if !strings.Contains(errb.String(), "--baseline is required") {
		t.Fatalf("missing required-baseline message: %q", errb.String())
	}
}

// TestCLI_Report_BadBaselineFile_IsInternalError covers the load-failure path
// (cmdReport returns ExitInternal when the baseline cannot be opened/parsed).
func TestCLI_Report_BadBaselineFile_IsInternalError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	var out, errb bytes.Buffer
	if code := run([]string{"report", "--baseline", missing, "--roots", t.TempDir()}, &out, &errb); code != walker.ExitInternal {
		t.Fatalf("report with unreadable baseline want exit %d, got %d (err=%q)", walker.ExitInternal, code, errb.String())
	}
}

// --- cmdDiff ----------------------------------------------------------------

// TestCLI_Diff_EmitsMarkerLostJSON covers the cmdDiff happy path AND the
// machine-readable marker_lost classification: two snapshot files where the
// current lost a non-KAT marker must emit a JSON delta of kind marker_lost
// severity FAIL with summary.fail >= 1, and exit 0 (diff is a producer, not a
// gate — the FAIL is carried in the payload for a downstream consumer).
func TestCLI_Diff_EmitsMarkerLostJSON(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "base.json")
	current := filepath.Join(dir, "cur.json")
	mustWrite(t, baseline, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{"has_loud_once_wiring":true}}`))
	mustWrite(t, current, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{}}`))

	var out, errb bytes.Buffer
	code := run([]string{"diff", "--baseline", baseline, "--current", current}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("diff want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	var payload struct {
		Deltas  []walker.Delta `json:"deltas"`
		Summary walker.Summary `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("diff output is not valid JSON: %v\nbody=%s", err, out.String())
	}
	var found *walker.Delta
	for i := range payload.Deltas {
		if payload.Deltas[i].Kind == walker.DeltaMarkerLost {
			found = &payload.Deltas[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a marker_lost delta in JSON; got %+v", payload.Deltas)
	}
	if found.Severity != walker.SeverityFail {
		t.Fatalf("marker_lost must be FAIL; got %s", found.Severity)
	}
	if payload.Summary.Fail < 1 {
		t.Fatalf("summary.fail must be >=1 for a marker_lost; got %+v", payload.Summary)
	}
}

func TestCLI_Diff_BadBaselineFile_IsInternalError(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := run([]string{"diff",
		"--baseline", filepath.Join(dir, "no-base.json"),
		"--current", filepath.Join(dir, "no-cur.json")}, &out, &errb)
	if code != walker.ExitInternal {
		t.Fatalf("diff with unreadable baseline want exit %d, got %d", walker.ExitInternal, code)
	}
	if !strings.Contains(errb.String(), "baseline:") {
		t.Fatalf("expected baseline-load error; stderr=%q", errb.String())
	}
}

func TestCLI_Diff_BadCurrentFile_IsInternalError(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "base.json")
	mustWrite(t, baseline, freshBaselineJSON(""))
	var out, errb bytes.Buffer
	code := run([]string{"diff",
		"--baseline", baseline,
		"--current", filepath.Join(dir, "no-cur.json")}, &out, &errb)
	if code != walker.ExitInternal {
		t.Fatalf("diff with unreadable current want exit %d, got %d", walker.ExitInternal, code)
	}
	if !strings.Contains(errb.String(), "current:") {
		t.Fatalf("expected current-load error; stderr=%q", errb.String())
	}
}

// --- verify: marker_lost / marker_gained end-to-end exit codes --------------

// TestCLI_Verify_MarkerLost_ExitFail is the end-to-end "marker_lost must exit
// non-zero" guarantee: a fresh baseline pins a non-KAT marker that the current
// scanned tree no longer exposes, so verify must return ExitDriftFail (1) even
// in lenient (non-strict) mode.
func TestCLI_Verify_MarkerLost_ExitFail(t *testing.T) {
	root := mkRootWithGoMember(t) // flagships/alpha with go.mod + plain a.go (no markers)
	flagships := filepath.Join(root, "flagships")
	baseline := filepath.Join(t.TempDir(), "base.json")
	mustWrite(t, baseline, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{"has_loud_once_wiring":true}}`))

	var out, errb bytes.Buffer
	code := run([]string{"verify", "--baseline", baseline, "--roots", flagships}, &out, &errb)
	if code != walker.ExitDriftFail {
		t.Fatalf("marker_lost verify want exit %d, got %d (out=%q err=%q)",
			walker.ExitDriftFail, code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "fail=1") {
		t.Fatalf("expected fail=1 in verdict line; out=%q", out.String())
	}
}

// TestCLI_Verify_MarkerGained_ExitOK is the inverse: the current tree exposes a
// marker the baseline lacked (a PASS-class improvement), so verify stays at
// ExitOK even under --strict.
func TestCLI_Verify_MarkerGained_ExitOK(t *testing.T) {
	root := t.TempDir()
	flagships := filepath.Join(root, "flagships")
	// alpha's source exposes the LoudOnce marker.
	mustWrite(t, filepath.Join(flagships, "alpha", "go.mod"), "module example.com/alpha\ngo 1.22\n")
	mustWrite(t, filepath.Join(flagships, "alpha", "a.go"), "package a\n// LoudOnce wired here\n")
	baseline := filepath.Join(t.TempDir(), "base.json")
	mustWrite(t, baseline, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{}}`))

	var out, errb bytes.Buffer
	code := run([]string{"verify", "--strict", "--baseline", baseline, "--roots", flagships}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("marker_gained verify want exit %d, got %d (out=%q err=%q)",
			walker.ExitOK, code, out.String(), errb.String())
	}
}

// --- verify --json (cw-verify-json-audit) -----------------------------------

// TestCLI_Verify_JSON_EmitsCIResult is the end-to-end wiring proof for
// `verify --json`: the marker_lost run must print the structured CIResult
// (exit_code + summary + R154 audit_row) to stdout and exit non-zero.
func TestCLI_Verify_JSON_EmitsCIResult(t *testing.T) {
	root := mkRootWithGoMember(t) // flagships/alpha with go.mod + plain a.go (no markers)
	flagships := filepath.Join(root, "flagships")
	baseline := filepath.Join(t.TempDir(), "base.json")
	mustWrite(t, baseline, freshBaselineJSON(
		`{"name":"alpha","path":"x","cohort":"flagships","substrate":"go","markers":{"has_loud_once_wiring":true}}`))

	var out, errb bytes.Buffer
	code := run([]string{"verify", "--json", "--baseline", baseline, "--roots", flagships}, &out, &errb)
	if code != walker.ExitDriftFail {
		t.Fatalf("verify --json marker_lost want exit %d, got %d (out=%q err=%q)",
			walker.ExitDriftFail, code, out.String(), errb.String())
	}
	var got struct {
		ExitCode int            `json:"exit_code"`
		Summary  walker.Summary `json:"summary"`
		Audit    struct {
			RuleTag string `json:"rule_tag"`
			Actor   string `json:"actor"`
			Outcome string `json:"outcome"`
		} `json:"audit_row"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("verify --json output is not valid JSON: %v\nbody=%s", err, out.String())
	}
	if got.ExitCode != walker.ExitDriftFail {
		t.Fatalf("exit_code want %d, got %d", walker.ExitDriftFail, got.ExitCode)
	}
	if got.Summary.Fail < 1 {
		t.Fatalf("summary.fail must be >=1; got %+v", got.Summary)
	}
	if got.Audit.RuleTag != walker.VerifyAuditRuleTag {
		t.Fatalf("audit_row.rule_tag want %q, got %q", walker.VerifyAuditRuleTag, got.Audit.RuleTag)
	}
	if got.Audit.Outcome != "FAIL" {
		t.Fatalf("audit_row.outcome want FAIL, got %q", got.Audit.Outcome)
	}
	// The default human verdict line must NOT be present under --json.
	if strings.Contains(out.String(), "cohort-walker verify: fail=") {
		t.Fatalf("--json must suppress the human verdict line; out=%q", out.String())
	}
}

// --- --roots resolution -----------------------------------------------------

func TestResolveRoots_CommaSeparated_TrimsAndSkipsEmpty(t *testing.T) {
	got := resolveRoots(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("root %d: want %q, got %q (full=%v)", i, want[i], got[i], got)
		}
	}
}

func TestResolveRoots_DefaultLayout_UsesLimitlessRoot(t *testing.T) {
	base := filepath.Join(t.TempDir(), "eco")
	t.Setenv("LIMITLESS_ROOT", base)
	got := resolveRoots("")
	want := []string{
		filepath.Join(base, "flagships"),
		filepath.Join(base, "infrastructure"),
		filepath.Join(base, "engines"),
		filepath.Join(base, "foundation"),
	}
	if len(got) != len(want) {
		t.Fatalf("want 4 roots %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("root %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

// TestResolveRoots_DefaultLayout_NoEnv asserts the separator-relative default
// (no LIMITLESS_ROOT): a "<sep>limitless/<cohort>" layout with NO hardcoded
// drive letter, so the binary resolves identically on every OS.
func TestResolveRoots_DefaultLayout_NoEnv(t *testing.T) {
	t.Setenv("LIMITLESS_ROOT", "") // empty -> falls through to separator-relative default
	got := resolveRoots("")
	if len(got) != 4 {
		t.Fatalf("want 4 default roots, got %v", got)
	}
	wantBase := string(filepath.Separator) + "limitless"
	for i, c := range []string{"flagships", "infrastructure", "engines", "foundation"} {
		want := filepath.Join(wantBase, c)
		if got[i] != want {
			t.Fatalf("root %d: want %q, got %q", i, want, got[i])
		}
		// No hardcoded drive letter at any level (cross-platform invariant).
		if strings.Contains(got[i], ":") {
			t.Fatalf("default root must not embed a drive letter; got %q", got[i])
		}
	}
}

// TestResolveRoots_WhitespaceFlag_FallsToDefault confirms a blank/whitespace
// --roots is treated as "unset" and falls through to the default layout.
func TestResolveRoots_WhitespaceFlag_FallsToDefault(t *testing.T) {
	t.Setenv("LIMITLESS_ROOT", filepath.Join(t.TempDir(), "eco"))
	if got := resolveRoots("    "); len(got) != 4 {
		t.Fatalf("whitespace --roots should fall to the 4-root default; got %v", got)
	}
}

// TestCLI_Scan_MultipleRoots exercises the comma-separated --roots split
// through run(): members from two distinct cohort roots must both appear.
func TestCLI_Scan_MultipleRoots(t *testing.T) {
	root := t.TempDir()
	flagships := filepath.Join(root, "flagships")
	engines := filepath.Join(root, "engines")
	mustWrite(t, filepath.Join(flagships, "alpha", "go.mod"), "module example.com/alpha\ngo 1.22\n")
	mustWrite(t, filepath.Join(engines, "beta", "Cargo.toml"), "[package]\nname=\"beta\"\nversion=\"0\"\nedition=\"2021\"\n")
	mustWrite(t, filepath.Join(engines, "beta", "src", "lib.rs"), "// no markers\n")

	var out, errb bytes.Buffer
	code := run([]string{"scan", "--roots", flagships + "," + engines}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("scan multi-root want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	snap, err := walker.LoadSnapshot(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("snapshot invalid: %v", err)
	}
	if len(snap.Members) != 2 {
		t.Fatalf("want 2 members across two roots, got %d: %+v", len(snap.Members), snap.Members)
	}
	byCohort := map[string]walker.Member{}
	for _, m := range snap.Members {
		byCohort[m.Cohort] = m
	}
	if a, ok := byCohort["flagships"]; !ok || a.Name != "alpha" || a.Substrate != walker.SubstrateGo {
		t.Fatalf("flagships/alpha (go) missing: %+v", snap.Members)
	}
	if b, ok := byCohort["engines"]; !ok || b.Name != "beta" || b.Substrate != walker.SubstrateRust {
		t.Fatalf("engines/beta (rust) missing: %+v", snap.Members)
	}
}

// readFile is a small test helper for asserting on rendered file output.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
