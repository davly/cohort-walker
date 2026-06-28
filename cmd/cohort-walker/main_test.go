package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davly/cohort-walker/internal/walker"
)

// --- CLI dispatch (uplift #24) ----------------------------------------------

func TestCLI_NoArgs_IsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != walker.ExitUsage {
		t.Fatalf("no-args want exit %d, got %d", walker.ExitUsage, code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Fatalf("usage text missing from stderr: %q", errb.String())
	}
}

func TestCLI_UnknownSubcommand_IsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errb); code != walker.ExitUsage {
		t.Fatalf("unknown subcommand want exit %d, got %d", walker.ExitUsage, code)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Fatalf("missing unknown-subcommand message: %q", errb.String())
	}
}

func TestCLI_Help_IsOK(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, &out, &errb); code != walker.ExitOK {
		t.Fatalf("--help want exit %d, got %d", walker.ExitOK, code)
	}
	if !strings.Contains(out.String(), "cohort-walker") {
		t.Fatalf("help output missing banner: %q", out.String())
	}
}

func TestCLI_KAT1Check_IsOK(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"kat-1-check"}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("kat-1-check want exit %d, got %d (out=%q)", walker.ExitOK, code, out.String())
	}
	if !strings.Contains(out.String(), "OK") || !strings.Contains(out.String(), walker.CanonicalKAT1Hex) {
		t.Fatalf("kat-1-check output unexpected: %q", out.String())
	}
}

func TestCLI_Scan_WritesValidJSONSnapshot(t *testing.T) {
	root := mkRootWithGoMember(t)
	outFile := filepath.Join(t.TempDir(), "snap.json")
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--out", outFile, "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("scan want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	f, err := os.Open(outFile)
	if err != nil {
		t.Fatalf("snapshot file not written: %v", err)
	}
	defer f.Close()
	snap, err := walker.LoadSnapshot(f)
	if err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.SchemaVersion != walker.SchemaVersion {
		t.Fatalf("snapshot schema mismatch: %q", snap.SchemaVersion)
	}
	if len(snap.Members) != 1 || snap.Members[0].Name != "alpha" {
		t.Fatalf("expected one member 'alpha', got %+v", snap.Members)
	}
}

func TestCLI_Scan_StdoutWhenNoOut(t *testing.T) {
	root := mkRootWithGoMember(t)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("scan want exit %d, got %d", walker.ExitOK, code)
	}
	if !strings.Contains(out.String(), walker.SchemaVersion) {
		t.Fatalf("scan stdout is not the snapshot JSON: %q", out.String())
	}
}

// TestCLI_Scan_NoTimestamp_ByteIdentical is the det-gate-shaped proof for the
// B4 uplift: it runs `scan --no-timestamp` over an unchanged fixture TWICE (the
// same way workshop/scripts/det-gate.sh runs each covered tool) and asserts the
// two outputs are byte-identical. It also asserts captured_at is suppressed to
// the zero sentinel, proving the flag is wired through the CLI to walker.Scan.
func TestCLI_Scan_NoTimestamp_ByteIdentical(t *testing.T) {
	root := mkRootWithGoMember(t)
	flagships := filepath.Join(root, "flagships")
	runScan := func() []byte {
		t.Helper()
		var out, errb bytes.Buffer
		code := run([]string{"scan", "--no-timestamp", "--roots", flagships}, &out, &errb)
		if code != walker.ExitOK {
			t.Fatalf("scan --no-timestamp want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
		}
		return out.Bytes()
	}
	a := runScan()
	b := runScan()
	if !bytes.Equal(a, b) {
		t.Fatalf("scan --no-timestamp must be byte-identical across runs;\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
	snap, err := walker.LoadSnapshot(bytes.NewReader(a))
	if err != nil {
		t.Fatalf("snapshot invalid: %v", err)
	}
	if !snap.CapturedAt.IsZero() {
		t.Fatalf("--no-timestamp must zero captured_at; got %v", snap.CapturedAt)
	}
}

// TestCLI_Scan_FiresLoudOnceOnDegradation covers the R143 LoudOnce wiring: a
// docs-only member resolves to substrate=unknown, which must fire exactly one
// structured stderr warning carrying the audit-rule discriminator.
func TestCLI_Scan_FiresLoudOnceOnDegradation(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "flagships", "docsonly", "README.md"), "# docs only\n")
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("scan want exit %d, got %d", walker.ExitOK, code)
	}
	if !strings.Contains(errb.String(), "LOUD-ONCE-WARNING") ||
		!strings.Contains(errb.String(), "R143_LOUD_ONCE_WARNING_FLAG") {
		t.Fatalf("expected R143 LoudOnce warning on degradation; stderr=%q", errb.String())
	}
}

func TestCLI_Diff_MissingFlags_IsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"diff", "--baseline", "only-one.json"}, &out, &errb); code != walker.ExitUsage {
		t.Fatalf("diff with one flag want exit %d, got %d", walker.ExitUsage, code)
	}
}

// --- firewall exit-3 path (uplift #24) --------------------------------------

func TestCLI_Verify_StaleZeroTimeBaseline_Exit3(t *testing.T) {
	root := mkRootWithGoMember(t)
	baseline := filepath.Join(t.TempDir(), "zero.json")
	mustWrite(t, baseline,
		`{"schema_version":"cohort-walker.v1","captured_at":"0001-01-01T00:00:00Z","roots":[],"members":[]}`)
	var out, errb bytes.Buffer
	code := run([]string{"verify", "--baseline", baseline, "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitStaleBaseline {
		t.Fatalf("zero-time baseline want exit %d, got %d (err=%q)", walker.ExitStaleBaseline, code, errb.String())
	}
	if !strings.Contains(errb.String(), "captured_at is zero") {
		t.Fatalf("expected zero-time stale reason; stderr=%q", errb.String())
	}
}

func TestCLI_Verify_BadSchemaBaseline_Exit3(t *testing.T) {
	root := mkRootWithGoMember(t)
	baseline := filepath.Join(t.TempDir(), "badschema.json")
	mustWrite(t, baseline,
		`{"schema_version":"cohort-walker.v0","captured_at":"2026-06-20T00:00:00Z","roots":[],"members":[]}`)
	var out, errb bytes.Buffer
	code := run([]string{"verify", "--baseline", baseline, "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitStaleBaseline {
		t.Fatalf("bad-schema baseline want exit %d, got %d (err=%q)", walker.ExitStaleBaseline, code, errb.String())
	}
	if !strings.Contains(errb.String(), "schema version unrecognised") {
		t.Fatalf("expected unknown-schema reason; stderr=%q", errb.String())
	}
}

func TestCLI_Verify_MissingBaseline_Exit3(t *testing.T) {
	root := mkRootWithGoMember(t)
	baseline := filepath.Join(t.TempDir(), "does-not-exist.json")
	var out, errb bytes.Buffer
	code := run([]string{"verify", "--baseline", baseline, "--roots", filepath.Join(root, "flagships")}, &out, &errb)
	if code != walker.ExitStaleBaseline {
		t.Fatalf("missing baseline want exit %d, got %d (err=%q)", walker.ExitStaleBaseline, code, errb.String())
	}
	if !strings.Contains(errb.String(), "does not exist") {
		t.Fatalf("expected missing-file reason; stderr=%q", errb.String())
	}
}

func TestCLI_Verify_MissingBaselineFlag_IsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify"}, &out, &errb); code != walker.ExitUsage {
		t.Fatalf("verify with no --baseline want exit %d, got %d", walker.ExitUsage, code)
	}
}

// TestCLI_Verify_FreshBaseline_Exit0 round-trips: scan to a baseline, then
// verify the same roots against it. A just-captured baseline is not stale and
// the tree is unchanged, so the gate passes (exit 0).
func TestCLI_Verify_FreshBaseline_Exit0(t *testing.T) {
	// Scan now honors SOURCE_DATE_EPOCH (B4); clear any ambient value so the
	// freshly-captured baseline uses the wall clock and is genuinely fresh
	// rather than an epoch-pinned (and thus stale) timestamp.
	t.Setenv("SOURCE_DATE_EPOCH", "")
	root := mkRootWithGoMember(t)
	flagships := filepath.Join(root, "flagships")
	baseline := filepath.Join(t.TempDir(), "fresh.json")
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--out", baseline, "--roots", flagships}, &out, &errb); code != walker.ExitOK {
		t.Fatalf("baseline scan failed: exit %d err=%q", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	code := run([]string{"verify", "--baseline", baseline, "--roots", flagships}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("fresh-baseline verify want exit %d, got %d (out=%q err=%q)",
			walker.ExitOK, code, out.String(), errb.String())
	}
}

// --- helpers ----------------------------------------------------------------

// mkRootWithGoMember builds <tmp>/flagships/alpha as a minimal Go cohort
// member and returns the <tmp> root.
func mkRootWithGoMember(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "flagships", "alpha", "go.mod"), "module example.com/alpha\ngo 1.22\n")
	mustWrite(t, filepath.Join(root, "flagships", "alpha", "a.go"), "package a\n")
	return root
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
