// Command cohort-walker is the CLI front-end for the cohort-walker drift
// engine. It wires the scan / verify / report / diff / kat-1-check
// subsystems (internal/walker) plus the three cohort guards that were built
// and tested but previously had no caller:
//
//   - the R150 staleness firewall (cohort/firewall) — verify exits 3 when the
//     baseline snapshot is stale (zero / future / beyond-horizon captured_at,
//     or a missing baseline file);
//   - the schema-version guard — verify exits 3 when the baseline's
//     schema_version does not match the current SchemaVersion (firewall's
//     StaleReasonUnknownSchema);
//   - the R143 LoudOnce warning (cohort/observability) — a single structured
//     stderr line is fired when a scan degrades (any member resolves to
//     substrate=unknown).
//
// The binary is pure-stdlib (flag, not cobra) to preserve the cohort
// canonical zero-non-stdlib posture documented in CONTEXT.md. All JSON output
// is machine-readable and deterministic (members are pre-sorted by Scan; the
// structs encode in field-declaration order; no maps are serialised).
//
// Roots are cross-platform: --roots takes a comma-separated list, else
// $LIMITLESS_ROOT joined with the four cohort dir names, else a separator-
// relative "<sep>limitless/{flagships,infrastructure,engines,foundation}"
// default that contains no hardcoded drive letter.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davly/cohort-walker/cohort/firewall"
	"github.com/davly/cohort-walker/cohort/identity"
	"github.com/davly/cohort-walker/cohort/observability"
	"github.com/davly/cohort-walker/internal/walker"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it returns an exit code instead of
// calling os.Exit so tests can drive the dispatch directly.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return walker.ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return cmdScan(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "report":
		return cmdReport(rest, stdout, stderr)
	case "diff":
		return cmdDiff(rest, stdout, stderr)
	case "kat-1-check":
		return cmdKAT1Check(rest, stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return walker.ExitOK
	default:
		fmt.Fprintf(stderr, "cohort-walker: unknown subcommand %q\n\n", cmd)
		printUsage(stderr)
		return walker.ExitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `cohort-walker — cohort drift detector

Usage:
  cohort-walker scan        [--out FILE] [--roots A,B,C]
  cohort-walker verify      --baseline FILE [--strict] [--roots A,B,C] [--horizon DUR]
  cohort-walker report      --baseline FILE [--out FILE] [--roots A,B,C]
  cohort-walker diff        --baseline FILE --current FILE
  cohort-walker kat-1-check

Roots default to $LIMITLESS_ROOT/{flagships,infrastructure,engines,foundation}
when --roots is omitted (cross-platform; no hardcoded drive letter).

Exit codes (mirror lore-mark-verify + cohort-map):
  0 OK · 1 drift FAIL · 2 drift WARN (--strict) · 3 stale baseline
  5 KAT-1 drift · 6 usage · 9 internal error
`)
}

// cmdScan walks the roots and writes a snapshot (JSON) to --out or stdout.
func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write snapshot JSON to this file (default: stdout)")
	rootsFlag := fs.String("roots", "", "comma-separated cohort roots (default: $LIMITLESS_ROOT layout)")
	if err := fs.Parse(args); err != nil {
		return walker.ExitUsage
	}
	snap, err := walker.Scan(walker.ScanOptions{Roots: resolveRoots(*rootsFlag)})
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker scan: %v\n", err)
		return walker.ExitInternal
	}
	warnOnDegradation(snap, stderr)
	if err := writeSnapshot(*out, snap, stdout); err != nil {
		fmt.Fprintf(stderr, "cohort-walker scan: %v\n", err)
		return walker.ExitInternal
	}
	return walker.ExitOK
}

// cmdVerify scans current, diffs against the baseline, and returns the CI
// exit code. The staleness firewall and schema-version guard run BEFORE the
// scan and short-circuit to exit 3.
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseline := fs.String("baseline", "", "path to baseline snapshot JSON (required)")
	strict := fs.Bool("strict", false, "treat WARN as failure (exit 2)")
	rootsFlag := fs.String("roots", "", "comma-separated cohort roots (default: $LIMITLESS_ROOT layout)")
	horizonFlag := fs.String("horizon", firewall.DefaultHorizon.String(), "staleness horizon (Go duration, e.g. 720h)")
	if err := fs.Parse(args); err != nil {
		return walker.ExitUsage
	}
	if strings.TrimSpace(*baseline) == "" {
		fmt.Fprintln(stderr, "cohort-walker verify: --baseline is required")
		return walker.ExitUsage
	}

	base, code := loadAndGuardBaseline(*baseline, *horizonFlag, stderr)
	if code != walker.ExitOK {
		return code
	}

	cur, err := walker.Scan(walker.ScanOptions{Roots: resolveRoots(*rootsFlag)})
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker verify: scan failed: %v\n", err)
		return walker.ExitInternal
	}
	warnOnDegradation(cur, stderr)

	cfg := walker.CIConfig{StrictWarn: *strict, BaselinePath: *baseline}
	return walker.VerifyCI(cfg, base, cur, stdout)
}

// cmdReport renders the human-readable markdown drift report. It is a render,
// not a gate, so it does not apply the staleness exit-3 short-circuit.
func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseline := fs.String("baseline", "", "path to baseline snapshot JSON (required)")
	out := fs.String("out", "", "write markdown report to this file (default: stdout)")
	rootsFlag := fs.String("roots", "", "comma-separated cohort roots (default: $LIMITLESS_ROOT layout)")
	if err := fs.Parse(args); err != nil {
		return walker.ExitUsage
	}
	if strings.TrimSpace(*baseline) == "" {
		fmt.Fprintln(stderr, "cohort-walker report: --baseline is required")
		return walker.ExitUsage
	}
	base, err := loadSnapshot(*baseline)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker report: %v\n", err)
		return walker.ExitInternal
	}
	cur, err := walker.Scan(walker.ScanOptions{Roots: resolveRoots(*rootsFlag)})
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker report: scan failed: %v\n", err)
		return walker.ExitInternal
	}
	warnOnDegradation(cur, stderr)
	rep := walker.Diff(base, cur)

	w, closeFn, err := openOut(*out, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker report: %v\n", err)
		return walker.ExitInternal
	}
	defer closeFn()
	if err := walker.RenderMarkdown(w, rep); err != nil {
		fmt.Fprintf(stderr, "cohort-walker report: %v\n", err)
		return walker.ExitInternal
	}
	return walker.ExitOK
}

// cmdDiff loads two existing snapshots and emits the machine-readable JSON
// delta to stdout. It is a pure producer (no scan, no gate).
func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseline := fs.String("baseline", "", "path to baseline snapshot JSON (required)")
	current := fs.String("current", "", "path to current snapshot JSON (required)")
	if err := fs.Parse(args); err != nil {
		return walker.ExitUsage
	}
	if strings.TrimSpace(*baseline) == "" || strings.TrimSpace(*current) == "" {
		fmt.Fprintln(stderr, "cohort-walker diff: --baseline and --current are both required")
		return walker.ExitUsage
	}
	base, err := loadSnapshot(*baseline)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker diff: baseline: %v\n", err)
		return walker.ExitInternal
	}
	cur, err := loadSnapshot(*current)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker diff: current: %v\n", err)
		return walker.ExitInternal
	}
	rep := walker.Diff(base, cur)
	if err := walker.RenderJSON(stdout, rep); err != nil {
		fmt.Fprintf(stderr, "cohort-walker diff: %v\n", err)
		return walker.ExitInternal
	}
	return walker.ExitOK
}

// cmdKAT1Check recomputes the R151 KAT-1 anchor with crypto/hmac and compares
// it byte-for-byte to the pinned constant. Exit 5 on any divergence.
func cmdKAT1Check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kat-1-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return walker.ExitUsage
	}
	h := hmac.New(sha256.New, nil) // empty key, per KAT-1
	h.Write([]byte{0x01})          // domain tag
	var zero [32]byte
	h.Write(zero[:]) // 32 NUL corpus
	got := hex.EncodeToString(h.Sum(nil))
	if got != identity.KAT1Hex || identity.KAT1Hex != walker.CanonicalKAT1Hex {
		fmt.Fprintf(stdout, "kat-1-check: FAIL recomputed=%s identity_pin=%s walker_canonical=%s\n",
			got, identity.KAT1Hex, walker.CanonicalKAT1Hex)
		return walker.ExitKAT1Drift
	}
	fmt.Fprintf(stdout, "kat-1-check: OK %s\n", got)
	return walker.ExitOK
}

// --- shared helpers ---------------------------------------------------------

// loadAndGuardBaseline opens, parses, and runs the schema-version + staleness
// guards on a baseline snapshot. It returns ExitStaleBaseline (3) on a missing
// file, schema mismatch, or stale captured_at; ExitInternal (9) on a parse
// error; ExitUsage (6) on a bad --horizon; ExitOK on success.
func loadAndGuardBaseline(path, horizonStr string, stderr io.Writer) (*walker.Snapshot, int) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker verify: %s (%v)\n", firewall.StaleReasonMissingFile, err)
		return nil, walker.ExitStaleBaseline
	}
	defer f.Close()
	base, err := walker.LoadSnapshot(f)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker verify: cannot parse baseline: %v\n", err)
		return nil, walker.ExitInternal
	}
	// Schema-version guard.
	if base.SchemaVersion != walker.SchemaVersion {
		fmt.Fprintf(stderr, "cohort-walker verify: %s (baseline=%q want=%q)\n",
			firewall.StaleReasonUnknownSchema, base.SchemaVersion, walker.SchemaVersion)
		return nil, walker.ExitStaleBaseline
	}
	// Staleness firewall.
	horizon, err := time.ParseDuration(horizonStr)
	if err != nil {
		fmt.Fprintf(stderr, "cohort-walker verify: bad --horizon %q: %v\n", horizonStr, err)
		return nil, walker.ExitUsage
	}
	if stale, reason := firewall.IsStale(base.CapturedAt, horizon, time.Now().UTC()); stale {
		fmt.Fprintf(stderr, "cohort-walker verify: %s\n", reason)
		return nil, walker.ExitStaleBaseline
	}
	return base, walker.ExitOK
}

// loadSnapshot opens and parses a snapshot file.
func loadSnapshot(path string) (*walker.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return walker.LoadSnapshot(f)
}

// warnOnDegradation fires a single R143 LoudOnce warning to stderr when the
// scan degraded — currently when any member resolved to substrate=unknown.
func warnOnDegradation(snap *walker.Snapshot, stderr io.Writer) {
	var warn observability.LoudOnce
	unknown := 0
	for _, m := range snap.Members {
		if m.Substrate == walker.SubstrateUnknown {
			unknown++
		}
	}
	if unknown > 0 {
		warn.Fire(stderr, fmt.Sprintf(
			"%d cohort member(s) scanned with substrate=unknown; substrate detection degraded", unknown))
	}
}

// writeSnapshot serialises snap to out (file) or stdout when out is empty.
func writeSnapshot(out string, snap *walker.Snapshot, stdout io.Writer) error {
	w, closeFn, err := openOut(out, stdout)
	if err != nil {
		return err
	}
	defer closeFn()
	return walker.SaveSnapshot(w, snap)
}

// openOut returns a writer for path (or stdout when path is empty) plus a
// close function that is a no-op for stdout.
func openOut(path string, stdout io.Writer) (io.Writer, func(), error) {
	if strings.TrimSpace(path) == "" {
		return stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { f.Close() }, nil
}

// resolveRoots turns the --roots flag into an absolute-or-relative root list.
// Precedence: explicit --roots (comma-separated) > $LIMITLESS_ROOT layout >
// a separator-relative "<sep>limitless/<cohort>" default. No hardcoded drive
// letter at any level, so the binary builds and runs identically on every OS.
func resolveRoots(rootsFlag string) []string {
	if s := strings.TrimSpace(rootsFlag); s != "" {
		var roots []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				roots = append(roots, p)
			}
		}
		return roots
	}
	base := defaultEcosystemBase()
	cohorts := []string{"flagships", "infrastructure", "engines", "foundation"}
	roots := make([]string, 0, len(cohorts))
	for _, c := range cohorts {
		roots = append(roots, filepath.Join(base, c))
	}
	return roots
}

// defaultEcosystemBase resolves the ecosystem checkout root without a
// hardcoded drive letter. $LIMITLESS_ROOT wins; otherwise a separator-relative
// "/limitless" (which on Windows resolves against the current drive).
func defaultEcosystemBase() string {
	if base := strings.TrimSpace(os.Getenv("LIMITLESS_ROOT")); base != "" {
		return base
	}
	return string(filepath.Separator) + "limitless"
}
