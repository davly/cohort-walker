package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davly/cohort-walker/internal/walker"
)

// forkcensus_cli_test.go covers the `fork-census` CLI wiring (forge F10):
// dispatch, --json machine-readable output, the human-summary default,
// --out file writing, and the ExitForbiddenRoot (7) end-to-end path.

// TestCLI_ForkCensus_JSON_ClustersAndOutlier drives fork-census end-to-end
// over a temp fixture and asserts the JSON payload's clustering.
func TestCLI_ForkCensus_JSON_ClustersAndOutlier(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "app-a", "shared.txt"), "canonical body\n")
	mustWrite(t, filepath.Join(root, "app-b", "shared.txt"), "canonical body\n")
	mustWrite(t, filepath.Join(root, "app-c", "shared.txt"), "drifted body\n")

	var out, errb bytes.Buffer
	code := run([]string{"fork-census", "--roots", root, "--files", "shared.txt", "--json", "--no-timestamp"}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("fork-census want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	var rep walker.ForkCensusReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("fork-census --json output invalid: %v\nbody=%s", err, out.String())
	}
	if rep.SchemaVersion != walker.ForkCensusSchemaVersion {
		t.Fatalf("schema_version want %q, got %q", walker.ForkCensusSchemaVersion, rep.SchemaVersion)
	}
	if len(rep.Families) != 1 || len(rep.Families[0].Clusters) != 2 {
		t.Fatalf("want 1 family / 2 clusters, got %+v", rep.Families)
	}
	if len(rep.Families[0].Outliers) != 1 || rep.Families[0].Outliers[0] != "app-c" {
		t.Fatalf("outliers want [app-c], got %v", rep.Families[0].Outliers)
	}
}

// TestCLI_ForkCensus_HumanSummary_DefaultsToText covers the default
// (non-JSON) render path: the human summary must name the file family and
// flag the outlier.
func TestCLI_ForkCensus_HumanSummary_DefaultsToText(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "app-a", "shared.txt"), "same\n")
	mustWrite(t, filepath.Join(root, "app-b", "shared.txt"), "same\n")
	mustWrite(t, filepath.Join(root, "app-c", "shared.txt"), "different\n")

	var out, errb bytes.Buffer
	code := run([]string{"fork-census", "--roots", root, "--files", "shared.txt"}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("fork-census want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	body := out.String()
	if !strings.Contains(body, "shared.txt") {
		t.Fatalf("human summary missing family file name: %q", body)
	}
	if !strings.Contains(body, "OUTLIERS: app-c") {
		t.Fatalf("human summary missing outlier line: %q", body)
	}
}

// TestCLI_ForkCensus_OutFile_Writes covers --out (writes to a file instead
// of stdout, mirroring cmdScan/cmdReport's openOut contract).
func TestCLI_ForkCensus_OutFile_Writes(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "app-a", "shared.txt"), "body\n")
	outFile := filepath.Join(t.TempDir(), "census.json")

	var out, errb bytes.Buffer
	code := run([]string{"fork-census", "--roots", root, "--files", "shared.txt", "--json", "--out", outFile}, &out, &errb)
	if code != walker.ExitOK {
		t.Fatalf("fork-census --out want exit %d, got %d (err=%q)", walker.ExitOK, code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty when --out is set; got %q", out.String())
	}
	body := readFile(t, outFile)
	if !strings.Contains(body, walker.ForkCensusSchemaVersion) {
		t.Fatalf("--out file missing schema_version: %q", body)
	}
}

// TestCLI_ForkCensus_ForbiddenRoot_ExitsSeven is the end-to-end guard proof:
// a --roots path naming fleetworks or vocaladev must exit ExitForbiddenRoot
// (7), the same guarantee RunForkCensus makes at the walker layer.
func TestCLI_ForkCensus_ForbiddenRoot_ExitsSeven(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"fork-census", "--roots", `C:\vocaladev\FleetworksGodfather\apps`}, &out, &errb)
	if code != walker.ExitForbiddenRoot {
		t.Fatalf("forbidden root want exit %d, got %d (err=%q)", walker.ExitForbiddenRoot, code, errb.String())
	}
	if !strings.Contains(errb.String(), "forbidden") {
		t.Fatalf("stderr missing forbidden-root message: %q", errb.String())
	}
}

// TestCLI_ForkCensus_DefaultRoots_UsesLimitlessRootApps covers
// resolveForkRoots' $LIMITLESS_ROOT precedence (mirrors
// TestResolveRoots_DefaultLayout_UsesLimitlessRoot for the 4-cohort roots).
func TestCLI_ForkCensus_DefaultRoots_UsesLimitlessRootApps(t *testing.T) {
	base := filepath.Join(t.TempDir(), "eco")
	t.Setenv("LIMITLESS_ROOT", base)
	got := resolveForkRoots("")
	want := []string{filepath.Join(base, "apps")}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// TestCLI_ForkCensus_DefaultRoots_NoEnv_UsesWalkerDefault covers the final
// fallback: no --roots, no $LIMITLESS_ROOT -> walker.DefaultForkRoots.
func TestCLI_ForkCensus_DefaultRoots_NoEnv_UsesWalkerDefault(t *testing.T) {
	t.Setenv("LIMITLESS_ROOT", "")
	got := resolveForkRoots("")
	if len(got) != len(walker.DefaultForkRoots) || got[0] != walker.DefaultForkRoots[0] {
		t.Fatalf("want %v, got %v", walker.DefaultForkRoots, got)
	}
}

// TestSplitCommaList_TrimsSkipsEmpty_NilOnBlank covers the small shared flag
// parser fork-census's --roots/--files both use.
func TestSplitCommaList_TrimsSkipsEmpty_NilOnBlank(t *testing.T) {
	got := splitCommaList(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: want %q, got %q", i, want[i], got[i])
		}
	}
	if splitCommaList("   ") != nil {
		t.Fatalf("blank input must return nil")
	}
}
