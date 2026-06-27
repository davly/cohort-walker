package walker

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davly/cohort-walker/cohort/audit"
	"github.com/davly/cohort-walker/cohort/escape"
	"github.com/davly/cohort-walker/cohort/firewall"
	"github.com/davly/cohort-walker/cohort/identity"
	"github.com/davly/cohort-walker/cohort/legal"
	"github.com/davly/cohort-walker/cohort/observability"
)

// --- KAT-1 byte-identity recompute (R151) -----------------------------------

// TestKAT1Recompute_HMACByteEquality recomputes the KAT-1 anchor with
// crypto/hmac directly and asserts the result is byte-identical to the
// pinned hex constant in cohort/identity. Any drift fails the build.
func TestKAT1Recompute_HMACByteEquality(t *testing.T) {
	h := hmac.New(sha256.New, nil) // empty key, per KAT-1
	h.Write([]byte{0x01})          // domain tag
	var zero [32]byte
	h.Write(zero[:]) // 32 NUL corpus
	digest := h.Sum(nil)
	got := hex.EncodeToString(digest)
	if got != identity.KAT1Hex {
		t.Fatalf("KAT-1 drift:\n  want %s\n  got  %s", identity.KAT1Hex, got)
	}
}

func TestKAT1Recompute_MatchesScanCanonical(t *testing.T) {
	if identity.KAT1Hex != CanonicalKAT1Hex {
		t.Fatalf("identity vs scan canonical drift: identity=%s walker=%s", identity.KAT1Hex, CanonicalKAT1Hex)
	}
}

// --- substrate detection ----------------------------------------------------

func TestSubstrateDetection_GoModule(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"go.mod":  "module example.com/foo\n\ngo 1.22\n",
		"main.go": "package main\nfunc main() {}\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateGo {
		t.Fatalf("want Go, got %v", got)
	}
}

func TestSubstrateDetection_RustCargo(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"Cargo.toml": "[package]\nname = \"foo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
		"src/lib.rs": "pub fn add() {}\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateRust {
		t.Fatalf("want Rust, got %v", got)
	}
}

func TestSubstrateDetection_PythonPyproject(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"pyproject.toml":  "[project]\nname = \"foo\"\n",
		"foo/__init__.py": "",
	})
	if got := detectSubstrate(tmp); got != SubstratePython {
		t.Fatalf("want Python, got %v", got)
	}
}

func TestSubstrateDetection_TypeScriptTsConfig(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"tsconfig.json": "{}",
		"package.json":  `{"name":"foo"}`,
	})
	if got := detectSubstrate(tmp); got != SubstrateTypeScript {
		t.Fatalf("want TypeScript, got %v", got)
	}
}

func TestSubstrateDetection_Elixir(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"mix.exs": "defmodule Foo.MixProject do\nend\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateElixir {
		t.Fatalf("want Elixir, got %v", got)
	}
}

func TestSubstrateDetection_Zig(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"build.zig": "const std = @import(\"std\");\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateZig {
		t.Fatalf("want Zig, got %v", got)
	}
}

func TestSubstrateDetection_FallbackOnSource(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"lib/foo.rs": "fn main() {}\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateRust {
		t.Fatalf("want Rust (fallback), got %v", got)
	}
}

func TestSubstrateDetection_Unknown(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"README.md": "# foo\n",
	})
	if got := detectSubstrate(tmp); got != SubstrateUnknown {
		t.Fatalf("want Unknown, got %v", got)
	}
}

// --- marker probes ----------------------------------------------------------

func TestMarkers_AllSevenPresent(t *testing.T) {
	src := "package foo\n" +
		"// mirror_mark anchor: " + CanonicalKAT1Hex + "\n" +
		"// wire prefix: " + CanonicalWireFormatPrefix + "\n" +
		"// LoudOnce wired here\n" +
		"// LOUD-ONCE-WARNING audit_rule=R143_LOUD_ONCE_WARNING_FLAG\n" +
		"// IsStale predicate exposed\n" +
		"// LIABILITY_FOOTER constant pinned\n" +
		"import _ \"github.com/davly/limitless/foundation/pkg/mirrormark\"\n"
	tmp := mkTempMember(t, map[string]string{
		"mirrormark/mirrormark.go": src,
	})
	m := probeMarkers(tmp, 1<<20)
	if !m.HasMirrorMarkPkg {
		t.Error("mirrormark pkg not detected")
	}
	if !m.KAT1HexPinned {
		t.Error("KAT-1 pin not detected")
	}
	if !m.WireFormatPrefixOK {
		t.Error("wire prefix not detected")
	}
	if !m.HasLoudOnceWiring {
		t.Error("LoudOnce wiring not detected")
	}
	if !m.HasIsStalePredicate {
		t.Error("IsStale not detected")
	}
	if !m.HasLiabilityFooter {
		t.Error("LIABILITY_FOOTER not detected")
	}
	if !m.UsesFoundationPkg {
		t.Error("foundation/pkg usage not detected")
	}
}

func TestMarkers_DriftDetection_BareV1Prefix(t *testing.T) {
	src := "// mirror_mark stub\n" +
		"const VERSION = \"v1:\"\n" + // wrong prefix
		"// lore handling\n"
	tmp := mkTempMember(t, map[string]string{
		"mark.go": src,
	})
	m := probeMarkers(tmp, 1<<20)
	if m.WireFormatPrefixDrift == "" {
		t.Fatalf("expected wire-format drift to be detected; got markers %+v", m)
	}
}

func TestMarkers_NoFalsePositives_OnEmptyMember(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"README.md": "# nothing\n",
	})
	m := probeMarkers(tmp, 1<<20)
	if m.KAT1HexPinned || m.HasMirrorMarkPkg || m.WireFormatPrefixOK ||
		m.HasLoudOnceWiring || m.HasIsStalePredicate || m.HasLiabilityFooter ||
		m.UsesFoundationPkg || m.WireFormatPrefixDrift != "" {
		t.Fatalf("expected all-zero markers, got %+v", m)
	}
}

func TestMarkers_KAT1NotConfusedWithSuffix(t *testing.T) {
	// A file containing a different 64-char hex string must NOT match.
	wrong := strings.Repeat("a", 64)
	tmp := mkTempMember(t, map[string]string{
		"foo.go": "// hex " + wrong + "\n",
	})
	m := probeMarkers(tmp, 1<<20)
	if m.KAT1HexPinned {
		t.Fatal("KAT-1 pin matched on unrelated 64-char hex string")
	}
}

// --- INDEX-LIE detection ----------------------------------------------------

func TestIndexLie_RustModWithoutFile(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"src/lib.rs":  "pub mod ghost;\npub mod real;\n",
		"src/real.rs": "pub fn ok() {}\n",
		"Cargo.toml":  "[package]\nname=\"f\"\nversion=\"0\"\nedition=\"2021\"\n",
	})
	lies := detectRustModLies(tmp)
	found := false
	for _, l := range lies {
		if strings.Contains(l, "ghost") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ghost mod to be flagged; got %v", lies)
	}
}

func TestIndexLie_RustModWithRealSibling(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"src/lib.rs":  "pub mod real;\n",
		"src/real.rs": "",
	})
	lies := detectRustModLies(tmp)
	for _, l := range lies {
		if strings.Contains(l, "real") {
			t.Fatalf("false positive on present mod: %v", lies)
		}
	}
}

func TestIndexLie_GoDocMismatch(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"sub/doc.go": "// Package wrong declares the wrong name.\npackage wrong\n",
	})
	lies := detectGoDocLies(tmp)
	if len(lies) == 0 {
		t.Fatal("expected doc-package mismatch to be flagged")
	}
}

func TestIndexLie_GoDocAgreement(t *testing.T) {
	tmp := mkTempMember(t, map[string]string{
		"sub/doc.go": "// Package sub is honest.\npackage sub\n",
	})
	lies := detectGoDocLies(tmp)
	if len(lies) != 0 {
		t.Fatalf("expected no lies for honest doc.go; got %v", lies)
	}
}

// TestIndexLie_GoDocReadIsCapped asserts detectGoDocLies caps its per-file
// read at 1 MiB. A doc.go with >1 MiB of leading filler followed by a
// mismatched `// Package` declaration must NOT be flagged, because the
// declaration sits beyond the cap and is never read. With the prior
// unbounded os.ReadFile the whole file would be read and the lie WOULD be
// flagged — so this is the fail-before/pass-after discriminator for the cap.
func TestIndexLie_GoDocReadIsCapped(t *testing.T) {
	// >1 MiB of comment filler that contains no "// Package " substring,
	// then the mismatched declaration. dirName is "sub", decl says "wrong".
	filler := strings.Repeat("// filler line padding\n", 60000) // ~1.3 MiB
	body := filler + "// Package wrong declares a name that mismatches the dir.\npackage wrong\n"
	tmp := mkTempMember(t, map[string]string{
		"sub/doc.go": body,
	})
	lies := detectGoDocLies(tmp)
	if len(lies) != 0 {
		t.Fatalf("declaration beyond the 1 MiB read cap must not be read; got %v", lies)
	}

	// Sanity: the SAME mismatch within the cap IS still flagged (cap is not a
	// blanket disable).
	near := mkTempMember(t, map[string]string{
		"sub/doc.go": "// Package wrong mismatches the dir.\npackage wrong\n",
	})
	if got := detectGoDocLies(near); len(got) == 0 {
		t.Fatalf("in-cap mismatch should still be flagged; got none")
	}
}

// --- end-to-end Scan --------------------------------------------------------

// TestScan_EmptyRoots_NoMembers is HERMETIC: it passes a single empty
// t.TempDir root so Scan never falls through to DefaultRoots and never walks
// the live filesystem. (The prior version passed Roots:[]string{}, which made
// Scan substitute the real DefaultRoots — C:\limitless\flagships etc. — and
// filepath.WalkDir the entire live ecosystem tree; with no walk cap that hung
// until the test timeout. See TestScan_EmptyRoots_SubstitutesDefaultRoots for
// the substitution behaviour, asserted WITHOUT walking the live tree.)
func TestScan_EmptyRoots_NoMembers(t *testing.T) {
	emptyRoot := t.TempDir()
	snap, err := Scan(ScanOptions{Roots: []string{emptyRoot}, Now: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version mismatch: %s", snap.SchemaVersion)
	}
	if len(snap.Members) != 0 {
		t.Fatalf("empty root should yield no members, got %d", len(snap.Members))
	}
}

// TestScan_EmptyRoots_SubstitutesDefaultRoots asserts the documented fallback
// (len(Roots)==0 -> DefaultRoots) WITHOUT walking the live tree: it inspects
// the returned snapshot's Roots field, which Scan records before any walk.
func TestScan_EmptyRoots_SubstitutesDefaultRoots(t *testing.T) {
	// Use a bogus DefaultRoots-shaped path that does not exist so os.ReadDir
	// returns fs.ErrNotExist and Scan skips it -- no walk happens.
	bogus := filepath.Join(t.TempDir(), "does-not-exist-flagships")
	saved := DefaultRoots
	DefaultRoots = []string{bogus}
	t.Cleanup(func() { DefaultRoots = saved })

	snap, err := Scan(ScanOptions{Roots: nil, Now: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Roots) != 1 || snap.Roots[0] != bogus {
		t.Fatalf("empty Roots should substitute DefaultRoots; got %v", snap.Roots)
	}
	if len(snap.Members) != 0 {
		t.Fatalf("non-existent default root should yield no members, got %d", len(snap.Members))
	}
}

// TestProbeMarkers_DepthCap asserts the walk does NOT descend past
// scanDepthCap. A marker planted BELOW the cap must be invisible; the same
// marker at/above the cap must be found. This discriminates the depth cap:
// reverting it (probeMarkers walking unbounded depth) makes the deep marker
// visible and fails the "deep marker invisible" assertion.
func TestProbeMarkers_DepthCap(t *testing.T) {
	// Build a path nested deeper than scanDepthCap separators from root.
	deep := strings.Repeat("d/", scanDepthCap+2) // > scanDepthCap separators
	tmp := mkTempMember(t, map[string]string{
		deep + "buried.go": "// KAT " + CanonicalKAT1Hex + "\n",
	})
	m := probeMarkers(tmp, 1<<20)
	if m.KAT1HexPinned {
		t.Fatalf("marker buried below scanDepthCap should NOT be read; got %+v", m)
	}

	// Sanity: the SAME marker at shallow depth IS found (cap is not a blanket
	// disable).
	shallow := mkTempMember(t, map[string]string{
		"shallow.go": "// KAT " + CanonicalKAT1Hex + "\n",
	})
	if m2 := probeMarkers(shallow, 1<<20); !m2.KAT1HexPinned {
		t.Fatalf("shallow marker should be read; got %+v", m2)
	}
}

// TestProbeMarkers_FileCapTerminates asserts the file-count cap bounds the
// number of files read. It plants scanFileCap "decoy" source files (sorted
// before) plus one marker file whose name sorts AFTER all decoys, so the cap
// is exhausted before the marker is reached. With the cap removed (prod
// reverted), the marker would be read and KAT1HexPinned would be true.
func TestProbeMarkers_FileCapTerminates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file-cap test in -short mode")
	}
	files := make(map[string]string, scanFileCap+1)
	for i := 0; i < scanFileCap; i++ {
		// "aaa..." prefix + zero-padded index sorts before the marker.
		files[fmt.Sprintf("decoy_%06d.go", i)] = "package p\n"
	}
	// Marker file name sorts AFTER every decoy.
	files["zzz_marker.go"] = "// KAT " + CanonicalKAT1Hex + "\n"
	tmp := mkTempMember(t, files)
	m := probeMarkers(tmp, 1<<20)
	if m.KAT1HexPinned {
		t.Fatalf("file beyond scanFileCap should NOT be read; got %+v", m)
	}
}

func TestScan_SyntheticRoot(t *testing.T) {
	root := t.TempDir()
	// Build two fake "flagship" subdirs.
	mustWriteDir(t, filepath.Join(root, "alpha"), map[string]string{
		"go.mod":             "module example.com/alpha\ngo 1.22\n",
		"mirrormark/mark.go": "package mirrormark\nconst KAT = \"" + CanonicalKAT1Hex + "\"\nconst V = \"" + CanonicalWireFormatPrefix + "\"\n",
	})
	mustWriteDir(t, filepath.Join(root, "beta"), map[string]string{
		"Cargo.toml": "[package]\nname=\"beta\"\nversion=\"0\"\nedition=\"2021\"\n",
		"src/lib.rs": "// no KAT here\n",
	})
	snap, err := Scan(ScanOptions{Roots: []string{root}, Now: fixedTime()})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Members) != 2 {
		t.Fatalf("want 2 members, got %d", len(snap.Members))
	}
	var alpha, beta *Member
	for i := range snap.Members {
		switch snap.Members[i].Name {
		case "alpha":
			alpha = &snap.Members[i]
		case "beta":
			beta = &snap.Members[i]
		}
	}
	if alpha == nil || beta == nil {
		t.Fatalf("missing expected members: %+v", snap.Members)
	}
	if alpha.Substrate != SubstrateGo {
		t.Errorf("alpha: want Go, got %v", alpha.Substrate)
	}
	if !alpha.Markers.KAT1HexPinned {
		t.Error("alpha: KAT-1 pin missed")
	}
	if beta.Substrate != SubstrateRust {
		t.Errorf("beta: want Rust, got %v", beta.Substrate)
	}
	if beta.Markers.KAT1HexPinned {
		t.Error("beta: false-positive KAT-1 pin")
	}
}

// --- Diff -------------------------------------------------------------------

func TestDiff_NoChange_ZeroDeltas(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}}}}
	rep := Diff(prev, cur)
	if len(rep.Deltas) != 0 {
		t.Fatalf("expected no deltas, got %v", rep.Deltas)
	}
}

func TestDiff_KAT1Lost_IsFail(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: false}}}}
	rep := Diff(prev, cur)
	if rep.Summary.Fail == 0 {
		t.Fatalf("expected FAIL on KAT-1 loss; deltas=%v", rep.Deltas)
	}
}

func TestDiff_NewMember_IsInfo(t *testing.T) {
	prev := &Snapshot{}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships"}}}
	rep := Diff(prev, cur)
	found := false
	for _, d := range rep.Deltas {
		if d.Kind == DeltaNewMember && d.Severity == SeverityInfo {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected new-member info delta; got %v", rep.Deltas)
	}
}

func TestDiff_DroppedMember_IsWarn(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships"}}}
	cur := &Snapshot{}
	rep := Diff(prev, cur)
	found := false
	for _, d := range rep.Deltas {
		if d.Kind == DeltaDroppedMember && d.Severity == SeverityWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dropped-member warn delta; got %v", rep.Deltas)
	}
}

func TestDiff_SubstrateChange_IsWarn(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateRust}}}
	rep := Diff(prev, cur)
	found := false
	for _, d := range rep.Deltas {
		if d.Kind == DeltaSubstrateChanged && d.Severity == SeverityWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected substrate-change warn; got %v", rep.Deltas)
	}
}

func TestDiff_WireFormatDriftIntroduced(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships"}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships",
		Markers: Markers{WireFormatPrefixDrift: `"v1:"`}}}}
	rep := Diff(prev, cur)
	if rep.Summary.Fail == 0 {
		t.Fatalf("expected FAIL on wire-format drift; got %v", rep.Deltas)
	}
}

func TestDiff_IndexLieIntroduced(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships"}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships",
		IndexLies: []string{"rust mod ghost declared in lib.rs not on disk"}}}}
	rep := Diff(prev, cur)
	if rep.Summary.Fail == 0 {
		t.Fatalf("expected FAIL on INDEX-LIE; got %v", rep.Deltas)
	}
}

func TestDiff_MissingR174_5of5_IsWarn(t *testing.T) {
	// Member with only 2 of 5 markers.
	m := Member{Name: "alpha", Cohort: "flagships",
		Markers: Markers{KAT1HexPinned: true, HasMirrorMarkPkg: true}}
	cur := &Snapshot{Members: []Member{m}}
	rep := Diff(nil, cur)
	found := false
	for _, d := range rep.Deltas {
		if d.Kind == DeltaMissingR174 && d.Severity == SeverityWarn {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing-R174 warn; got %v", rep.Deltas)
	}
}

func TestDiff_FullFiveOfFive_NoR174Warn(t *testing.T) {
	m := Member{Name: "alpha", Cohort: "flagships", Markers: Markers{
		HasMirrorMarkPkg: true, KAT1HexPinned: true, HasLoudOnceWiring: true,
		HasIsStalePredicate: true, HasLiabilityFooter: true,
	}}
	cur := &Snapshot{Members: []Member{m}}
	rep := Diff(nil, cur)
	for _, d := range rep.Deltas {
		if d.Kind == DeltaMissingR174 {
			t.Fatalf("unexpected R174 warn on 5/5 member: %v", d)
		}
	}
}

func TestDiff_OrdersBySeverity(t *testing.T) {
	cur := &Snapshot{Members: []Member{
		{Name: "alpha", Cohort: "f", IndexLies: []string{"a lie"}},
	}}
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "f"}}}
	rep := Diff(prev, cur)
	if len(rep.Deltas) < 1 {
		t.Fatal("expected ≥1 delta")
	}
	if rep.Deltas[0].Severity != SeverityFail {
		t.Fatalf("expected FAIL first; got %v", rep.Deltas[0])
	}
}

// --- Report rendering -------------------------------------------------------

func TestRenderMarkdown_IncludesLiabilityFooter(t *testing.T) {
	rep := &DiffReport{
		Current:  &Snapshot{CapturedAt: fixedTime()},
		Previous: nil,
		Summary:  Summary{},
	}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "NOT LEGAL ADVICE") {
		t.Fatalf("liability footer missing from markdown:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), escape.Tag) && !strings.Contains(buf.String(), "HUMAN ESCAPE") {
		t.Fatalf("human-escape clause missing from markdown")
	}
}

func TestRenderJSON_RoundTripsDeltas(t *testing.T) {
	rep := &DiffReport{Deltas: []Delta{{Member: "alpha", Cohort: "f", Kind: DeltaKAT1Lost, Severity: SeverityFail, Detail: "test"}}, Summary: Summary{Fail: 1}}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Deltas []Delta `json:"deltas"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, buf.String())
	}
	if len(out.Deltas) != 1 || out.Deltas[0].Severity != SeverityFail {
		t.Fatalf("round-trip lost data: %+v", out.Deltas)
	}
}

func TestSaveAndLoadSnapshot_RoundTrip(t *testing.T) {
	snap := &Snapshot{
		SchemaVersion: SchemaVersion,
		CapturedAt:    fixedTime(),
		Roots:         []string{"/tmp/roots"},
		Members:       []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo}},
	}
	var buf bytes.Buffer
	if err := SaveSnapshot(&buf, snap); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSnapshot(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != snap.SchemaVersion {
		t.Fatalf("schema lost in round-trip")
	}
	if len(got.Members) != 1 || got.Members[0].Name != "alpha" {
		t.Fatalf("members lost in round-trip: %+v", got.Members)
	}
}

// --- CI -----------------------------------------------------------------

func TestVerifyCI_ExitCodes(t *testing.T) {
	cases := []struct {
		name    string
		summary Summary
		strict  bool
		want    int
	}{
		{"clean", Summary{Pass: 3}, false, ExitOK},
		{"fail", Summary{Fail: 1}, false, ExitDriftFail},
		{"warn_lenient", Summary{Warn: 1}, false, ExitOK},
		{"warn_strict", Summary{Warn: 1}, true, ExitDriftWarn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := &DiffReport{Summary: c.summary}
			_ = rep
			// Build a Snapshot pair that produces c.summary.
			prev, cur := snapshotsForSummary(c.summary)
			var buf bytes.Buffer
			code := VerifyCI(CIConfig{StrictWarn: c.strict}, prev, cur, &buf)
			if code != c.want {
				t.Fatalf("want exit %d, got %d (out=%s)", c.want, code, buf.String())
			}
		})
	}
}

// --- cohort packages (eat own dogfood) ----------------------------------

func TestObservabilityLoudOnce_FiresOnlyOnce(t *testing.T) {
	var once observability.LoudOnce
	var buf bytes.Buffer
	if !once.Fire(&buf, "first") {
		t.Fatal("first call should fire")
	}
	if once.Fire(&buf, "second") {
		t.Fatal("second call must not fire")
	}
	if !strings.Contains(buf.String(), observability.AuditRule) {
		t.Fatalf("audit-rule tag missing from output: %q", buf.String())
	}
}

func TestObservabilityLoudOnce_ResetRearms(t *testing.T) {
	var once observability.LoudOnce
	once.Fire(io.Discard, "a")
	if once.Fire(io.Discard, "b") {
		t.Fatal("must not fire before reset")
	}
	once.Reset()
	if !once.Fire(io.Discard, "c") {
		t.Fatal("reset must re-arm")
	}
}

func TestFirewallIsStale_ZeroIsStale(t *testing.T) {
	stale, reason := firewall.IsStale(time.Time{}, firewall.DefaultHorizon, fixedTime())
	if !stale {
		t.Fatal("zero time must be stale")
	}
	if reason != firewall.StaleReasonZeroTime {
		t.Fatalf("want zero-time reason, got %q", reason)
	}
}

func TestFirewallIsStale_FutureIsStale(t *testing.T) {
	future := fixedTime().Add(24 * time.Hour)
	stale, reason := firewall.IsStale(future, firewall.DefaultHorizon, fixedTime())
	if !stale || reason != firewall.StaleReasonFutureTimestamp {
		t.Fatalf("want future-stale, got stale=%v reason=%q", stale, reason)
	}
}

func TestFirewallIsStale_FreshIsNotStale(t *testing.T) {
	fresh := fixedTime().Add(-time.Hour)
	stale, _ := firewall.IsStale(fresh, firewall.DefaultHorizon, fixedTime())
	if stale {
		t.Fatal("1-hour-old must not be stale")
	}
}

func TestFirewallIsStale_BeyondHorizonIsStale(t *testing.T) {
	old := fixedTime().Add(-2 * firewall.DefaultHorizon)
	stale, reason := firewall.IsStale(old, firewall.DefaultHorizon, fixedTime())
	if !stale || reason != firewall.StaleReasonExpired {
		t.Fatalf("want expired-stale, got stale=%v reason=%q", stale, reason)
	}
}

func TestAuditNewRow_OutcomeConstrained(t *testing.T) {
	row := audit.NewRow("R155", "cohort-walker", "alpha", audit.OutcomePass, "")
	if row.Outcome != audit.OutcomePass {
		t.Fatalf("outcome lost")
	}
	if row.CapturedAt.IsZero() {
		t.Fatal("auto-clock not set")
	}
}

func TestAuditNewRowAt_ClockInjected(t *testing.T) {
	ts := fixedTime()
	row := audit.NewRowAt("R155", "x", "y", audit.OutcomeFail, "drift", ts)
	if !row.CapturedAt.Equal(ts.UTC()) {
		t.Fatalf("clock not honoured: want %v got %v", ts.UTC(), row.CapturedAt)
	}
}

func TestEscape_IsOverridable(t *testing.T) {
	if !escape.IsOverridable("FAIL") {
		t.Error("FAIL must be overridable")
	}
	if !escape.IsOverridable("SKIP") {
		t.Error("SKIP must be overridable")
	}
	if escape.IsOverridable("PASS") {
		t.Error("PASS must not be overridable")
	}
}

func TestLegal_LiabilityFooter_LiteralTag(t *testing.T) {
	if !strings.Contains(legal.LiabilityFooter, "NOT LEGAL ADVICE") {
		t.Fatal("liability footer missing canonical prefix")
	}
	if legal.Tag != "R166_LIABILITY_FOOTER_CONST" {
		t.Fatalf("liability footer tag drift: %q", legal.Tag)
	}
}

func TestIdentity_KAT1HexCanonical(t *testing.T) {
	if identity.KAT1Hex != "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca" {
		t.Fatalf("identity pin drifted from canonical: %s", identity.KAT1Hex)
	}
	if identity.Version != "lore@v1:" {
		t.Fatalf("identity Version drifted: %s", identity.Version)
	}
}

func TestOutcomeConversion(t *testing.T) {
	if Outcome(ExitOK) != audit.OutcomePass {
		t.Error("ok → Pass")
	}
	if Outcome(ExitDriftFail) != audit.OutcomeFail {
		t.Error("fail → Fail")
	}
	if Outcome(99) != audit.OutcomeSkip {
		t.Error("unknown → Skip")
	}
}

// --- helpers ----------------------------------------------------------------

func fixedTime() time.Time {
	return time.Date(2026, 5, 28, 11, 0, 0, 0, time.UTC)
}

func mkTempMember(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, body := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustWriteDir(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, body := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// snapshotsForSummary constructs a (prev, cur) pair that diffs to the
// supplied severity-mix. Cheap synthetic test scaffolding.
func snapshotsForSummary(s Summary) (*Snapshot, *Snapshot) {
	prev := &Snapshot{}
	cur := &Snapshot{}
	for i := 0; i < s.Fail; i++ {
		name := makeName("fail", i)
		prev.Members = append(prev.Members, Member{Name: name, Cohort: "f", Markers: Markers{KAT1HexPinned: true}})
		cur.Members = append(cur.Members, Member{Name: name, Cohort: "f", Markers: Markers{KAT1HexPinned: false}})
	}
	for i := 0; i < s.Warn; i++ {
		name := makeName("warn", i)
		prev.Members = append(prev.Members, Member{Name: name, Cohort: "f"})
		cur.Members = append(cur.Members, Member{Name: name, Cohort: "f", Substrate: SubstrateRust})
	}
	for i := 0; i < s.Info; i++ {
		name := makeName("info", i)
		cur.Members = append(cur.Members, Member{Name: name, Cohort: "f"})
	}
	for i := 0; i < s.Pass; i++ {
		name := makeName("pass", i)
		prev.Members = append(prev.Members, Member{Name: name, Cohort: "f"})
		cur.Members = append(cur.Members, Member{Name: name, Cohort: "f", Markers: Markers{KAT1HexPinned: true}})
	}
	return prev, cur
}

func makeName(prefix string, i int) string { return prefix + "-" + indexToStr(i) }

func indexToStr(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+(i%10))) + out
		i /= 10
	}
	return out
}
