package walker

import (
	"bytes"
	"strings"
	"testing"
)

// verdict_coverage_test.go closes the verdict-layer gaps called out in
// cw-cli-coverage: the non-KAT marker_lost / marker_gained classification
// paths (marker_lost MUST be a FAIL that drives a non-zero CI exit), the
// per-(cohort,substrate) census aggregation, and the markdown census table.
// These are package-internal verdict tests (no firewall / no live scan); the
// end-to-end CLI counterparts live in cmd/cohort-walker/coverage_test.go.

// --- marker_lost / marker_gained classification -----------------------------

// markerSetter flips one of the four non-KAT 5-of-5 marker bits on a Markers
// value. KAT-1 is excluded on purpose: it has its own dedicated
// kat1_lost / kat1_gained kinds (see TestDiff_KAT1Lost_IsFail), so the
// marker_lost / marker_gained classifier in classifyMarkerChange only covers
// these four.
var nonKATMarkers = []struct {
	name string // detail substring classifyMarkerChange emits
	set  func(m *Markers, v bool)
}{
	{"mirrormark_pkg", func(m *Markers, v bool) { m.HasMirrorMarkPkg = v }},
	{"loud_once_wiring", func(m *Markers, v bool) { m.HasLoudOnceWiring = v }},
	{"is_stale_predicate", func(m *Markers, v bool) { m.HasIsStalePredicate = v }},
	{"liability_footer", func(m *Markers, v bool) { m.HasLiabilityFooter = v }},
}

// TestDiff_MarkerLost_IsFail proves that losing ANY of the four non-KAT
// markers between snapshots classifies as a marker_lost FAIL, and that the
// FAIL is what makes the summary report a failure (Summary.HasFail()). This is
// the verdict-layer half of "marker_lost must FAIL/exit non-zero".
func TestDiff_MarkerLost_IsFail(t *testing.T) {
	for _, mk := range nonKATMarkers {
		t.Run(mk.name, func(t *testing.T) {
			var wasMk, nowMk Markers
			mk.set(&wasMk, true)  // baseline had the marker
			mk.set(&nowMk, false) // current lost it
			prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: wasMk}}}
			cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: nowMk}}}
			rep := Diff(prev, cur)

			var lost *Delta
			for i := range rep.Deltas {
				if rep.Deltas[i].Kind == DeltaMarkerLost {
					lost = &rep.Deltas[i]
				}
			}
			if lost == nil {
				t.Fatalf("expected a marker_lost delta for %s; got %+v", mk.name, rep.Deltas)
			}
			if lost.Severity != SeverityFail {
				t.Fatalf("marker_lost must be FAIL; got %s", lost.Severity)
			}
			if !strings.Contains(lost.Detail, mk.name) {
				t.Fatalf("marker_lost detail should name the marker %q; got %q", mk.name, lost.Detail)
			}
			if !rep.Summary.HasFail() {
				t.Fatalf("a marker_lost FAIL must make Summary.HasFail() true; summary=%+v", rep.Summary)
			}
		})
	}
}

// TestDiff_MarkerGained_IsPass proves the inverse: gaining a non-KAT marker
// classifies as a marker_gained PASS (an improvement, never a gate failure).
func TestDiff_MarkerGained_IsPass(t *testing.T) {
	for _, mk := range nonKATMarkers {
		t.Run(mk.name, func(t *testing.T) {
			var wasMk, nowMk Markers
			mk.set(&wasMk, false) // baseline lacked it
			mk.set(&nowMk, true)  // current gained it
			prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: wasMk}}}
			cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: nowMk}}}
			rep := Diff(prev, cur)

			var gained *Delta
			for i := range rep.Deltas {
				if rep.Deltas[i].Kind == DeltaMarkerGained {
					gained = &rep.Deltas[i]
				}
			}
			if gained == nil {
				t.Fatalf("expected a marker_gained delta for %s; got %+v", mk.name, rep.Deltas)
			}
			if gained.Severity != SeverityPass {
				t.Fatalf("marker_gained must be PASS; got %s", gained.Severity)
			}
			if rep.Summary.HasFail() {
				t.Fatalf("a marker_gained PASS must NOT make Summary.HasFail() true; summary=%+v", rep.Summary)
			}
		})
	}
}

// TestVerifyCI_MarkerLost_ExitFail is the verdict-layer exit-code assertion:
// a snapshot pair whose only delta is a non-KAT marker loss drives VerifyCI to
// ExitDriftFail (1) even in lenient (non-strict) mode. This is the "exit
// non-zero" guarantee at the CI adapter boundary.
func TestVerifyCI_MarkerLost_ExitFail(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{HasLoudOnceWiring: true}}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{}}}}
	var buf bytes.Buffer
	if code := VerifyCI(CIConfig{StrictWarn: false}, prev, cur, &buf); code != ExitDriftFail {
		t.Fatalf("marker_lost must drive ExitDriftFail (%d) even lenient; got %d (out=%q)", ExitDriftFail, code, buf.String())
	}
}

// TestVerifyCI_MarkerGained_ExitOK confirms a PASS-only delta (marker gained)
// does not trip the gate: exit stays 0.
func TestVerifyCI_MarkerGained_ExitOK(t *testing.T) {
	prev := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{}}}}
	cur := &Snapshot{Members: []Member{{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{HasLoudOnceWiring: true}}}}
	var buf bytes.Buffer
	if code := VerifyCI(CIConfig{StrictWarn: true}, prev, cur, &buf); code != ExitOK {
		t.Fatalf("marker_gained PASS must keep ExitOK (%d) even strict; got %d (out=%q)", ExitOK, code, buf.String())
	}
}

// --- cohort census aggregation ----------------------------------------------

// TestCohortCensusRows_GroupsAndSorts checks the per-(cohort,substrate)
// aggregation: rows are grouped by the (cohort,substrate) pair, the four
// marker tallies are summed per group, and the row order is the deterministic
// (cohort, substrate) lexicographic sort (no reliance on map order).
func TestCohortCensusRows_GroupsAndSorts(t *testing.T) {
	snap := &Snapshot{Members: []Member{
		{Name: "a", Cohort: "engines", Substrate: SubstrateRust, Markers: Markers{KAT1HexPinned: true, HasLiabilityFooter: true}},
		{Name: "b", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true, HasLoudOnceWiring: true, HasIsStalePredicate: true}},
		{Name: "c", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}},
		{Name: "d", Cohort: "flagships", Substrate: SubstrateRust},
	}}
	rows := cohortCensusRows(snap)

	wantOrder := []struct{ cohort, substrate string }{
		{"engines", "rust"},
		{"flagships", "go"},
		{"flagships", "rust"},
	}
	if len(rows) != len(wantOrder) {
		t.Fatalf("want %d census rows, got %d: %+v", len(wantOrder), len(rows), rows)
	}
	for i, w := range wantOrder {
		if rows[i].Cohort != w.cohort || rows[i].Substrate != w.substrate {
			t.Fatalf("row %d order wrong: want %s/%s, got %s/%s", i, w.cohort, w.substrate, rows[i].Cohort, rows[i].Substrate)
		}
	}

	// flagships|go aggregates b+c: Total 2, KAT1 2, LiabilityFooter 0,
	// LoudOnce 1, IsStale 1.
	fgo := rows[1]
	if fgo.Total != 2 || fgo.KAT1 != 2 || fgo.LiabilityFooter != 0 || fgo.LoudOnce != 1 || fgo.IsStale != 1 {
		t.Fatalf("flagships/go census tally wrong: %+v", fgo)
	}
	// engines|rust: single member with KAT1 + LiabilityFooter.
	erust := rows[0]
	if erust.Total != 1 || erust.KAT1 != 1 || erust.LiabilityFooter != 1 || erust.LoudOnce != 0 || erust.IsStale != 0 {
		t.Fatalf("engines/rust census tally wrong: %+v", erust)
	}
}

// TestRenderMarkdown_IncludesCensusTable proves the census table is rendered
// into the markdown report whenever Current is present, with the header and a
// correctly-tallied data row.
func TestRenderMarkdown_IncludesCensusTable(t *testing.T) {
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "b", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true, HasLoudOnceWiring: true, HasIsStalePredicate: true}},
		{Name: "c", Cohort: "flagships", Substrate: SubstrateGo, Markers: Markers{KAT1HexPinned: true}},
	}}
	rep := Diff(nil, cur)
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "## Cohort census (current snapshot)") {
		t.Fatalf("census section header missing:\n%s", out)
	}
	// Row: Cohort | Substrate | Total | KAT1 | LiabFooter | LoudOnce | IsStale
	// = flagships | go | 2 | 2 | 0 | 1 | 1
	if !strings.Contains(out, "| flagships | go | 2 | 2 | 0 | 1 | 1 |") {
		t.Fatalf("expected flagships/go census row not found:\n%s", out)
	}
}

// TestRenderMarkdown_NoCensusWhenNoCurrent confirms the census section is
// omitted when there is no current snapshot (it is keyed on report.Current).
func TestRenderMarkdown_NoCensusWhenNoCurrent(t *testing.T) {
	rep := &DiffReport{Current: nil, Previous: nil, Summary: Summary{}}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Cohort census") {
		t.Fatalf("census table must be omitted with no current snapshot:\n%s", buf.String())
	}
}
