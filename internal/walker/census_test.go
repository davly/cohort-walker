package walker

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// census_test.go covers cw-absolute-census: members below the R174 5-of-5 bar
// must be reported in ABSOLUTE terms (named), so a chronically-incomplete
// baseline member — which produces no delta — is still visible.

// belowMarkers is missing loud_once_wiring, is_stale_predicate, liability_footer.
var belowMarkers = Markers{HasMirrorMarkPkg: true, KAT1HexPinned: true}

// fullMarkers meets the 5-of-5 bar.
var fullMarkers = Markers{
	HasMirrorMarkPkg:    true,
	KAT1HexPinned:       true,
	HasLoudOnceWiring:   true,
	HasIsStalePredicate: true,
	HasLiabilityFooter:  true,
}

// TestBelowR174Members_ListsAndSorts checks the absolute census lists only
// below-bar members, names their missing markers, and is sorted by
// (cohort, member) deterministically.
func TestBelowR174Members_ListsAndSorts(t *testing.T) {
	snap := &Snapshot{Members: []Member{
		{Name: "zeta", Cohort: "flagships", Substrate: SubstrateGo, Markers: belowMarkers},
		{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
		{Name: "beta", Cohort: "engines", Substrate: SubstrateRust, Markers: Markers{}},
	}}
	rows := BelowR174Members(snap)
	if len(rows) != 2 {
		t.Fatalf("want 2 below-bar members (zeta, beta); got %d: %+v", len(rows), rows)
	}
	// Sorted by (cohort, member): engines/beta before flagships/zeta.
	if rows[0].Cohort != "engines" || rows[0].Member != "beta" {
		t.Fatalf("row 0 want engines/beta, got %s/%s", rows[0].Cohort, rows[0].Member)
	}
	if rows[1].Cohort != "flagships" || rows[1].Member != "zeta" {
		t.Fatalf("row 1 want flagships/zeta, got %s/%s", rows[1].Cohort, rows[1].Member)
	}
	if rows[1].Missing != "loud_once_wiring,is_stale_predicate,liability_footer" {
		t.Fatalf("zeta missing-marker list wrong: %q", rows[1].Missing)
	}
	// beta lacks everything.
	if rows[0].Missing != "mirrormark_pkg,kat1_hex_pin,loud_once_wiring,is_stale_predicate,liability_footer" {
		t.Fatalf("beta missing-marker list wrong: %q", rows[0].Missing)
	}
}

// TestBelowR174Members_NilSnapshot is the nil guard.
func TestBelowR174Members_NilSnapshot(t *testing.T) {
	if rows := BelowR174Members(nil); rows != nil {
		t.Fatalf("nil snapshot must return nil; got %+v", rows)
	}
}

// TestRenderMarkdown_BelowR174AbsoluteCensus is the core value proof: a member
// below the bar in BOTH snapshots produces NO delta, yet must appear in the
// absolute below-bar census section.
func TestRenderMarkdown_BelowR174AbsoluteCensus(t *testing.T) {
	prev := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: belowMarkers},
		{Name: "delta", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
	}}
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: belowMarkers},
		{Name: "delta", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
	}}
	rep := Diff(prev, cur)

	// Prove the gap: an unchanged below-bar member produces no missing_r174 delta.
	for _, d := range rep.Deltas {
		if d.Kind == DeltaMissingR174 {
			t.Fatalf("unchanged below-bar member must NOT produce a delta; got %+v", d)
		}
	}

	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "## Below R174 5-of-5 (current snapshot)") {
		t.Fatalf("absolute below-bar section header missing:\n%s", out)
	}
	if !strings.Contains(out, "| flagships | gamma | go | loud_once_wiring,is_stale_predicate,liability_footer |") {
		t.Fatalf("below-bar row for chronically-incomplete gamma missing:\n%s", out)
	}
	// delta meets the bar -> must NOT appear as a below-bar row.
	if strings.Contains(out, "| flagships | delta | go |") {
		t.Fatalf("full member must not appear in the below-bar census:\n%s", out)
	}
}

// TestRenderMarkdown_BelowR174_AllMeet covers the all-clear message.
func TestRenderMarkdown_BelowR174_AllMeet(t *testing.T) {
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
	}}
	rep := Diff(nil, cur)
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "_All current members meet R174 5-of-5._") {
		t.Fatalf("all-meet message missing:\n%s", buf.String())
	}
}

// TestRenderJSON_IncludesBelowR174 proves the below-bar census is machine-
// readable in the JSON delta output.
func TestRenderJSON_IncludesBelowR174(t *testing.T) {
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "gamma", Cohort: "flagships", Substrate: SubstrateGo, Markers: belowMarkers},
		{Name: "delta", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
	}}
	rep := Diff(cur, cur) // prev==cur: no deltas, gamma chronically below bar
	var buf bytes.Buffer
	if err := RenderJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		BelowR174 []BelowR174Row `json:"below_r174_5of5"`
	}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("RenderJSON output invalid: %v\nbody=%s", err, buf.String())
	}
	if len(payload.BelowR174) != 1 || payload.BelowR174[0].Member != "gamma" {
		t.Fatalf("below_r174_5of5 must name gamma; got %+v", payload.BelowR174)
	}
	if payload.BelowR174[0].Missing != "loud_once_wiring,is_stale_predicate,liability_footer" {
		t.Fatalf("gamma missing list wrong: %q", payload.BelowR174[0].Missing)
	}
}

// TestRenderJSON_BelowR174_EmptyNotNull confirms the field serialises to [] not
// null when no member is below the bar (stable machine-readable shape).
func TestRenderJSON_BelowR174_EmptyNotNull(t *testing.T) {
	cur := &Snapshot{CapturedAt: fixedTime(), Members: []Member{
		{Name: "alpha", Cohort: "flagships", Substrate: SubstrateGo, Markers: fullMarkers},
	}}
	rep := Diff(nil, cur)
	var buf bytes.Buffer
	if err := RenderJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"below_r174_5of5": []`) {
		t.Fatalf("empty below-bar census must serialise to []; body=%s", buf.String())
	}
}
