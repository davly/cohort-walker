package catalogue

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTemp writes body to a temp .md file and returns its path. Helper
// shared by the edge-case tests below.
func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.md")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// entry returns the parsed REntry with the given RuleID and whether it
// was found.
func entry(doc RCatalogueDoc, id string) (REntry, bool) {
	for _, e := range doc.Entries {
		if e.RuleID == id {
			return e, true
		}
	}
	return REntry{}, false
}

// idSet returns the set of RuleIDs present in the parsed doc.
func idSet(doc RCatalogueDoc) map[string]bool {
	s := make(map[string]bool, len(doc.Entries))
	for _, e := range doc.Entries {
		s[e.RuleID] = true
	}
	return s
}

// TestParseMissingPartXII asserts that a file with no Part XII header
// yields an empty entry list (not an error). The parser only emits
// headings seen *after* the Part XII anchor.
func TestParseMissingPartXII(t *testing.T) {
	body := "# Standard\n\n## Part XI — Watchlist\n\n### R25 — should be ignored, no Part XII\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Entries) != 0 {
		t.Fatalf("got %d entries, want 0 (no Part XII section present)", len(doc.Entries))
	}
	if doc.Summary.TotalEntries != 0 || doc.Summary.HighestRNumber != 0 {
		t.Fatalf("summary not zeroed for empty parse: %+v", doc.Summary)
	}
}

// TestPartXIIIBoundaryNotMatched is the regression guard for the
// trailing-space anchor: "## Part XII " must NOT prefix-match
// "## Part XIII". A heading appearing only under Part XIII must be
// excluded, and a "## Part XIII" line must terminate Part XII parsing.
func TestPartXIIIBoundaryNotMatched(t *testing.T) {
	body := "## Part XII — Retrofits\n\n" +
		"### R200 — inside part XII\n- x\n\n" +
		"## Part XIII — Innovations\n\n" +
		"### R201 — inside part XIII, must be excluded\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ids := idSet(doc)
	if !ids["R200"] {
		t.Error("R200 (inside Part XII) was not parsed")
	}
	if ids["R201"] {
		t.Error("R201 (inside Part XIII) was incorrectly parsed — Part XII boundary leaked")
	}
}

// TestSubclauseDotPrecedence asserts that a dotted rule id (R145.B) is
// detected as a sub-clause of R145, and that the dot path wins even when
// a later dash exists in the heading body.
func TestSubclauseDotPrecedence(t *testing.T) {
	body := "## Part XII — Retrofits\n\n### R145.B — SIBLING-NOT-STACKED hardening\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := entry(doc, "R145.B")
	if !ok {
		t.Fatal("R145.B not parsed")
	}
	if !e.IsSubclause {
		t.Error("R145.B should be a sub-clause")
	}
	if e.ParentRuleID != "R145" {
		t.Errorf("R145.B parent = %q, want R145", e.ParentRuleID)
	}
}

// TestSubclauseDashNamed asserts that a dash-named rule id like
// R143-OFFLINE-CONTRACT-PIN is treated as a sub-clause of R143 (the
// parent prefix is a parseable Rnnn).
func TestSubclauseDashNamed(t *testing.T) {
	body := "## Part XII — Retrofits\n\n### R143-OFFLINE-CONTRACT-PIN — placeholder-mode pin\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := entry(doc, "R143-OFFLINE-CONTRACT-PIN")
	if !ok {
		t.Fatal("R143-OFFLINE-CONTRACT-PIN not parsed")
	}
	if !e.IsSubclause || e.ParentRuleID != "R143" {
		t.Errorf("parent = %q, IsSubclause = %v; want R143 / true", e.ParentRuleID, e.IsSubclause)
	}
}

// TestTopLevelRuleNotSubclause asserts a plain Rnnn heading is top-level
// (not a sub-clause) and carries no ParentRuleID.
func TestTopLevelRuleNotSubclause(t *testing.T) {
	body := "## Part XII — Retrofits\n\n### R151 — KAT-AS-COHORT-INVARIANT\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := entry(doc, "R151")
	if !ok {
		t.Fatal("R151 not parsed")
	}
	if e.IsSubclause {
		t.Error("R151 should be top-level, got sub-clause")
	}
	if e.ParentRuleID != "" {
		t.Errorf("R151 ParentRuleID = %q, want empty", e.ParentRuleID)
	}
}

// TestPromotedDateExtraction asserts the first ISO date in a heading is
// captured, and that a heading without a date leaves PromotedDate empty.
func TestPromotedDateExtraction(t *testing.T) {
	body := "## Part XII — Retrofits\n\n" +
		"### R143 — LOUD-ONCE (4/3 — process-scoped, 2026-05-11)\n- x\n\n" +
		"### R152 — no date here at all\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	withDate, ok := entry(doc, "R143")
	if !ok {
		t.Fatal("R143 not parsed")
	}
	if withDate.PromotedDate != "2026-05-11" {
		t.Errorf("R143 PromotedDate = %q, want 2026-05-11", withDate.PromotedDate)
	}
	noDate, ok := entry(doc, "R152")
	if !ok {
		t.Fatal("R152 not parsed")
	}
	if noDate.PromotedDate != "" {
		t.Errorf("R152 PromotedDate = %q, want empty", noDate.PromotedDate)
	}
}

// TestRawHeadingStripsMarkdownPrefix asserts RawHeading is the heading
// verbatim minus the leading "### " (so callers can re-style without
// re-parsing) and that Title is the body after the em-dash separator.
func TestRawHeadingAndTitle(t *testing.T) {
	body := "## Part XII — Retrofits\n\n### R151 — KAT cohort invariant pin\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := entry(doc, "R151")
	if !ok {
		t.Fatal("R151 not parsed")
	}
	const wantRaw = "R151 — KAT cohort invariant pin"
	if e.RawHeading != wantRaw {
		t.Errorf("RawHeading = %q, want %q", e.RawHeading, wantRaw)
	}
	const wantTitle = "KAT cohort invariant pin"
	if e.Title != wantTitle {
		t.Errorf("Title = %q, want %q", e.Title, wantTitle)
	}
}

// TestLineNumberIsOneBased asserts LineNumber points at the actual source
// line (1-based) so a caller can grep -nFx the RawHeading to confirm.
func TestLineNumberIsOneBased(t *testing.T) {
	// Line 1: ## Part XII ...
	// Line 2: (blank)
	// Line 3: ### R151 ...
	body := "## Part XII — Retrofits\n\n### R151 — anchor\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e, ok := entry(doc, "R151")
	if !ok {
		t.Fatal("R151 not parsed")
	}
	if e.LineNumber != 3 {
		t.Errorf("R151 LineNumber = %d, want 3", e.LineNumber)
	}
}

// TestSummaryCounts asserts the aggregate counts: total, top-level vs
// sub-clause split, and HighestRNumber extracted across dotted and
// dash-named suffixes.
func TestSummaryCounts(t *testing.T) {
	body := "## Part XII — Retrofits\n\n" +
		"### R25 — base\n- x\n\n" +
		"### R145.B — subclause dotted\n- x\n\n" +
		"### R143-OFFLINE-CONTRACT-PIN — subclause dashed\n- x\n\n" +
		"### R210 — highest top-level\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s := doc.Summary
	if s.TotalEntries != 4 {
		t.Errorf("TotalEntries = %d, want 4", s.TotalEntries)
	}
	if s.SubclauseEntries != 2 {
		t.Errorf("SubclauseEntries = %d, want 2 (R145.B + R143-...)", s.SubclauseEntries)
	}
	if s.TopLevelEntries != 2 {
		t.Errorf("TopLevelEntries = %d, want 2 (R25 + R210)", s.TopLevelEntries)
	}
	if s.HighestRNumber != 210 {
		t.Errorf("HighestRNumber = %d, want 210 (dash/dot suffixes stripped before max)", s.HighestRNumber)
	}
}

// TestNonRuleHeadingsExcluded asserts H3 headings that are not R-rules
// (e.g. "### Notes") and non-heading lines inside Part XII are skipped.
func TestNonRuleHeadingsExcluded(t *testing.T) {
	body := "## Part XII — Retrofits\n\n" +
		"### Notes on usage\nsome prose\n\n" +
		"#### R300 — wrong heading depth (H4, not H3)\n- x\n\n" +
		"### R151 — real rule\n- x\n"
	doc, err := Parse(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ids := idSet(doc)
	if ids["R300"] {
		t.Error("H4 #### R300 should not be parsed (only ### H3 rules count)")
	}
	if !ids["R151"] {
		t.Error("R151 (valid H3 rule) should be parsed")
	}
	// "### Notes" is not an R-heading; it must not appear.
	if len(doc.Entries) != 1 {
		t.Errorf("got %d entries, want exactly 1 (only R151)", len(doc.Entries))
	}
}

// TestParseNonexistentFile asserts an I/O error is surfaced (not swallowed)
// when the source path does not exist.
func TestParseNonexistentFile(t *testing.T) {
	_, err := Parse(filepath.Join(t.TempDir(), "does-not-exist.md"))
	if err == nil {
		t.Fatal("Parse of nonexistent file returned nil error, want non-nil")
	}
}
