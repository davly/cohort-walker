package catalogue

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleCatalogue = `# ECOSYSTEM QUALITY STANDARD

## Part XI — Pre-Mortem Watchlist

### R24 — fake heading not in part XII
- decoy

## Part XII — Additional Retrofits

### R25 — Inverted ESCAPE alarm annotation
- **What:** test
- **Evidence:** test

### R143 — LOUD-ONCE-WARNING-FLAG (4/3 — process-scoped degraded-mode disclosure, 2026-05-11)
- **What:** flag the once-only banner
- **Evidence:** multiple

### R143-OFFLINE-CONTRACT-PIN — placeholder-mode anti-false-positive pin (sub-clause of R143; promoted 2026-05-27)
- **What:** test

### R145.B — SIBLING-NOT-STACKED
- **What:** test

### R151 — R-KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN
- **What:** test

## Part XIII — Canonical Innovations Library

### R999 — should not be parsed (outside Part XII)
- decoy
`

func TestParseSampleCatalogue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.md")
	if err := os.WriteFile(path, []byte(sampleCatalogue), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion == 0 {
		t.Error("schema version not set")
	}
	if len(doc.Entries) < 5 {
		t.Fatalf("got %d entries, want >= 5", len(doc.Entries))
	}
	gotIDs := make(map[string]bool)
	for _, e := range doc.Entries {
		gotIDs[e.RuleID] = true
	}
	for _, expect := range []string{"R25", "R143", "R143-OFFLINE-CONTRACT-PIN", "R145.B", "R151"} {
		if !gotIDs[expect] {
			t.Errorf("expected entry %s not present in parsed list", expect)
		}
	}
	// Decoy must be excluded.
	for _, e := range doc.Entries {
		if e.RuleID == "R24" || e.RuleID == "R999" {
			t.Errorf("decoy heading %s was incorrectly parsed", e.RuleID)
		}
	}
	// R145.B is a subclause of R145.
	for _, e := range doc.Entries {
		if e.RuleID == "R145.B" {
			if !e.IsSubclause || e.ParentRuleID != "R145" {
				t.Errorf("R145.B parsed parent = %q, IsSubclause = %v", e.ParentRuleID, e.IsSubclause)
			}
		}
		// R143-OFFLINE-CONTRACT-PIN sub-clause of R143.
		if e.RuleID == "R143-OFFLINE-CONTRACT-PIN" {
			if !e.IsSubclause || e.ParentRuleID != "R143" {
				t.Errorf("R143-OFFLINE-CONTRACT-PIN parsed parent = %q, IsSubclause = %v", e.ParentRuleID, e.IsSubclause)
			}
		}
		if e.RuleID == "R143" && e.PromotedDate != "2026-05-11" {
			t.Errorf("R143 promoted date = %q, want 2026-05-11", e.PromotedDate)
		}
	}
	if doc.Summary.HighestRNumber < 151 {
		t.Errorf("HighestRNumber = %d, want >= 151", doc.Summary.HighestRNumber)
	}
}
