// JSON wire shapes for the `r_catalogue` document. Ported from the
// overnight-build line's internal/output package (branch
// godfather/overnight-build-2026-06-10-cohort-walker) — on main the
// catalogue package is self-contained so it composes with the walker
// architecture without reintroducing the retired output package.
//
// Cohort discipline (BR1 §11):
//   - JSON fields are explicit; no implicit zero-value semantics.
//   - Lists are sorted deterministically so byte-identical re-runs
//     compare cleanly under `git diff`.
package catalogue

// SchemaVersion is the wire-format version emitted in the top-level
// document. Bump on any breaking change to the JSON shape.
const SchemaVersion = 1

// Tool identifies the binary that produced a report. Embedded in the
// top-level document so artefacts are traceable across machines.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RCatalogueDoc is the top-level shape for `cohort-walker r_catalogue` —
// the parsed Part XII of ECOSYSTEM_QUALITY_STANDARD.md.
type RCatalogueDoc struct {
	SchemaVersion int         `json:"schema_version"`
	Tool          Tool        `json:"tool"`
	GeneratedAt   string      `json:"generated_at"`
	SourcePath    string      `json:"source_path"`
	PartTitle     string      `json:"part_title"`
	Entries       []REntry    `json:"entries"`
	Summary       RCatSummary `json:"summary"`
}

// REntry is one R-rule heading parsed from Part XII. Heading lines look
// like `### R151 — R-KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN ...`.
type REntry struct {
	// RawHeading is the markdown heading line verbatim minus the leading
	// `### ` (so callers can re-style without re-parsing).
	RawHeading string `json:"raw_heading"`

	// RuleID is the leading R-identifier (e.g. "R151", "R145.B",
	// "R143-OFFLINE-CONTRACT-PIN"). Empty if the heading could not be
	// parsed.
	RuleID string `json:"rule_id"`

	// Title is the heading body after the first em-dash separator (or
	// the whole heading if no em-dash is present).
	Title string `json:"title"`

	// LineNumber is the 1-based line where the heading appears in the
	// source file. Lets callers `grep -nFx <heading>` to confirm.
	LineNumber int `json:"line_number"`

	// PromotedDate is the date string extracted from the title (e.g.
	// "2026-05-22"). Empty if no ISO date is present.
	PromotedDate string `json:"promoted_date,omitempty"`

	// IsSubclause is true if the rule id contains a "." (e.g. R145.B).
	IsSubclause bool `json:"is_subclause"`

	// ParentRuleID is the parent rule id when IsSubclause is true (e.g.
	// "R145" for "R145.B"). Empty for top-level rules.
	ParentRuleID string `json:"parent_rule_id,omitempty"`
}

// RCatSummary is the aggregate counts emitted alongside the per-entry
// list. Useful for at-a-glance health checks.
type RCatSummary struct {
	TotalEntries     int `json:"total_entries"`
	TopLevelEntries  int `json:"top_level_entries"`
	SubclauseEntries int `json:"subclause_entries"`
	HighestRNumber   int `json:"highest_r_number"`
}
