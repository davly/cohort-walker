// report.go — emits drift reports in two formats:
//
//	* Markdown — human-readable, suitable for embedding in a PR
//	  comment or a CI-summary panel. Includes the R166 liability
//	  footer (required) and the R69a human-escape line.
//	* JSON — machine-readable, suitable for the GitHub Actions
//	  artefact and for downstream automation.

package walker

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/davly/cohort-walker/cohort/escape"
	"github.com/davly/cohort-walker/cohort/legal"
)

// RenderMarkdown writes a human-readable markdown drift report to w.
// The report always ends with the R166 liability footer + the R69a
// human-escape clause.
func RenderMarkdown(w io.Writer, report *DiffReport) error {
	if report == nil {
		return fmt.Errorf("nil report")
	}
	bw := &errWriter{w: w}

	bw.WriteString("# cohort-walker drift report\n\n")
	bw.WriteString(fmt.Sprintf("- Schema: `%s`\n", SchemaVersion))
	if report.Current != nil {
		bw.WriteString(fmt.Sprintf("- Current snapshot: %s\n", report.Current.CapturedAt.UTC().Format(time.RFC3339)))
	}
	if report.Previous != nil {
		bw.WriteString(fmt.Sprintf("- Previous snapshot: %s\n", report.Previous.CapturedAt.UTC().Format(time.RFC3339)))
	} else {
		bw.WriteString("- Previous snapshot: (none — baseline run)\n")
	}
	bw.WriteString("\n## Summary\n\n")
	bw.WriteString(fmt.Sprintf("- FAIL: %d\n- WARN: %d\n- INFO: %d\n- PASS: %d\n\n",
		report.Summary.Fail, report.Summary.Warn, report.Summary.Info, report.Summary.Pass))

	if len(report.Deltas) == 0 {
		bw.WriteString("_No drift detected._\n\n")
	} else {
		bw.WriteString("## Deltas\n\n")
		bw.WriteString("| Severity | Cohort | Member | Kind | Detail |\n")
		bw.WriteString("|---|---|---|---|---|\n")
		for _, d := range report.Deltas {
			bw.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				d.Severity, d.Cohort, d.Member, d.Kind, mdEscape(d.Detail)))
		}
		bw.WriteString("\n")
	}

	// Section: cohort census (per-substrate counts) — useful for at-a-
	// glance verification of "X new substrates joined this week".
	if report.Current != nil {
		bw.WriteString("## Cohort census (current snapshot)\n\n")
		bw.WriteString("| Cohort | Substrate | Members | KAT-1 pinned | LiabFooter | LoudOnce | IsStale |\n")
		bw.WriteString("|---|---|---|---|---|---|---|\n")
		for _, row := range cohortCensusRows(report.Current) {
			bw.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d | %d |\n",
				row.Cohort, row.Substrate, row.Total, row.KAT1, row.LiabilityFooter, row.LoudOnce, row.IsStale))
		}
		bw.WriteString("\n")

		// Section: absolute below-R174 census — names every current member that
		// fails the 5-of-5 bar regardless of whether it changed since the
		// baseline. The delta layer only flags NEW members, so this is the only
		// place a chronically-incomplete baseline member becomes visible.
		below := BelowR174Members(report.Current)
		bw.WriteString("## Below R174 5-of-5 (current snapshot)\n\n")
		if len(below) == 0 {
			bw.WriteString("_All current members meet R174 5-of-5._\n\n")
		} else {
			bw.WriteString("| Cohort | Member | Substrate | Missing markers |\n")
			bw.WriteString("|---|---|---|---|\n")
			for _, row := range below {
				bw.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					row.Cohort, row.Member, row.Substrate, mdEscape(row.Missing)))
			}
			bw.WriteString("\n")
		}
	}

	// R69a human-escape clause + R166 liability footer — both mandatory
	// for the regulator-handoff boundary.
	bw.WriteString("---\n\n")
	bw.WriteString(escape.HumanEscape)
	bw.WriteString("\n\n---\n\n")
	bw.WriteString(legal.LiabilityFooter)

	return bw.err
}

// RenderJSON writes the machine-readable JSON form to w.
func RenderJSON(w io.Writer, report *DiffReport) error {
	if report == nil {
		return fmt.Errorf("nil report")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Absolute below-bar census surfaced alongside the deltas so a downstream
	// consumer sees chronically-incomplete members, not only changed ones.
	// Normalise nil to an empty slice for a stable [] (never null) shape.
	below := BelowR174Members(report.Current)
	if below == nil {
		below = []BelowR174Row{}
	}
	out := struct {
		SchemaVersion string         `json:"schema_version"`
		LiabilityNote string         `json:"liability_note"`
		EscapeClause  string         `json:"human_escape"`
		Deltas        []Delta        `json:"deltas"`
		Summary       Summary        `json:"summary"`
		BelowR174     []BelowR174Row `json:"below_r174_5of5"`
	}{
		SchemaVersion: SchemaVersion,
		LiabilityNote: "see cohort/legal/liability_footer.go — output is informational, not a compliance verdict",
		EscapeClause:  escape.HumanEscape,
		Deltas:        report.Deltas,
		Summary:       report.Summary,
		BelowR174:     below,
	}
	return enc.Encode(out)
}

// BelowR174Row names a current-snapshot member that fails the R174 5-of-5
// bar, with the comma-joined list of missing markers. This is an ABSOLUTE
// census, not a delta: the missing_r174_5of5 DELTA is only ever emitted for
// NEW members (classifyAbsolute), so a member that was already below the bar
// in the baseline and stayed there produces no delta and would otherwise be
// invisible. This row surfaces those chronically-incomplete members.
type BelowR174Row struct {
	Cohort    string `json:"cohort"`
	Member    string `json:"member"`
	Substrate string `json:"substrate"`
	Missing   string `json:"missing_markers"`
}

// BelowR174Members returns every current member failing the 5-of-5 bar,
// sorted by (cohort, member) for determinism. Returns nil for a nil snapshot.
func BelowR174Members(snap *Snapshot) []BelowR174Row {
	if snap == nil {
		return nil
	}
	var rows []BelowR174Row
	for _, m := range snap.Members {
		if meetsR174FiveOfFive(m.Markers) {
			continue
		}
		rows = append(rows, BelowR174Row{
			Cohort:    m.Cohort,
			Member:    m.Name,
			Substrate: string(m.Substrate),
			Missing:   missingR174Detail(m.Markers),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Cohort != rows[j].Cohort {
			return rows[i].Cohort < rows[j].Cohort
		}
		return rows[i].Member < rows[j].Member
	})
	return rows
}

// censusRow is one (cohort, substrate) summary row.
type censusRow struct {
	Cohort          string
	Substrate       string
	Total           int
	KAT1            int
	LiabilityFooter int
	LoudOnce        int
	IsStale         int
}

func cohortCensusRows(snap *Snapshot) []censusRow {
	bucket := map[string]*censusRow{}
	for _, m := range snap.Members {
		key := m.Cohort + "|" + string(m.Substrate)
		r, ok := bucket[key]
		if !ok {
			r = &censusRow{Cohort: m.Cohort, Substrate: string(m.Substrate)}
			bucket[key] = r
		}
		r.Total++
		if m.Markers.KAT1HexPinned {
			r.KAT1++
		}
		if m.Markers.HasLiabilityFooter {
			r.LiabilityFooter++
		}
		if m.Markers.HasLoudOnceWiring {
			r.LoudOnce++
		}
		if m.Markers.HasIsStalePredicate {
			r.IsStale++
		}
	}
	out := make([]censusRow, 0, len(bucket))
	for _, r := range bucket {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cohort != out[j].Cohort {
			return out[i].Cohort < out[j].Cohort
		}
		return out[i].Substrate < out[j].Substrate
	})
	return out
}

// errWriter chains write errors so we don't have to error-check every
// line.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) WriteString(s string) {
	if e.err != nil {
		return
	}
	_, e.err = io.WriteString(e.w, s)
}

// mdEscape escapes pipe characters in the markdown table cells.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// SaveSnapshot writes a snapshot as canonical pretty-printed JSON.
func SaveSnapshot(w io.Writer, snap *Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

// LoadSnapshot reads a snapshot from r.
func LoadSnapshot(r io.Reader) (*Snapshot, error) {
	dec := json.NewDecoder(r)
	var snap Snapshot
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &snap, nil
}
