// Package catalogue parses Part XII of ECOSYSTEM_QUALITY_STANDARD.md into
// a structured RCatalogueDoc — one REntry per `### Rnnn[.X]` heading.
//
// Cohort discipline:
//   - The parser is stdlib-only. No regex library dependency.
//   - It tolerates heading variants seen in the actual file: em-dash
//     (`—`), regular dash (`-`), parenthesised promotion-date suffixes,
//     "RETIRED" suffixes, "sub-clause of Rnnn" subordination markers.
//   - It does NOT attempt to extract the prose body of each rule (that
//     would require structural assumptions about heading-to-heading
//     content blocks). Phase 2 may add it; Phase 1 returns headings only.
package catalogue

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// partXIIHeader is the literal H2 anchor we use to find the start of the
// catalogue. We stop at the next H2 (any line starting with "## ").
// Note the trailing space: critical to NOT prefix-match "## Part XIII".
const partXIIHeader = "## Part XII "

// ruleHeadingRE matches `### Rnnn` or `### Rnnn.X` (with optional suffix).
// We deliberately match leniently because Part XII has accumulated many
// hand-edited variants over its lifetime.
var ruleHeadingRE = regexp.MustCompile(`^### (R\d+(?:\.[A-Za-z0-9]+)?(?:[ -]\S+)?)(?:\s+.*)?$`)

// ruleIDLeadRE extracts the leading R-identifier with optional ".X" or
// "-NAME" suffix. Anchored at start; trailing whitespace ends the match.
var ruleIDLeadRE = regexp.MustCompile(`^(R\d+(?:\.[A-Za-z0-9]+)?(?:-[A-Z][A-Z0-9-]*)?)`)

// dateRE finds the first ISO date in the heading line (yyyy-mm-dd).
var dateRE = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`)

// Parse reads the markdown file at sourcePath and returns the catalogue
// document. Errors are returned for I/O failures; per-line parse errors
// are silently skipped — the parser never aborts mid-file. Skipped lines
// can be reported via callers that hash entry count vs heading-line count
// if a strict-mode is later needed.
func Parse(sourcePath string) (RCatalogueDoc, error) {
	f, err := os.Open(sourcePath)
	if err != nil {
		return RCatalogueDoc{}, fmt.Errorf("catalogue: open %s: %w", sourcePath, err)
	}
	defer f.Close()

	doc := RCatalogueDoc{
		SchemaVersion: SchemaVersion,
		SourcePath:    sourcePath,
		PartTitle:     "Part XII — Additional Retrofits from Session 36 + Blitz + Infrastructure (R25+)",
	}

	scanner := bufio.NewScanner(f)
	// Large lines exist in the catalogue (some have wide one-liner blocks).
	// Default buffer is 64 KiB which is plenty here but bump for safety.
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	inPartXII := false
	lineNum := 0
	var entries []REntry

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Track entry into Part XII.
		if !inPartXII {
			if strings.HasPrefix(line, partXIIHeader) {
				inPartXII = true
			}
			continue
		}

		// Stop at the next H2.
		if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, partXIIHeader) {
			break
		}

		if !strings.HasPrefix(line, "### R") {
			continue
		}

		e, ok := parseHeading(line, lineNum)
		if !ok {
			continue
		}
		entries = append(entries, e)
	}

	if err := scanner.Err(); err != nil {
		return RCatalogueDoc{}, fmt.Errorf("catalogue: scan %s: %w", sourcePath, err)
	}

	doc.Entries = entries
	doc.Summary = summarise(entries)
	return doc, nil
}

// parseHeading extracts an REntry from a `### Rnnn ...` line. Returns
// ok=false when the line did not parse as an R-rule heading.
func parseHeading(line string, lineNum int) (REntry, bool) {
	stripped := strings.TrimPrefix(line, "### ")
	idMatch := ruleIDLeadRE.FindString(stripped)
	if idMatch == "" {
		return REntry{}, false
	}
	// Title is everything after the id (and any leading em-dash / dash).
	title := strings.TrimSpace(stripped[len(idMatch):])
	title = strings.TrimLeft(title, "— -—")
	title = strings.TrimSpace(title)

	e := REntry{
		RawHeading: stripped,
		RuleID:     idMatch,
		Title:      title,
		LineNumber: lineNum,
	}
	if d := dateRE.FindString(line); d != "" {
		e.PromotedDate = d
	}
	if dot := strings.Index(idMatch, "."); dot > 0 {
		e.IsSubclause = true
		e.ParentRuleID = idMatch[:dot]
	}
	// Heading variants like "R143-OFFLINE-CONTRACT-PIN" also count as
	// sub-clauses of R143.
	if dash := strings.Index(idMatch, "-"); dash > 0 && !e.IsSubclause {
		// Only treat as sub-clause if the prefix is a parseable Rnnn.
		parentCand := idMatch[:dash]
		if _, err := strconv.Atoi(strings.TrimPrefix(parentCand, "R")); err == nil {
			e.IsSubclause = true
			e.ParentRuleID = parentCand
		}
	}
	return e, true
}

// summarise computes the aggregate counts.
func summarise(entries []REntry) RCatSummary {
	s := RCatSummary{}
	s.TotalEntries = len(entries)
	highest := 0
	for _, e := range entries {
		if e.IsSubclause {
			s.SubclauseEntries++
		} else {
			s.TopLevelEntries++
		}
		// Strip leading "R" and trailing suffix to extract the integer.
		num := strings.TrimPrefix(e.RuleID, "R")
		if dot := strings.Index(num, "."); dot > 0 {
			num = num[:dot]
		}
		if dash := strings.Index(num, "-"); dash > 0 {
			num = num[:dash]
		}
		if n, err := strconv.Atoi(num); err == nil && n > highest {
			highest = n
		}
	}
	s.HighestRNumber = highest
	return s
}
