// diff.go — compare current scan to previous snapshot and classify
// every member-level delta into the R-rule taxonomy:
//
//   - KAT-1 divergence (FAIL) — a flagship that previously pinned the
//     canonical KAT-1 hex but no longer does. By construction of R151
//     this is a regression-class incident: byte-equality across the
//     cohort is the whole point.
//   - Missing R174 5-of-5 (WARN) — a flagship missing one or more of
//     the 5 marker bits a fully-onboarded cohort member would expose.
//   - Wire-format drift (FAIL) — a flagship now using a non-canonical
//     wire prefix (e.g. "v1:" instead of "lore@v1:"). This is a
//     cross-substrate parity break.
//   - INDEX-LIE catches (FAIL) — declared modules / packages whose disk
//     path is missing. R155.A class.
//   - New members (INFO) — appeared since last snapshot.
//   - Dropped members (WARN) — disappeared since last snapshot.

package walker

import (
	"sort"
)

// Severity is the four-state outcome class used by the report layer.
type Severity string

const (
	SeverityInfo Severity = "INFO"
	SeverityWarn Severity = "WARN"
	SeverityFail Severity = "FAIL"
	SeverityPass Severity = "PASS"
)

// Delta is a single row in the drift report.
type Delta struct {
	Member    string   `json:"member"`
	Cohort    string   `json:"cohort"`
	Kind      DeltaKind `json:"kind"`
	Severity  Severity `json:"severity"`
	Detail    string   `json:"detail"`
	WasValue  string   `json:"was,omitempty"`
	NowValue  string   `json:"now,omitempty"`
}

// DeltaKind enumerates every classified drift kind. Adding a new kind
// requires a new const + a new entry in computeDelta + tests.
type DeltaKind string

const (
	DeltaKAT1Lost          DeltaKind = "kat1_lost"
	DeltaKAT1Gained        DeltaKind = "kat1_gained"
	DeltaWireFormatDrift   DeltaKind = "wire_format_drift"
	DeltaIndexLie          DeltaKind = "index_lie"
	DeltaMissingR174       DeltaKind = "missing_r174_5of5"
	DeltaNewMember         DeltaKind = "new_member"
	DeltaDroppedMember     DeltaKind = "dropped_member"
	DeltaSubstrateChanged  DeltaKind = "substrate_changed"
	DeltaMarkerLost        DeltaKind = "marker_lost"
	DeltaMarkerGained      DeltaKind = "marker_gained"
)

// DiffReport is the full classified drift between two snapshots.
type DiffReport struct {
	Previous *Snapshot `json:"-"`
	Current  *Snapshot `json:"-"`
	Deltas   []Delta   `json:"deltas"`
	Summary  Summary   `json:"summary"`
}

// Summary aggregates per-severity counts for the CI exit-code layer.
type Summary struct {
	Pass int `json:"pass"`
	Info int `json:"info"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// HasFail returns true iff any FAIL severity is present. Used by the
// CI layer to decide exit code.
func (s Summary) HasFail() bool { return s.Fail > 0 }

// Diff compares prev to cur and returns a classified DiffReport. nil
// prev is treated as "everything is new" (baseline run).
func Diff(prev, cur *Snapshot) *DiffReport {
	report := &DiffReport{Previous: prev, Current: cur}

	prevByKey := map[string]Member{}
	if prev != nil {
		for _, m := range prev.Members {
			prevByKey[m.Cohort+"/"+m.Name] = m
		}
	}
	curByKey := map[string]Member{}
	if cur != nil {
		for _, m := range cur.Members {
			curByKey[m.Cohort+"/"+m.Name] = m
		}
	}

	// New members.
	for k, m := range curByKey {
		if _, was := prevByKey[k]; !was {
			report.Deltas = append(report.Deltas, Delta{
				Member: m.Name, Cohort: m.Cohort,
				Kind: DeltaNewMember, Severity: SeverityInfo,
				Detail: "new cohort member appeared since previous snapshot",
			})
		}
	}

	// Dropped members.
	for k, m := range prevByKey {
		if _, still := curByKey[k]; !still {
			report.Deltas = append(report.Deltas, Delta{
				Member: m.Name, Cohort: m.Cohort,
				Kind: DeltaDroppedMember, Severity: SeverityWarn,
				Detail: "cohort member disappeared since previous snapshot",
			})
		}
	}

	// Per-member deltas.
	for k, now := range curByKey {
		was, existed := prevByKey[k]
		if !existed {
			// already accounted for under NewMember; but a new member
			// can still ship INDEX-LIE / wire-format drift on day one
			classifyAbsolute(now, &report.Deltas)
			continue
		}
		classifyDelta(was, now, &report.Deltas)
		// Absolute classification on top — wire-format drift and INDEX-
		// LIE are absolute breaks regardless of prior state.
		classifyAbsoluteIfNew(was, now, &report.Deltas)
	}

	// Sort deltas: FAIL first, then WARN, INFO, PASS; ties on member name.
	sort.SliceStable(report.Deltas, func(i, j int) bool {
		si, sj := severityRank(report.Deltas[i].Severity), severityRank(report.Deltas[j].Severity)
		if si != sj {
			return si < sj
		}
		if report.Deltas[i].Member != report.Deltas[j].Member {
			return report.Deltas[i].Member < report.Deltas[j].Member
		}
		return string(report.Deltas[i].Kind) < string(report.Deltas[j].Kind)
	})

	// Aggregate.
	for _, d := range report.Deltas {
		switch d.Severity {
		case SeverityPass:
			report.Summary.Pass++
		case SeverityInfo:
			report.Summary.Info++
		case SeverityWarn:
			report.Summary.Warn++
		case SeverityFail:
			report.Summary.Fail++
		}
	}

	return report
}

// classifyDelta inspects the was→now transition for a member and emits
// any deltas it implies.
func classifyDelta(was, now Member, into *[]Delta) {
	if was.Substrate != now.Substrate {
		*into = append(*into, Delta{
			Member: now.Name, Cohort: now.Cohort,
			Kind: DeltaSubstrateChanged, Severity: SeverityWarn,
			Detail:  "substrate language changed",
			WasValue: string(was.Substrate), NowValue: string(now.Substrate),
		})
	}

	// KAT-1 lost vs gained.
	if was.Markers.KAT1HexPinned && !now.Markers.KAT1HexPinned {
		*into = append(*into, Delta{
			Member: now.Name, Cohort: now.Cohort,
			Kind: DeltaKAT1Lost, Severity: SeverityFail,
			Detail: "KAT-1 hex pin lost — byte-equality anchor missing",
		})
	}
	if !was.Markers.KAT1HexPinned && now.Markers.KAT1HexPinned {
		*into = append(*into, Delta{
			Member: now.Name, Cohort: now.Cohort,
			Kind: DeltaKAT1Gained, Severity: SeverityPass,
			Detail: "KAT-1 hex pin gained — cohort member onboarded to R151",
		})
	}

	// Individual marker regressions.
	classifyMarkerChange("mirrormark_pkg", was.Markers.HasMirrorMarkPkg, now.Markers.HasMirrorMarkPkg, now, into)
	classifyMarkerChange("loud_once_wiring", was.Markers.HasLoudOnceWiring, now.Markers.HasLoudOnceWiring, now, into)
	classifyMarkerChange("is_stale_predicate", was.Markers.HasIsStalePredicate, now.Markers.HasIsStalePredicate, now, into)
	classifyMarkerChange("liability_footer", was.Markers.HasLiabilityFooter, now.Markers.HasLiabilityFooter, now, into)
}

func classifyMarkerChange(name string, was, now bool, m Member, into *[]Delta) {
	switch {
	case was && !now:
		*into = append(*into, Delta{
			Member: m.Name, Cohort: m.Cohort,
			Kind: DeltaMarkerLost, Severity: SeverityFail,
			Detail: "marker lost: " + name,
		})
	case !was && now:
		*into = append(*into, Delta{
			Member: m.Name, Cohort: m.Cohort,
			Kind: DeltaMarkerGained, Severity: SeverityPass,
			Detail: "marker gained: " + name,
		})
	}
}

// classifyAbsolute is invoked for new members that have no prior baseline.
func classifyAbsolute(m Member, into *[]Delta) {
	if drift := m.Markers.WireFormatPrefixDrift; drift != "" {
		*into = append(*into, Delta{
			Member: m.Name, Cohort: m.Cohort,
			Kind: DeltaWireFormatDrift, Severity: SeverityFail,
			Detail: "wire-format drift: " + drift + " (canonical: " + CanonicalWireFormatPrefix + ")",
		})
	}
	for _, lie := range m.IndexLies {
		*into = append(*into, Delta{
			Member: m.Name, Cohort: m.Cohort,
			Kind: DeltaIndexLie, Severity: SeverityFail,
			Detail: "INDEX-LIE: " + lie,
		})
	}
	if !meetsR174FiveOfFive(m.Markers) {
		*into = append(*into, Delta{
			Member: m.Name, Cohort: m.Cohort,
			Kind: DeltaMissingR174, Severity: SeverityWarn,
			Detail: "missing R174 5-of-5 markers: " + missingR174Detail(m.Markers),
		})
	}
}

// classifyAbsoluteIfNew emits an absolute delta only when "now" exposes
// something "was" didn't. Avoids spamming the report with old drift
// already accounted for in the snapshot history.
func classifyAbsoluteIfNew(was, now Member, into *[]Delta) {
	if now.Markers.WireFormatPrefixDrift != "" &&
		was.Markers.WireFormatPrefixDrift != now.Markers.WireFormatPrefixDrift {
		*into = append(*into, Delta{
			Member: now.Name, Cohort: now.Cohort,
			Kind: DeltaWireFormatDrift, Severity: SeverityFail,
			Detail:  "wire-format drift introduced: " + now.Markers.WireFormatPrefixDrift,
			WasValue: was.Markers.WireFormatPrefixDrift,
			NowValue: now.Markers.WireFormatPrefixDrift,
		})
	}
	// INDEX-LIE: any string in now.IndexLies not present in was.IndexLies.
	prev := map[string]bool{}
	for _, l := range was.IndexLies {
		prev[l] = true
	}
	for _, l := range now.IndexLies {
		if !prev[l] {
			*into = append(*into, Delta{
				Member: now.Name, Cohort: now.Cohort,
				Kind: DeltaIndexLie, Severity: SeverityFail,
				Detail: "INDEX-LIE: " + l,
			})
		}
	}
}

// meetsR174FiveOfFive returns true iff the member exposes all five
// canonical marker bits. (foundation/pkg usage is a 6th nice-to-have,
// not counted in the 5-of-5 verdict; wire-format drift presence is a
// failure not counted here.)
func meetsR174FiveOfFive(mk Markers) bool {
	return mk.HasMirrorMarkPkg &&
		mk.KAT1HexPinned &&
		mk.HasLoudOnceWiring &&
		mk.HasIsStalePredicate &&
		mk.HasLiabilityFooter
}

func missingR174Detail(mk Markers) string {
	missing := []string{}
	if !mk.HasMirrorMarkPkg {
		missing = append(missing, "mirrormark_pkg")
	}
	if !mk.KAT1HexPinned {
		missing = append(missing, "kat1_hex_pin")
	}
	if !mk.HasLoudOnceWiring {
		missing = append(missing, "loud_once_wiring")
	}
	if !mk.HasIsStalePredicate {
		missing = append(missing, "is_stale_predicate")
	}
	if !mk.HasLiabilityFooter {
		missing = append(missing, "liability_footer")
	}
	if len(missing) == 0 {
		return "(none)"
	}
	out := missing[0]
	for _, m := range missing[1:] {
		out += "," + m
	}
	return out
}

func severityRank(s Severity) int {
	switch s {
	case SeverityFail:
		return 0
	case SeverityWarn:
		return 1
	case SeverityInfo:
		return 2
	case SeverityPass:
		return 3
	}
	return 9
}
