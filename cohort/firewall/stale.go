// Package firewall hosts the R150 IsStale predicate for cohort-walker.
//
// R150 R-PARALLEL-MAP-R144-SIBLING (PROMOTED 2026-05-22, batch 4) and its
// Class-3 jurisdiction-version sub-class require every flagship that
// carries schematised or versioned knowledge to expose an IsStale
// predicate so callers can refuse to operate on stale data.
//
// cohort-walker's "schematised knowledge" is the cohort-snapshot.json
// baseline. Snapshots older than the stale-threshold are themselves
// silent-degradation surfaces (a CI gate that compares today's tree to
// a 6-month-old snapshot would generate false-positive drift on every
// healthy improvement). IsStale lets CI fail loudly when the snapshot
// is older than the configured horizon.
//
// The 7 honest-TODO sentinels enumerated below are sub-class signals,
// kept as named constants so a downstream grep can find every site
// without source-reading.
package firewall

import "time"

// Sentinel constants enumerate every honest-TODO that may make IsStale
// return true. Kept as named constants for grep-discoverability.
const (
	StaleReasonExpired           = "stale: snapshot older than horizon"
	StaleReasonMissingFile       = "stale: snapshot file does not exist"
	StaleReasonMissingTimestamp  = "stale: snapshot has no captured_at"
	StaleReasonUnparsableISO8601 = "stale: snapshot captured_at not RFC3339"
	StaleReasonFutureTimestamp   = "stale: snapshot captured_at in the future"
	StaleReasonZeroTime          = "stale: snapshot captured_at is zero"
	StaleReasonUnknownSchema     = "stale: snapshot schema version unrecognised"
)

// DefaultHorizon is the stale threshold used when CI does not override.
// 30 days lines up with the GitHub Actions retention for the artefact
// the workflow template uploads.
const DefaultHorizon = 30 * 24 * time.Hour

// IsStale returns (stale, reason). reason is one of the Stale* sentinel
// constants for grep-discoverability. now is injectable for tests.
func IsStale(capturedAt time.Time, horizon time.Duration, now time.Time) (bool, string) {
	if capturedAt.IsZero() {
		return true, StaleReasonZeroTime
	}
	if capturedAt.After(now) {
		return true, StaleReasonFutureTimestamp
	}
	if now.Sub(capturedAt) > horizon {
		return true, StaleReasonExpired
	}
	return false, ""
}
