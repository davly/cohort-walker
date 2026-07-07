package firewall

import (
	"testing"
	"time"
)

// TestIsStale_Table pins the exact staleness math of the R150 predicate.
//
// The integration tests in cmd/cohort-walker exercise IsStale only through
// the whole binary against wall-clock time.Now(), so the security-critical
// edges — most notably the inclusive boundary now == capturedAt+horizon —
// were never asserted directly and deterministically. This table is the
// regression guard: flipping `>` to `>=` (or vice versa), dropping the
// future check, or mishandling the zero-time sentinel each break exactly
// one row here.
func TestIsStale_Table(t *testing.T) {
	// A fixed, zone-bearing base instant. Using a non-UTC zone for capturedAt
	// while passing a UTC now proves the predicate is instant-based (Sub/After
	// compare absolute instants), so the stored zone must not change the verdict.
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.FixedZone("PST", -8*3600))
	const horizon = 30 * 24 * time.Hour

	cases := []struct {
		name       string
		capturedAt time.Time
		now        time.Time
		wantStale  bool
		wantReason string
	}{
		{
			name:       "fresh well within horizon",
			capturedAt: base,
			now:        base.Add(horizon - time.Hour),
			wantStale:  false,
			wantReason: "",
		},
		{
			name:       "exact boundary now==capturedAt+horizon is NOT stale",
			capturedAt: base,
			now:        base.Add(horizon),
			wantStale:  false,
			wantReason: "",
		},
		{
			name:       "one nanosecond past horizon is stale",
			capturedAt: base,
			now:        base.Add(horizon + time.Nanosecond),
			wantStale:  true,
			wantReason: StaleReasonExpired,
		},
		{
			name:       "captured exactly at now is fresh (not future)",
			capturedAt: base,
			now:        base,
			wantStale:  false,
			wantReason: "",
		},
		{
			name:       "future captured_at (clock skew / poisoned baseline) is stale",
			capturedAt: base.Add(time.Nanosecond),
			now:        base,
			wantStale:  true,
			wantReason: StaleReasonFutureTimestamp,
		},
		{
			name:       "zero captured_at is stale",
			capturedAt: time.Time{},
			now:        base,
			wantStale:  true,
			wantReason: StaleReasonZeroTime,
		},
		{
			name:       "cross-zone instant equality respects absolute time, not wall clock",
			capturedAt: base, // 2026-06-01 12:00 PST == 20:00 UTC
			now:        base.UTC().Add(horizon),
			wantStale:  false,
			wantReason: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stale, reason := IsStale(tc.capturedAt, horizon, tc.now)
			if stale != tc.wantStale {
				t.Fatalf("IsStale stale=%v, want %v (reason=%q)", stale, tc.wantStale, reason)
			}
			if reason != tc.wantReason {
				t.Fatalf("IsStale reason=%q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// TestIsStale_FutureBeatsExpired documents precedence: a future timestamp
// that is ALSO older-than-horizon in magnitude can never reach the expired
// branch, because After(now) short-circuits first. (Constructed by making
// now far in the past relative to capturedAt.)
func TestIsStale_FutureTakesPrecedenceOverExpired(t *testing.T) {
	capturedAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := capturedAt.Add(-365 * 24 * time.Hour) // now is a year before capture
	stale, reason := IsStale(capturedAt, 24*time.Hour, now)
	if !stale || reason != StaleReasonFutureTimestamp {
		t.Fatalf("want future-timestamp stale, got stale=%v reason=%q", stale, reason)
	}
}
