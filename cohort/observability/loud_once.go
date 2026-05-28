// Package observability hosts the R143 LOUD-ONCE-WARNING-FLAG wire for
// cohort-walker.
//
// R143 LOUD-ONCE-WARNING-FLAG (STANDARD since 2026-05-11) requires that
// silent-degradation or silent-clamp surfaces fire a single, structured,
// once-per-process warning so operators see the signal at least once but
// never get flooded.
//
// cohort-walker has two silent-degradation paths:
//
//  1. Substrate detector hits an unknown / unrecognised manifest file
//     (e.g. a flagship using a build system we have not catalogued).
//     The walker continues, but the substrate field will be "unknown".
//
//  2. KAT-1 hex byte-identity check skipped because no candidate file
//     was found to inspect (e.g. flagship is doc-only at this revision).
//     The walker continues with a "kat1=absent" verdict, but the operator
//     deserves to know that absence is not the same as drift.
//
// Both paths fire a single structured stderr line on first occurrence
// per process, then go quiet.
package observability

import (
	"fmt"
	"io"
	"sync"
)

// Audit-rule discriminator. Operators / CI grep this string to find R143
// emissions in their log capture.
const AuditRule = "R143_LOUD_ONCE_WARNING_FLAG"

// LoudOnce is a single-shot warning gate. Zero-value is ready to use.
type LoudOnce struct {
	once sync.Once
}

// Fire emits a single structured warning line to w on the first call.
// Subsequent calls are no-ops. The line shape is byte-compatible with
// the foundry + insights + gauntlet R143 wires (LOUD-ONCE-WARNING prefix
// + audit_rule= discriminator + message). Returns true on the call that
// actually emitted, false on subsequent calls.
func (l *LoudOnce) Fire(w io.Writer, message string) bool {
	fired := false
	l.once.Do(func() {
		fmt.Fprintf(w, "[LOUD-ONCE-WARNING] audit_rule=%s message=%q\n", AuditRule, message)
		fired = true
	})
	return fired
}

// Reset rearms the gate. Test-only: production code must never reset.
func (l *LoudOnce) Reset() { l.once = sync.Once{} }
