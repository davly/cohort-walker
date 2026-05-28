// Package identity hosts the R151 R-KAT-AS-COHORT-INVARIANT pin for
// cohort-walker itself.
//
// cohort-walker is a cohort member; R151 requires that every cohort member
// pin the canonical KAT-1 HMAC-SHA256 hex digest as a literal constant
// AND assert byte-equality against an OpenSSL-reproducible recomputation
// in tests. This file is the literal pin; the test in walker_test.go
// recomputes the digest and compares.
//
// The digest is the R151 anchor: HMAC-SHA256(key=[], msg=0x01 || 32x0x00).
// Anywhere this hex string drifts from the canonical pin, the entire
// cohort invariant story is broken — see R151 promotion rationale.
package identity

// KAT1Hex is the cohort-canonical KAT-1 anchor, byte-identical with every
// other cohort member's pin (Go canonical / Rust foundry / Python
// dreamcatcher / TS conjure / OCaml limitless-ocaml / etc).
const KAT1Hex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// Version is the L43 wire-format prefix; included here as a sibling
// invariant so a single import gives a flagship the full pin pair.
const Version = "lore@v1:"

// CohortName is the flagship name used in audit rows + drift reports.
const CohortName = "cohort-walker"

// MirrorMarkPackagePath is the conventional internal mirrormark package
// path. cohort-walker uses the cohort-map binary for stamping; it
// imports the cohort-map mark primitives transitively, so this field
// records "external" to signal that.
const MirrorMarkPackagePath = "external (via cohort-map)"
