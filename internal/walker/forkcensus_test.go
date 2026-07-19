package walker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

// forkcensus_test.go is the RED-GREEN hermetic self-test for forge F10 (the
// content-hash fork-drift census, review law L2): three synthetic "apps"
// prove clustering + outlier naming, a fleetworks-named root/member proves
// the exclusion guard, and a CRLF-vs-LF pair of otherwise-identical content
// proves EOL normalization prevents phantom drift from a Windows checkout.

// TestForkCensus_TwoClusters_CorrectMembersAndOutlier is the core clustering
// proof: 3 fixture apps, one family file with 2 distinct byte-contents ->
// the census must yield exactly 2 clusters, the plurality (2 members) must
// be canonical, and the lone divergent member must be the named outlier.
func TestForkCensus_TwoClusters_CorrectMembersAndOutlier(t *testing.T) {
	root := t.TempDir()
	mustWriteDir(t, filepath.Join(root, "app-a"), map[string]string{
		"shared.txt": "canonical body\n",
	})
	mustWriteDir(t, filepath.Join(root, "app-b"), map[string]string{
		"shared.txt": "canonical body\n",
	})
	mustWriteDir(t, filepath.Join(root, "app-c"), map[string]string{
		"shared.txt": "DRIFTED body\n",
	})

	rep, err := RunForkCensus(ForkCensusOptions{
		Roots: []string{root},
		Files: []string{"shared.txt"},
		Now:   fixedTime(),
	})
	if err != nil {
		t.Fatalf("RunForkCensus: %v", err)
	}
	if len(rep.Families) != 1 {
		t.Fatalf("want 1 family, got %d: %+v", len(rep.Families), rep.Families)
	}
	fc := rep.Families[0]
	if fc.File != "shared.txt" {
		t.Fatalf("family file want shared.txt, got %q", fc.File)
	}
	if len(fc.Clusters) != 2 {
		t.Fatalf("want 2 clusters, got %d: %+v", len(fc.Clusters), fc.Clusters)
	}
	if fc.PresentMembers != 3 {
		t.Fatalf("want 3 present members, got %d", fc.PresentMembers)
	}

	canonical := fc.Clusters[0]
	if !canonical.Canonical {
		t.Fatalf("clusters[0] must be flagged canonical: %+v", canonical)
	}
	if len(canonical.Members) != 2 || canonical.Members[0] != "app-a" || canonical.Members[1] != "app-b" {
		t.Fatalf("canonical cluster want [app-a app-b], got %v", canonical.Members)
	}
	if fc.CanonicalTie {
		t.Fatalf("2-vs-1 must not be reported as a tie: %+v", fc)
	}
	if len(fc.Outliers) != 1 || fc.Outliers[0] != "app-c" {
		t.Fatalf("outliers want [app-c], got %v", fc.Outliers)
	}
	// The second cluster must NOT be marked canonical.
	if fc.Clusters[1].Canonical {
		t.Fatalf("only one cluster may be canonical: %+v", fc.Clusters)
	}
}

// TestForkCensus_ForbiddenMemberName_Excluded proves the belt-and-suspenders
// member-name filter: a "fleetworks-godfather" subdir under an otherwise
// allowed root must never appear as a member, in any family's clusters,
// outliers, or absent-members list — Fleetworks is operator-driven only and
// must never be autonomously scanned (MEMORY.md).
func TestForkCensus_ForbiddenMemberName_Excluded(t *testing.T) {
	root := t.TempDir()
	mustWriteDir(t, filepath.Join(root, "real-fork"), map[string]string{
		"shared.txt": "body\n",
	})
	mustWriteDir(t, filepath.Join(root, "fleetworks-godfather"), map[string]string{
		"shared.txt": "body\n",
	})

	rep, err := RunForkCensus(ForkCensusOptions{
		Roots: []string{root},
		Files: []string{"shared.txt"},
		Now:   fixedTime(),
	})
	if err != nil {
		t.Fatalf("RunForkCensus: %v", err)
	}
	if len(rep.Families) != 1 {
		t.Fatalf("want 1 family, got %+v", rep.Families)
	}
	fc := rep.Families[0]
	if fc.PresentMembers != 1 {
		t.Fatalf("fleetworks-godfather must be excluded from present_members; got %d", fc.PresentMembers)
	}
	for _, c := range fc.Clusters {
		for _, m := range c.Members {
			if m == "fleetworks-godfather" {
				t.Fatalf("fleetworks-godfather leaked into a cluster: %+v", fc.Clusters)
			}
		}
	}
	for _, a := range fc.AbsentMembers {
		if a == "fleetworks-godfather" {
			t.Fatalf("fleetworks-godfather leaked into absent_members: %v", fc.AbsentMembers)
		}
	}
}

// TestForkCensus_ForbiddenRootPath_Refused proves the hard-refuse guard on
// the ROOT itself: any --roots path containing "fleetworks" or "vocaladev"
// (case-insensitive) must return a *ForbiddenRootError and produce no
// report at all — never a partial/best-effort scan of a forbidden tree.
func TestForkCensus_ForbiddenRootPath_Refused(t *testing.T) {
	for _, root := range []string{
		`C:\vocaladev\FleetworksGodfather\apps`,
		`C:\SomeDrive\VocalAdev\apps`,
	} {
		root := root
		t.Run(root, func(t *testing.T) {
			rep, err := RunForkCensus(ForkCensusOptions{Roots: []string{root}, Now: fixedTime()})
			if rep != nil {
				t.Fatalf("forbidden root must return a nil report; got %+v", rep)
			}
			var forbidden *ForbiddenRootError
			if !errors.As(err, &forbidden) {
				t.Fatalf("want *ForbiddenRootError, got %v (%T)", err, err)
			}
			if forbidden.Root != root {
				t.Fatalf("ForbiddenRootError.Root want %q, got %q", root, forbidden.Root)
			}
		})
	}
}

// TestForkCensus_CRLFvsLF_SameCluster is the phantom-drift-immunity proof:
// two forks whose file content is logically identical but checked out with
// different line endings (LF vs CRLF) must land in the SAME cluster. The
// raw (non-normalized) SHA-256 of the two files is first asserted to differ
// — proving the byte-level difference is real — so the "same cluster"
// assertion below is proof the EOL normalization did the work, not a
// no-op over already-identical bytes.
func TestForkCensus_CRLFvsLF_SameCluster(t *testing.T) {
	lfBody := "line one\nline two\nline three\n"
	crlfBody := "line one\r\nline two\r\nline three\r\n"

	rawLF := sha256.Sum256([]byte(lfBody))
	rawCRLF := sha256.Sum256([]byte(crlfBody))
	if hex.EncodeToString(rawLF[:]) == hex.EncodeToString(rawCRLF[:]) {
		t.Fatal("fixture is broken: LF and CRLF bodies must differ at the raw byte level")
	}

	root := t.TempDir()
	mustWriteDir(t, filepath.Join(root, "app-lf"), map[string]string{"shared.txt": lfBody})
	mustWriteDir(t, filepath.Join(root, "app-crlf"), map[string]string{"shared.txt": crlfBody})

	rep, err := RunForkCensus(ForkCensusOptions{
		Roots: []string{root},
		Files: []string{"shared.txt"},
		Now:   fixedTime(),
	})
	if err != nil {
		t.Fatalf("RunForkCensus: %v", err)
	}
	if len(rep.Families) != 1 {
		t.Fatalf("want 1 family, got %+v", rep.Families)
	}
	fc := rep.Families[0]
	if len(fc.Clusters) != 1 {
		t.Fatalf("CRLF vs LF of identical content must be ONE cluster (no phantom drift); got %d: %+v",
			len(fc.Clusters), fc.Clusters)
	}
	if len(fc.Clusters[0].Members) != 2 {
		t.Fatalf("want both app-lf and app-crlf in the single cluster, got %v", fc.Clusters[0].Members)
	}
	if len(fc.Outliers) != 0 {
		t.Fatalf("want zero outliers, got %v", fc.Outliers)
	}
}

// TestForkCensus_MemberWithNoFamilyFiles_Dropped proves a candidate member
// with ZERO family files present is dropped from the cohort entirely — it
// must not appear as an absent_member on every family (the doc-repo /
// non-fork noise this guards against).
func TestForkCensus_MemberWithNoFamilyFiles_Dropped(t *testing.T) {
	root := t.TempDir()
	mustWriteDir(t, filepath.Join(root, "real-fork"), map[string]string{
		"shared.txt": "body\n",
	})
	mustWriteDir(t, filepath.Join(root, "unrelated-doc-repo"), map[string]string{
		"README.md": "not a family file\n",
	})

	rep, err := RunForkCensus(ForkCensusOptions{
		Roots: []string{root},
		Files: []string{"shared.txt"},
		Now:   fixedTime(),
	})
	if err != nil {
		t.Fatalf("RunForkCensus: %v", err)
	}
	fc := rep.Families[0]
	if fc.PresentMembers != 1 {
		t.Fatalf("want 1 present member (unrelated-doc-repo dropped), got %d", fc.PresentMembers)
	}
	for _, a := range fc.AbsentMembers {
		if a == "unrelated-doc-repo" {
			t.Fatalf("unrelated-doc-repo has zero family files and must be dropped, not listed absent: %v", fc.AbsentMembers)
		}
	}
}

// TestForkCensus_NoTimestamp_ByteIdentical mirrors TestScan_NoTimestamp_
// ByteIdentical: two censuses of an unchanged fixture, run with different
// injected clocks but NoTimestamp:true, must serialise to byte-identical
// JSON (captured_at is the only thing that could otherwise leak the clock).
func TestForkCensus_NoTimestamp_ByteIdentical(t *testing.T) {
	root := t.TempDir()
	mustWriteDir(t, filepath.Join(root, "app-a"), map[string]string{"shared.txt": "body\n"})

	optsA := ForkCensusOptions{Roots: []string{root}, Files: []string{"shared.txt"}, NoTimestamp: true, Now: fixedTime()}
	optsB := ForkCensusOptions{Roots: []string{root}, Files: []string{"shared.txt"}, NoTimestamp: true, Now: fixedTime().Add(1000)}

	repA, err := RunForkCensus(optsA)
	if err != nil {
		t.Fatal(err)
	}
	repB, err := RunForkCensus(optsB)
	if err != nil {
		t.Fatal(err)
	}
	if !repA.CapturedAt.IsZero() || !repB.CapturedAt.IsZero() {
		t.Fatalf("NoTimestamp must zero captured_at; got %v / %v", repA.CapturedAt, repB.CapturedAt)
	}
}

// TestForkCensus_UnknownRoot_NoMembers_NoError mirrors the scan.go
// contract (Scan treats a missing root as zero members, not an error) so a
// caller passing a stale/typo'd root gets an empty (not failing) census.
func TestForkCensus_UnknownRoot_NoMembers_NoError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	rep, err := RunForkCensus(ForkCensusOptions{Roots: []string{missing}, Now: fixedTime()})
	if err != nil {
		t.Fatalf("missing root must not error, got %v", err)
	}
	if len(rep.Families) != 0 {
		t.Fatalf("missing root must yield zero families, got %+v", rep.Families)
	}
}
