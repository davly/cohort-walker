// forkcensus.go — the content-hash fork-drift census (forge F10 / review law
// L2). The ~20 SvelteKit apps under C:\limitless\apps are FORKS of
// apps/nexus-thin-template sharing a file-family (session.ts, payments.ts,
// nexus.ts, analytics.ts, Dockerfile, svelte.config.js, hooks.server.ts,
// sdk-manifest.json, ...). Forking creates no import edge, so the
// dependency-graph / cross-poll oracles that this repo's marker-scan (see
// scan.go) and every dep-graph tool in the estate are built around are
// structurally blind to this reuse-and-drift class.
//
// The census is a MAP, not a gate: for each family file it hashes every
// fork's copy (SHA-256 over EOL-normalized bytes, so CRLF-vs-LF Windows
// checkouts never create phantom drift), clusters forks by identical
// content, names the plurality cluster "canonical", and lists every other
// member as an outlier. It never fails a build — drift is the expected
// finding, not an error condition.
package walker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ForkCensusSchemaVersion is the fork-census JSON schema tag.
const ForkCensusSchemaVersion = "cohort-walker.fork-census.v1"

// DefaultForkFamilyFiles is the curated default file-family set: relative
// paths (forward-slash, joined via filepath.Join at scan time) present in a
// majority of the live apps/ fork cohort, curated to the security / payments
// / infra surface review law L2 flagged as import-invisible (session
// handling, payment webhooks, entitlement/DSAR, and the deploy/build
// manifests every fork inherits verbatim from nexus-thin-template at fork
// time and then drifts independently thereafter).
//
// Discovered by intersecting what exists across the live apps/ cohort
// (2026-07-19): every path below is a real file on at least 4 forks. This is
// a starting set, not a closed one — pass --files to census a different
// family without a code change.
var DefaultForkFamilyFiles = []string{
	"Dockerfile",
	"svelte.config.js",
	"vite.config.ts",
	"sdk-manifest.json",
	"src/hooks.server.ts",
	"src/lib/nexus.ts",
	"src/lib/analytics.ts",
	"src/lib/seo.ts",
	"src/lib/dsar.ts",
	"src/lib/server/session.ts",
	"src/lib/server/payments.ts",
	"src/lib/server/state.ts",
	"src/lib/server/entitlement.ts",
	"src/lib/server/lsPayments.ts",
	"src/lib/server/ratelimit.ts",
	"src/lib/server/jsonStore.ts",
	"src/lib/server/dsar.ts",
	"src/routes/health/+server.ts",
	"src/routes/api/generate/+server.ts",
	"src/routes/api/stripe-webhook/+server.ts",
	"src/routes/api/mor-webhook/+server.ts",
	"src/routes/api/checkout/+server.ts",
}

// forbiddenRootTokens: any --roots path containing one of these (case
// insensitive) is refused outright. Fleetworks is operator-driven only (no
// autonomous session may read or touch it); vocaladev is its sibling
// checkout. See MEMORY.md "Fleetworks = operator-driven only".
var forbiddenRootTokens = []string{"fleetworks", "vocaladev"}

// forbiddenMemberTokens: an immediate subdir whose NAME contains one of
// these is dropped from the member list even when the root itself is
// allowed (belt-and-suspenders: C:\limitless\apps\fleetworks-godfather lives
// directly under the allowed apps/ root).
var forbiddenMemberTokens = []string{"fleetworks"}

// ForbiddenRootError is returned by RunForkCensus when a caller-supplied
// root names a forbidden tree. main.go maps it to ExitForbiddenRoot (7).
type ForbiddenRootError struct {
	Root string
}

func (e *ForbiddenRootError) Error() string {
	return fmt.Sprintf("root %q is forbidden (fleetworks / vocaladev are operator-driven only; never scanned autonomously)", e.Root)
}

// ForkCensusOptions configures a fork-census run.
type ForkCensusOptions struct {
	Roots []string // fork-root directories to enumerate members under; DefaultForkRoots if empty
	Files []string // family relative paths to census; DefaultForkFamilyFiles if empty
	Now   time.Time
	// NoTimestamp mirrors ScanOptions.NoTimestamp: zeroes captured_at so two
	// censuses of an unchanged tree are byte-identical.
	NoTimestamp bool
}

// ClusterInfo is one content-identical group within a family.
type ClusterInfo struct {
	Hash      string   `json:"hash"`      // full SHA-256 hex of the EOL-normalized content
	Members   []string `json:"members"`   // fork names, sorted
	Canonical bool     `json:"canonical"` // true on exactly one cluster: the plurality
}

// FamilyCensus is the per-file-family clustering result.
type FamilyCensus struct {
	File           string        `json:"file"`
	Clusters       []ClusterInfo `json:"clusters"` // sorted: count desc, then hash asc
	CanonicalHash  string        `json:"canonical_hash"`
	CanonicalTie   bool          `json:"canonical_tie,omitempty"`  // >1 cluster tied for plurality; canonical picked by lexicographically-smallest hash
	Outliers       []string      `json:"outliers"`                 // members NOT in the canonical cluster, sorted; [] not null
	AbsentMembers  []string      `json:"absent_members,omitempty"` // present-cohort forks that lack this file entirely (informational, not drift)
	PresentMembers int           `json:"present_members"`
}

// ForkCensusReport is the full census: schema + every family's clustering.
type ForkCensusReport struct {
	SchemaVersion string         `json:"schema_version"`
	CapturedAt    time.Time      `json:"captured_at"`
	Roots         []string       `json:"roots"`
	Families      []FamilyCensus `json:"families"`
}

// RunForkCensus enumerates fork members under opts.Roots, hashes each
// member's copy of every opts.Files family path (EOL-normalized SHA-256),
// clusters by identical content, and returns the deterministic census.
//
// A member is included in the cohort only if it has AT LEAST ONE family
// file present — this drops non-fork siblings (doc repos, the cohort-walker
// Go tool itself, a bare template placeholder) from the absent-file noise
// without needing an explicit allowlist.
func RunForkCensus(opts ForkCensusOptions) (*ForkCensusReport, error) {
	roots := opts.Roots
	if len(roots) == 0 {
		roots = DefaultForkRoots
	}
	files := opts.Files
	if len(files) == 0 {
		files = DefaultForkFamilyFiles
	}
	for _, r := range roots {
		low := strings.ToLower(r)
		for _, tok := range forbiddenRootTokens {
			if strings.Contains(low, tok) {
				return nil, &ForbiddenRootError{Root: r}
			}
		}
	}

	capturedAt := resolveForkCensusCapturedAt(opts)

	members, err := discoverForkMembers(roots, files)
	if err != nil {
		return nil, err
	}

	rep := &ForkCensusReport{
		SchemaVersion: ForkCensusSchemaVersion,
		CapturedAt:    capturedAt,
		Roots:         append([]string{}, roots...),
	}

	sortedFiles := append([]string{}, files...)
	sort.Strings(sortedFiles)

	for _, file := range sortedFiles {
		fc := censusOneFamily(file, members)
		if fc.PresentMembers == 0 {
			continue // no fork carries this family file; nothing to cluster
		}
		rep.Families = append(rep.Families, fc)
	}

	return rep, nil
}

// forkMember is one discovered fork root's absolute path + name.
type forkMember struct {
	name string
	path string
}

// discoverForkMembers walks every root's immediate subdirs (skipping
// dotdirs, symlinks/junctions, and forbidden-token names) and keeps only
// members that have at least one of files present.
func discoverForkMembers(roots, files []string) ([]forkMember, error) {
	var members []forkMember
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, ent := range entries {
			name := ent.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			memberPath := filepath.Join(root, name)
			info, err := os.Lstat(memberPath)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue // skip symlinks / junctions (e.g. apps/foundation -> ../foundation)
			}
			if !info.IsDir() {
				continue
			}
			lowName := strings.ToLower(name)
			forbidden := false
			for _, tok := range forbiddenMemberTokens {
				if strings.Contains(lowName, tok) {
					forbidden = true
					break
				}
			}
			if forbidden {
				continue
			}
			if seen[memberPath] {
				continue
			}
			if !memberHasAnyFamilyFile(memberPath, files) {
				continue
			}
			seen[memberPath] = true
			members = append(members, forkMember{name: name, path: memberPath})
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	return members, nil
}

// memberHasAnyFamilyFile reports whether path has at least one of files.
func memberHasAnyFamilyFile(path string, files []string) bool {
	for _, f := range files {
		if fileExists(filepath.Join(path, filepath.FromSlash(f))) {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// censusOneFamily hashes file across every member, clusters by content, and
// names the canonical cluster.
func censusOneFamily(file string, members []forkMember) FamilyCensus {
	fc := FamilyCensus{File: file, Outliers: []string{}}
	byHash := map[string][]string{}

	for _, m := range members {
		p := filepath.Join(m.path, filepath.FromSlash(file))
		if !fileExists(p) {
			fc.AbsentMembers = append(fc.AbsentMembers, m.name)
			continue
		}
		h, err := hashFileEOLNormalized(p)
		if err != nil {
			// Unreadable file (permissions, race): treat like absent rather
			// than fail the whole census — a single bad file must not blind
			// the map for every other fork.
			fc.AbsentMembers = append(fc.AbsentMembers, m.name)
			continue
		}
		byHash[h] = append(byHash[h], m.name)
	}
	fc.PresentMembers = 0
	for _, ms := range byHash {
		fc.PresentMembers += len(ms)
	}
	sort.Strings(fc.AbsentMembers)

	clusters := make([]ClusterInfo, 0, len(byHash))
	for h, ms := range byHash {
		sort.Strings(ms)
		clusters = append(clusters, ClusterInfo{Hash: h, Members: ms})
	}
	// Deterministic sort: count desc, then hash asc (the lexicographically
	// smallest hash among tied-largest clusters becomes canonical below).
	sort.Slice(clusters, func(i, j int) bool {
		if len(clusters[i].Members) != len(clusters[j].Members) {
			return len(clusters[i].Members) > len(clusters[j].Members)
		}
		return clusters[i].Hash < clusters[j].Hash
	})

	if len(clusters) > 0 {
		clusters[0].Canonical = true
		fc.CanonicalHash = clusters[0].Hash
		if len(clusters) > 1 && len(clusters[1].Members) == len(clusters[0].Members) {
			fc.CanonicalTie = true
		}
		for _, c := range clusters[1:] {
			fc.Outliers = append(fc.Outliers, c.Members...)
		}
		sort.Strings(fc.Outliers)
	}
	fc.Clusters = clusters

	return fc
}

// hashFileEOLNormalized reads p and returns the hex SHA-256 of its content
// with every CR byte (0x0D) stripped first, so a CRLF-checked-out file and
// its LF-checked-out twin hash identically — a Windows git checkout must
// never manufacture phantom fork drift out of line-ending policy alone.
func hashFileEOLNormalized(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	normalized := make([]byte, 0, len(body))
	for _, b := range body {
		if b == '\r' {
			continue
		}
		normalized = append(normalized, b)
	}
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:]), nil
}

// resolveForkCensusCapturedAt mirrors resolveCapturedAt (scan.go) exactly so
// fork-census joins the same determinism / SOURCE_DATE_EPOCH contract.
func resolveForkCensusCapturedAt(opts ForkCensusOptions) time.Time {
	if opts.NoTimestamp {
		return time.Time{}
	}
	if !opts.Now.IsZero() {
		return opts.Now.UTC()
	}
	if t, ok := sourceDateEpoch(); ok {
		return t
	}
	return time.Now().UTC()
}

// RenderForkCensusJSON writes rep as indented JSON.
func RenderForkCensusJSON(w io.Writer, rep *ForkCensusReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// RenderForkCensusText writes the human-readable summary: per family, the
// canonical cluster size and every outlier fork + its short hash.
func RenderForkCensusText(w io.Writer, rep *ForkCensusReport) error {
	fmt.Fprintf(w, "fork-drift census — %d root(s), %d famil(y/ies)\n", len(rep.Roots), len(rep.Families))
	if len(rep.Families) == 0 {
		fmt.Fprintln(w, "(no family file matched any fork)")
		return nil
	}
	for _, fc := range rep.Families {
		fmt.Fprintf(w, "\n%s  (%d present, %d cluster(s)", fc.File, fc.PresentMembers, len(fc.Clusters))
		if len(fc.AbsentMembers) > 0 {
			fmt.Fprintf(w, ", %d absent", len(fc.AbsentMembers))
		}
		fmt.Fprint(w, ")\n")
		for _, c := range fc.Clusters {
			tag := ""
			if c.Canonical {
				tag = " [canonical]"
				if fc.CanonicalTie {
					tag = " [canonical, TIE]"
				}
			}
			short := c.Hash
			if len(short) > 12 {
				short = short[:12]
			}
			fmt.Fprintf(w, "  %s  n=%d%s  %s\n", short, len(c.Members), tag, strings.Join(c.Members, ", "))
		}
		if len(fc.Outliers) > 0 {
			fmt.Fprintf(w, "  OUTLIERS: %s\n", strings.Join(fc.Outliers, ", "))
		}
	}
	return nil
}
