// Package walker implements the cohort-walker scan / diff / report
// engine. The scanner walks the four canonical cohort roots
// (flagships / infrastructure / engines / foundation), classifies each
// member by substrate language, and probes for the seven invariant
// markers a fully-onboarded R174 5-of-5 cohort member should expose:
//
//  1. mirrormark package or equivalent file presence
//  2. KAT-1 hex byte-identity pin (R151)
//  3. L43 wire-format prefix `lore@v1:` literal
//  4. R143 LoudOnce wiring (loud-warn / fire_*_once style)
//  5. R150 IsStale predicate
//  6. R166 LIABILITY_FOOTER constant
//  7. foundation/pkg/* thin-shim usage (Go canonical only)
//
// The scan is pure-stdlib and intentionally cheap: a substring grep on
// the first ~1MB of each candidate file. False-positives are acceptable
// because the downstream diff stage is what generates verdicts; a single
// presence-bit per marker is enough to seed the diff.
package walker

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Substrate enumerates every substrate language cohort-walker recognises.
// Adding a new substrate requires:
//   - a new const here,
//   - a new entry in substrateDetectors below,
//   - tests in scan_test.go.
type Substrate string

const (
	SubstrateUnknown    Substrate = "unknown"
	SubstrateGo         Substrate = "go"
	SubstrateRust       Substrate = "rust"
	SubstratePython     Substrate = "python"
	SubstrateTypeScript Substrate = "typescript"
	SubstrateJavaScript Substrate = "javascript"
	SubstrateCrystal    Substrate = "crystal"
	SubstrateElixir     Substrate = "elixir"
	SubstrateErlang     Substrate = "erlang"
	SubstrateZig        Substrate = "zig"
	SubstrateC          Substrate = "c"
	SubstrateCpp        Substrate = "cpp"
	SubstrateOCaml      Substrate = "ocaml"
	SubstrateHaskell    Substrate = "haskell"
	SubstrateLean       Substrate = "lean"
	SubstrateIdris      Substrate = "idris"
	SubstrateScala      Substrate = "scala"
	SubstrateKotlin     Substrate = "kotlin"
	SubstrateJava       Substrate = "java"
	SubstrateSwift      Substrate = "swift"
	SubstrateRuby       Substrate = "ruby"
	SubstrateGleam      Substrate = "gleam"
	SubstrateDart       Substrate = "dart"
	SubstrateFSharp     Substrate = "fsharp"
	SubstrateCSharp     Substrate = "csharp"
	SubstratePHP        Substrate = "php"
	SubstrateRacket     Substrate = "racket"
	SubstrateR          Substrate = "r"
	SubstrateFortran    Substrate = "fortran"
	SubstrateAda        Substrate = "ada"
	SubstrateSolidity   Substrate = "solidity"
	SubstratePerl       Substrate = "perl"
	SubstrateBefunge    Substrate = "befunge"
)

// substrateDetectors maps a manifest filename to the substrate it
// implies. First match wins. The order in detect() is significant
// because some flagships ship a Cargo.toml AND a go.mod at the same
// level (atelier, anchor) — we choose the language of the most-tracked
// file by scanning all manifests then picking by priority.
var substrateDetectors = []struct {
	file      string
	substrate Substrate
	priority  int // higher wins on conflict
}{
	{"go.mod", SubstrateGo, 80},
	{"Cargo.toml", SubstrateRust, 80},
	{"pyproject.toml", SubstratePython, 80},
	{"setup.py", SubstratePython, 50},
	{"requirements.txt", SubstratePython, 30},
	{"package.json", SubstrateTypeScript, 70}, // upgraded to TS if tsconfig
	{"tsconfig.json", SubstrateTypeScript, 90},
	{"shard.yml", SubstrateCrystal, 80},
	{"mix.exs", SubstrateElixir, 80},
	{"rebar.config", SubstrateErlang, 80},
	{"build.zig", SubstrateZig, 80},
	{"CMakeLists.txt", SubstrateCpp, 60},
	{"Makefile", SubstrateC, 30},
	{"dune-project", SubstrateOCaml, 80},
	{"stack.yaml", SubstrateHaskell, 80},
	{"cabal.project", SubstrateHaskell, 70},
	{"lakefile.lean", SubstrateLean, 80},
	{"lean-toolchain", SubstrateLean, 70},
	{"package.yaml", SubstrateHaskell, 50},
	{"idris.ipkg", SubstrateIdris, 80},
	{"build.sbt", SubstrateScala, 80},
	{"build.gradle", SubstrateKotlin, 70},
	{"build.gradle.kts", SubstrateKotlin, 80},
	{"pom.xml", SubstrateJava, 80},
	{"Package.swift", SubstrateSwift, 80},
	{"Gemfile", SubstrateRuby, 80},
	{"gleam.toml", SubstrateGleam, 80},
	{"pubspec.yaml", SubstrateDart, 80},
	{"composer.json", SubstratePHP, 80},
	{"info.rkt", SubstrateRacket, 80},
	{"DESCRIPTION", SubstrateR, 70},
	{"foundry.toml", SubstrateGo, 10}, // Limitless-internal forge manifest; weak signal only
}

// Member is a single cohort row: one flagship / engine / infra /
// foundation package.
type Member struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Cohort     string    `json:"cohort"` // flagships|engines|infrastructure|foundation
	Substrate  Substrate `json:"substrate"`
	Markers    Markers   `json:"markers"`
	IndexLies  []string  `json:"index_lies,omitempty"` // declared modules not on disk
	CapturedAt time.Time `json:"-"`
}

// Markers captures the 7 presence-bits that drive drift detection.
type Markers struct {
	HasMirrorMarkPkg      bool   `json:"has_mirrormark_pkg"`
	KAT1HexPinned         bool   `json:"kat1_hex_pinned"`
	WireFormatPrefixOK    bool   `json:"wire_format_prefix_ok"`
	WireFormatPrefixDrift string `json:"wire_format_prefix_drift,omitempty"` // populated only on drift
	HasLoudOnceWiring     bool   `json:"has_loud_once_wiring"`
	HasIsStalePredicate   bool   `json:"has_is_stale_predicate"`
	HasLiabilityFooter    bool   `json:"has_liability_footer"`
	UsesFoundationPkg     bool   `json:"uses_foundation_pkg"`
}

// Snapshot is the full scan result; saved as JSON for diffing.
type Snapshot struct {
	SchemaVersion string    `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`
	Roots         []string  `json:"roots"`
	Members       []Member  `json:"members"`
}

// SchemaVersion is the snapshot schema; bump when Member or Markers
// shape changes incompatibly.
const SchemaVersion = "cohort-walker.v1"

// scanFileCap and scanDepthCap bound the per-member source-tree walks so a
// pathologically large or deep member cannot make the scan run unbounded
// (the package doc and scanMember's comment both promise the walk stays
// cheap; see scanMember). These caps are deliberately generous — far larger
// than any real cohort member — so they are a no-op for every honest member:
// presence-bit detection is monotone OR accumulation and a single bit is
// enough (see package doc), so the only behaviour a cap can change is failing
// to add a LATE bit on a >scanFileCap-file member, which no real member is.
const (
	// scanFileCap bounds the number of files read across detectSubstrate /
	// inferFromSourceExtensions / probeMarkers per member.
	scanFileCap = 4000
	// scanDepthCap bounds directory descent (separator count from member
	// root) for the marker probe. detectSubstrate/inferFromSourceExtensions
	// already cap at 2/3 respectively.
	scanDepthCap = 6
)

// CanonicalKAT1Hex is the byte-equality anchor a cohort member must pin.
const CanonicalKAT1Hex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// CanonicalWireFormatPrefix is the L43 v1 prefix every cohort member
// MUST emit.
const CanonicalWireFormatPrefix = "lore@v1:"

// ScanOptions configures a scan run.
type ScanOptions struct {
	Roots []string  // absolute paths to walk; defaults below if empty
	Now   time.Time // injected clock; wins over SOURCE_DATE_EPOCH and the wall clock
	// MaxFileBytes caps the per-file read for marker probes. Keeps a
	// runaway 1GB generated file from blowing memory.
	MaxFileBytes int64
	// NoTimestamp suppresses captured_at: it is set to the zero time, which
	// serialises to the fixed sentinel "0001-01-01T00:00:00Z" so two scans of
	// an unchanged tree are byte-identical (the prerequisite for adding
	// cohort-walker to workshop/scripts/det-gate.sh). Mirrors the
	// receipt / groundtruth -no-timestamp model. The firewall already treats a
	// zero captured_at as stale, so a suppressed snapshot can never masquerade
	// as a fresh freshness baseline. SOURCE_DATE_EPOCH is honored otherwise.
	NoTimestamp bool
}

// DefaultRoots mirrors the I33 spec.
var DefaultRoots = []string{
	`C:\limitless\flagships`,
	`C:\limitless\infrastructure`,
	`C:\limitless\engines`,
	`C:\limitless\foundation`,
}

// Scan walks every cohort root and returns a snapshot.
func Scan(opts ScanOptions) (*Snapshot, error) {
	if len(opts.Roots) == 0 {
		opts.Roots = DefaultRoots
	}
	capturedAt := resolveCapturedAt(opts)
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 1 << 20 // 1 MiB per file
	}

	snap := &Snapshot{
		SchemaVersion: SchemaVersion,
		CapturedAt:    capturedAt,
		Roots:         append([]string{}, opts.Roots...),
	}

	for _, root := range opts.Roots {
		cohort := cohortNameFromRoot(root)
		entries, err := os.ReadDir(root)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, ent := range entries {
			if !ent.IsDir() || strings.HasPrefix(ent.Name(), ".") {
				continue
			}
			memberPath := filepath.Join(root, ent.Name())
			m, err := scanMember(ent.Name(), memberPath, cohort, opts)
			if err != nil {
				continue // best-effort; skip unreadable members
			}
			m.CapturedAt = capturedAt
			snap.Members = append(snap.Members, m)
		}
	}

	sort.Slice(snap.Members, func(i, j int) bool {
		if snap.Members[i].Cohort != snap.Members[j].Cohort {
			return snap.Members[i].Cohort < snap.Members[j].Cohort
		}
		return snap.Members[i].Name < snap.Members[j].Name
	})

	return snap, nil
}

// resolveCapturedAt picks the snapshot's captured_at, mirroring the
// receipt / groundtruth suppression model so cohort-walker can join the
// determinism gate (workshop/scripts/det-gate.sh). Order:
//
//   - NoTimestamp -> the zero time (serialises to the fixed sentinel
//     "0001-01-01T00:00:00Z"; byte-identical run-to-run).
//   - an injected opts.Now -> that clock (tests / callers).
//   - then SOURCE_DATE_EPOCH (reproducible-build convention: integer seconds
//     since the Unix epoch) for committed/deterministic snapshots.
//   - else the wall clock.
//
// A set-but-unparseable SOURCE_DATE_EPOCH falls back to the wall clock (same as
// groundtruth's sourceDateEpoch).
func resolveCapturedAt(opts ScanOptions) time.Time {
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

// sourceDateEpoch returns the time encoded in the SOURCE_DATE_EPOCH env var (the
// reproducible-build convention: seconds since the Unix epoch) if it is set and
// parseable, so captured_at is deterministic across runs.
func sourceDateEpoch() (time.Time, bool) {
	s := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if s == "" {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0).UTC(), true
}

func cohortNameFromRoot(root string) string {
	base := filepath.Base(filepath.Clean(root))
	return strings.ToLower(base)
}

// scanMember probes one cohort member.
func scanMember(name, path, cohort string, opts ScanOptions) (Member, error) {
	m := Member{Name: name, Path: path, Cohort: cohort, Substrate: SubstrateUnknown}

	// Substrate detection: walk top + one level of subdirs (some
	// flagships nest the manifest under reference/ or backend/).
	m.Substrate = detectSubstrate(path)

	// Marker probes: walk source files (cap depth at 6, cap file count
	// at 2000 to stay cheap).
	m.Markers = probeMarkers(path, opts.MaxFileBytes)

	// INDEX-LIE detection: for Go modules, parse the top-level
	// mod-declaration files and check each "package XYZ" import path
	// resolves on disk.
	m.IndexLies = detectIndexLies(path, m.Substrate)

	return m, nil
}

// detectSubstrate inspects manifest filenames and returns the highest-
// priority match. Walks at most depth 2 from path.
func detectSubstrate(path string) Substrate {
	best := SubstrateUnknown
	bestPriority := -1
	filesSeen := 0

	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip vendored or build directories early.
		if d.IsDir() {
			n := d.Name()
			if n == "node_modules" || n == "target" || n == ".git" || n == "build" || n == "dist" {
				return filepath.SkipDir
			}
			// Limit depth.
			rel, _ := filepath.Rel(path, p)
			if strings.Count(rel, string(filepath.Separator)) > 2 {
				return filepath.SkipDir
			}
			return nil
		}
		// Cap total files examined so an enormous member cannot run
		// unbounded. scanFileCap >> any real member, so no-op in practice.
		if filesSeen >= scanFileCap {
			return filepath.SkipAll
		}
		filesSeen++
		base := filepath.Base(p)
		for _, det := range substrateDetectors {
			if base == det.file && det.priority > bestPriority {
				best = det.substrate
				bestPriority = det.priority
			}
		}
		return nil
	})
	if walkErr != nil {
		return SubstrateUnknown
	}

	// Source-file fallback: if no manifest matched, infer from any
	// .py / .rs / .go file existence at one level.
	if best == SubstrateUnknown {
		best = inferFromSourceExtensions(path)
	}

	return best
}

// inferFromSourceExtensions is the cheap last-resort fallback when no
// manifest file was found.
func inferFromSourceExtensions(path string) Substrate {
	counts := map[Substrate]int{}
	filesSeen := 0
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(path, p)
		if strings.Count(rel, string(filepath.Separator)) > 3 {
			return nil
		}
		// Cap total files examined so an enormous member cannot run
		// unbounded. scanFileCap >> any real member, so no-op in practice.
		if filesSeen >= scanFileCap {
			return filepath.SkipAll
		}
		filesSeen++
		switch filepath.Ext(p) {
		case ".go":
			counts[SubstrateGo]++
		case ".rs":
			counts[SubstrateRust]++
		case ".py":
			counts[SubstratePython]++
		case ".ts":
			counts[SubstrateTypeScript]++
		case ".js":
			counts[SubstrateJavaScript]++
		case ".cr":
			counts[SubstrateCrystal]++
		case ".ex", ".exs":
			counts[SubstrateElixir]++
		case ".erl":
			counts[SubstrateErlang]++
		case ".zig":
			counts[SubstrateZig]++
		case ".c", ".h":
			counts[SubstrateC]++
		case ".cpp", ".hpp", ".cc":
			counts[SubstrateCpp]++
		case ".ml", ".mli":
			counts[SubstrateOCaml]++
		case ".hs":
			counts[SubstrateHaskell]++
		case ".lean":
			counts[SubstrateLean]++
		case ".idr":
			counts[SubstrateIdris]++
		case ".scala":
			counts[SubstrateScala]++
		case ".kt", ".kts":
			counts[SubstrateKotlin]++
		case ".java":
			counts[SubstrateJava]++
		case ".swift":
			counts[SubstrateSwift]++
		case ".rb":
			counts[SubstrateRuby]++
		case ".gleam":
			counts[SubstrateGleam]++
		case ".dart":
			counts[SubstrateDart]++
		case ".fs", ".fsx":
			counts[SubstrateFSharp]++
		case ".cs":
			counts[SubstrateCSharp]++
		case ".php":
			counts[SubstratePHP]++
		case ".rkt":
			counts[SubstrateRacket]++
		case ".r", ".R":
			counts[SubstrateR]++
		case ".f", ".f90", ".f95":
			counts[SubstrateFortran]++
		case ".adb", ".ads":
			counts[SubstrateAda]++
		case ".sol":
			counts[SubstrateSolidity]++
		case ".pl", ".pm":
			counts[SubstratePerl]++
		case ".bf":
			counts[SubstrateBefunge]++
		}
		return nil
	})
	best := SubstrateUnknown
	bestN := 0
	// Deterministic selection: iterate substrates in lexicographic order
	// rather than over the map directly. Ranging a Go map is randomized, so
	// a COUNT TIE between two substrates (e.g. one .go file and one .rs file)
	// would otherwise let the inferred substrate flip between byte-identical
	// scans, producing a phantom `substrate_changed` delta in the diff. With
	// a sorted walk and a strict `>`, a tie resolves to the lexicographically
	// smallest substrate, stably, every run.
	subs := make([]Substrate, 0, len(counts))
	for s := range counts {
		subs = append(subs, s)
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i] < subs[j] })
	for _, s := range subs {
		if counts[s] > bestN {
			best = s
			bestN = counts[s]
		}
	}
	return best
}

// probeMarkers reads up to MaxFileBytes from each source file under
// path and looks for the 7 invariant markers.
func probeMarkers(path string, maxBytes int64) Markers {
	var m Markers
	filesRead := 0

	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			n := d.Name()
			if n == "node_modules" || n == "target" || n == ".git" || n == "build" || n == "dist" || n == "vendor" {
				return filepath.SkipDir
			}
			// Cap descent so a pathologically deep member cannot run
			// unbounded. Depth is separator count from the member root.
			rel, _ := filepath.Rel(path, p)
			if strings.Count(rel, string(filepath.Separator)) > scanDepthCap {
				return filepath.SkipDir
			}
			return nil
		}
		// Cap by file extension so we do not read binary blobs.
		ext := filepath.Ext(p)
		if !isSourceExt(ext) && !isMarkerCandidateName(filepath.Base(p)) {
			return nil
		}
		// Cap total files read so an enormous member cannot run unbounded.
		// scanFileCap >> any real member, so this never trims an honest
		// scan; presence bits are monotone so a missed late bit is the only
		// possible effect (acceptable per the package doc).
		if filesRead >= scanFileCap {
			return filepath.SkipAll
		}
		filesRead++
		probeFile(p, maxBytes, &m)
		return nil
	})

	return m
}

// isSourceExt is the conservative source-extension allowlist.
func isSourceExt(ext string) bool {
	switch ext {
	case ".go", ".rs", ".py", ".ts", ".js", ".cr", ".ex", ".exs", ".erl",
		".zig", ".c", ".h", ".cpp", ".hpp", ".cc", ".ml", ".mli", ".hs",
		".lean", ".idr", ".scala", ".kt", ".kts", ".java", ".swift", ".rb",
		".gleam", ".dart", ".fs", ".fsx", ".cs", ".php", ".rkt",
		".r", ".R", ".f", ".f90", ".adb", ".ads", ".sol", ".pl", ".pm",
		".bf":
		return true
	}
	return false
}

// isMarkerCandidateName recognises non-source files that nonetheless
// often host the literal pin (e.g. KAT files written as .txt).
func isMarkerCandidateName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "kat") || strings.Contains(lower, "mirror_mark") || strings.Contains(lower, "mirrormark")
}

// probeFile opens p, reads up to maxBytes, and OR-s the marker bits
// into m.
func probeFile(p string, maxBytes int64, m *Markers) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()

	r := io.LimitReader(f, maxBytes)
	br := bufio.NewReaderSize(r, 32<<10)
	body, _ := io.ReadAll(br)
	s := string(body)

	// 1. mirrormark package — file lives under a mirror_mark / mirrormark
	// path component, or imports such a package.
	if strings.Contains(strings.ToLower(p), "mirror_mark") ||
		strings.Contains(strings.ToLower(p), "mirrormark") {
		m.HasMirrorMarkPkg = true
	}
	if strings.Contains(s, "mirrormark") || strings.Contains(s, "mirror_mark") {
		m.HasMirrorMarkPkg = true
	}

	// 2. KAT-1 hex pin — exact 64-char byte-equality.
	if strings.Contains(s, CanonicalKAT1Hex) {
		m.KAT1HexPinned = true
	}

	// 3. L43 wire-format prefix — canonical literal.
	if strings.Contains(s, CanonicalWireFormatPrefix) {
		m.WireFormatPrefixOK = true
	} else {
		// Drift catch: bare "v1:" used in a context that looks like a
		// mark prefix (within 80 chars of "mark" / "lore" tokens).
		if drift := detectWireFormatDrift(s); drift != "" {
			if m.WireFormatPrefixDrift == "" {
				m.WireFormatPrefixDrift = drift
			}
		}
	}

	// 4. R143 LoudOnce wiring — look for the canonical literal prefix or
	// audit-rule discriminator.
	if strings.Contains(s, "LOUD-ONCE-WARNING") ||
		strings.Contains(s, "R143_LOUD_ONCE_WARNING_FLAG") ||
		strings.Contains(strings.ToLower(s), "fire_once") ||
		strings.Contains(s, "LoudOnce") {
		m.HasLoudOnceWiring = true
	}

	// 5. R150 IsStale predicate — look for is_stale / IsStale identifier.
	if strings.Contains(s, "IsStale") || strings.Contains(s, "is_stale") ||
		strings.Contains(s, "isStale") {
		m.HasIsStalePredicate = true
	}

	// 6. R166 LIABILITY_FOOTER constant — case-sensitive literal.
	if strings.Contains(s, "LIABILITY_FOOTER") || strings.Contains(s, "LiabilityFooter") {
		m.HasLiabilityFooter = true
	}

	// 7. foundation/pkg/* thin-shim usage.
	if strings.Contains(s, "limitless/foundation/pkg/") ||
		strings.Contains(s, "limitless-foundation/pkg/") {
		m.UsesFoundationPkg = true
	}
}

// detectWireFormatDrift returns a non-empty drift descriptor when the
// file looks like it tried to be a Mirror-Mark wire but used a wrong
// prefix shape.
func detectWireFormatDrift(s string) string {
	// Only flag if some mark-related tokens are nearby — avoids false
	// positives from package-version strings.
	if !strings.Contains(s, "mark") && !strings.Contains(s, "mirror") &&
		!strings.Contains(s, "lore") {
		return ""
	}
	candidates := []string{
		`"v1:"`,
		`'v1:'`,
		"`v1:`",
		`"lore-v1:"`,
		`"lore_v1:"`,
		`"lore@v0:"`,
	}
	for _, c := range candidates {
		if strings.Contains(s, c) {
			return c
		}
	}
	return ""
}

// detectIndexLies parses Go mod-declaration-style files (mod.rs, main.go,
// __init__.py) for declared modules/packages whose disk path is missing.
// Returns one descriptor per discovered lie.
func detectIndexLies(path string, sub Substrate) []string {
	var lies []string

	switch sub {
	case SubstrateRust:
		lies = append(lies, detectRustModLies(path)...)
	case SubstrateGo:
		// Go INDEX-LIE class: a doc.go comment declaring a sub-package
		// that has no directory. Cheap probe: scan only top-level
		// doc.go files.
		lies = append(lies, detectGoDocLies(path)...)
	}
	return lies
}

// detectRustModLies walks every src/lib.rs / src/mod.rs and asserts each
// `pub mod XYZ;` line has a corresponding file/dir on disk.
func detectRustModLies(path string) []string {
	var lies []string
	candidates := []string{
		filepath.Join(path, "src", "lib.rs"),
		filepath.Join(path, "src", "main.rs"),
	}
	for _, c := range candidates {
		f, err := os.Open(c)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		f.Close()
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "pub mod ") && !strings.HasPrefix(line, "mod ") {
				continue
			}
			// "pub mod foo;"  or "mod foo;"
			line = strings.TrimPrefix(line, "pub ")
			line = strings.TrimPrefix(line, "mod ")
			line = strings.TrimSuffix(line, ";")
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			// Skip inline mod blocks: "mod foo {"
			if strings.Contains(line, "{") {
				continue
			}
			// Look for foo.rs or foo/mod.rs.
			modName := strings.TrimSpace(strings.Split(line, " ")[0])
			dir := filepath.Dir(c)
			file := filepath.Join(dir, modName+".rs")
			subdir := filepath.Join(dir, modName, "mod.rs")
			if !exists(file) && !exists(subdir) {
				lies = append(lies, "rust mod "+modName+" declared in "+filepath.Base(c)+" not on disk")
			}
		}
	}
	return lies
}

// detectGoDocLies walks for top-level doc.go files. Looks for `// Package
// XYZ` declarations whose XYZ doesn't match the directory name.
func detectGoDocLies(path string) []string {
	var lies []string
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(p) != "doc.go" {
			return nil
		}
		// Cap depth at 3 below root.
		rel, _ := filepath.Rel(path, p)
		if strings.Count(rel, string(filepath.Separator)) > 3 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		// Cap the read at 1 MiB, matching the guard pattern in
		// detectRustModLies (io.LimitReader(f, 1<<20)). os.ReadFile was
		// unbounded — a pathologically large doc.go could pull the whole
		// file into memory; the `// Package` declaration is always in the
		// first bytes, so the cap never changes an honest verdict.
		body, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		f.Close()
		// Look for: "// Package foo" where foo != filepath.Base(filepath.Dir(p))
		dirName := filepath.Base(filepath.Dir(p))
		s := string(body)
		idx := strings.Index(s, "// Package ")
		if idx == -1 {
			return nil
		}
		rest := s[idx+len("// Package "):]
		nl := strings.IndexByte(rest, '\n')
		if nl == -1 {
			nl = len(rest)
		}
		decl := strings.TrimSpace(rest[:nl])
		// First word.
		parts := strings.Fields(decl)
		if len(parts) == 0 {
			return nil
		}
		declName := parts[0]
		if declName != dirName && declName != "main" {
			lies = append(lies, "go doc.go in "+rel+" declares package "+declName+" but dir is "+dirName)
		}
		return nil
	})
	return lies
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
