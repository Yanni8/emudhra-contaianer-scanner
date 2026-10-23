// Package report renders scan results as human-readable text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/scan"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/stores"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/units"
)

// WriteJSON writes r as indented JSON.
func WriteJSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// width is the target line width of the text report. Table rows and single
// words (paths, hashes, URLs) may exceed it; prose is wrapped to it.
const width = 110

// severities in display order, worst first.
var severities = []blocklist.Severity{blocklist.SeverityCritical, blocklist.SeverityHigh, blocklist.SeverityMedium, blocklist.SeverityLow, blocklist.SeverityInfo}

// WriteText writes a plain-text report without ANSI colours: the image and
// package header, the findings at medium severity or above grouped by file,
// the low/info findings, the summary with the stores and the warnings.
// verbose lists every store that holds certificates (per-certificate
// directories collapsed to one row each), spells out the low/info findings
// and adds each finding's explanation and references.
func WriteText(w io.Writer, r *scan.Result, verbose bool) error {
	p := &printer{w: w}
	p.header(r, verbose)
	p.findings(r, verbose)
	p.summary(r, verbose)
	return p.err
}

// printer accumulates write errors so that the callers stay readable.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

// para writes text wrapped to the report width: the first line starts with
// prefix, continuation lines are indented by its width.
func (p *printer) para(prefix, text string) {
	p.hang(prefix, len(prefix), text)
}

// hang writes text wrapped to the report width with a hanging indent: the
// first line starts with prefix (printed verbatim, whatever its spacing),
// continuation lines are indented by indent spaces. A text that fits on the
// first line keeps its spacing as is.
func (p *printer) hang(prefix string, indent int, text string) {
	if strings.TrimSpace(text) == "" {
		p.line("%s", strings.TrimRight(prefix, " "))
		return
	}
	if len(prefix)+len(text) <= width {
		p.line("%s%s", prefix, text)
		return
	}
	lines := wrap(text, width-len(prefix))
	p.line("%s%s", prefix, lines[0])
	if len(lines) == 1 {
		return
	}
	pad := strings.Repeat(" ", indent)
	for _, l := range wrap(strings.Join(lines[1:], " "), width-indent) {
		p.line("%s%s", pad, l)
	}
}

// wrap breaks text into lines of at most n characters at spaces; words
// longer than n stay whole.
func wrap(text string, n int) []string {
	if n < 20 {
		n = 20
	}
	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			continue
		}
		cur := words[0]
		for _, wd := range words[1:] {
			if len(cur)+1+len(wd) > n {
				lines = append(lines, cur)
				cur = wd
				continue
			}
			cur += " " + wd
		}
		lines = append(lines, cur)
	}
	return lines
}

func (p *printer) header(r *scan.Result, verbose bool) {
	p.line("%s %s (blocklist %s)", r.Scanner.Name, r.Scanner.Version, r.Scanner.BlocklistVersion)
	if r.Image.Reference != "" {
		p.line("Image:     %s", r.Image.Reference)
		if r.Image.Digest != "" {
			p.line("Digest:    %s", r.Image.Digest)
		}
		platform := r.Image.Platform
		if platform == "" {
			platform = "unknown platform"
		}
		size := "size unknown"
		if r.Image.CompressedSize >= 0 {
			size = units.Bytes(r.Image.CompressedSize) + " compressed"
		}
		p.line("Platform:  %s (%s, %s)", platform, units.Plural(r.Image.Layers, "layer", "layers"), size)
	}
	p.line("OS:        %s", osLine(r.OS))
	p.packages(r, verbose)
	if len(r.EnvHints) > 0 {
		p.line("Environment:")
		for _, h := range r.EnvHints {
			prefix := "  "
			if h.Warning {
				prefix = "  WARNING "
			}
			p.para(prefix, fmt.Sprintf("%s=%s: %s", h.Variable, h.Value, h.Description))
		}
	}
	p.line("")
}

// osLine renders the operating system: the pretty name, followed by the ID
// and version from os-release when the pretty name does not already state
// them ("Distroless (debian 12)", "Alpine Linux v3.20 (alpine 3.20.10)").
func osLine(os stores.OSInfo) string {
	id := strings.TrimSpace(os.ID + " " + os.VersionID)
	switch {
	case os.PrettyName == "" && id == "":
		return "unknown (no os-release)"
	case os.PrettyName == "":
		return id
	case id == "":
		return os.PrettyName
	}
	pretty := strings.ToLower(os.PrettyName)
	if strings.Contains(pretty, strings.ToLower(os.ID)) && strings.Contains(pretty, strings.ToLower(os.VersionID)) {
		return os.PrettyName
	}
	return os.PrettyName + " (" + id + ")"
}

// packages prints the package table under a heading that names the package
// database the versions come from, or says that none was found or read.
func (p *printer) packages(r *scan.Result, verbose bool) {
	db := r.Summary.PackageDatabase
	noDB := db == "" || db == "none"
	switch {
	case len(r.Packages) == 0 && noDB:
		p.para("Packages:  ", "none found (no dpkg, apk or rpm database in the image; package versions were not determined)")
		return
	case len(r.Packages) == 0 && strings.Contains(db, "not parsed"):
		p.para("Packages:  ", "not determined: "+db)
		return
	case len(r.Packages) == 0:
		p.para("Packages:  ", "no trust-relevant package is installed (database: "+db+")")
		return
	case noDB:
		p.line("Packages (no dpkg, apk or rpm database in the image; runtime versions only):")
	default:
		p.line("Packages (%s):", db)
	}
	nameW, versionW, managerW := 0, 0, 0
	for _, pk := range r.Packages {
		nameW = max(nameW, len(pk.Name))
		versionW = max(versionW, len(pk.Version))
		managerW = max(managerW, len(pk.Manager))
	}
	// Caps keep a single very long name or version from pushing every row's
	// verdict off the line; a cell longer than its column overflows alone.
	nameW, versionW = min(nameW, 32), min(versionW, 32)
	for _, pk := range r.Packages {
		prefix := fmt.Sprintf("  %-*s  %-*s  %-*s  ", nameW, pk.Name, versionW, pk.Version, managerW, pk.Manager)
		p.hang(prefix, len(prefix), packageVerdict(pk))
		for _, extra := range packageExtras(pk, verbose) {
			p.hang("      "+extra.label, 6+len(extra.label), extra.text)
		}
	}
}

// packageVerdict renders the comparison column of a package row.
func packageVerdict(pk scan.PackageStatus) string {
	switch {
	case pk.Outdated == nil && pk.FixedVersion != "":
		return "not compared (fix: " + pk.FixedVersion + ")"
	case pk.Outdated == nil && pk.Note != "":
		return pk.Note
	case pk.Outdated == nil:
		return "no fix tracked"
	case *pk.Outdated && pk.FixedVersion != "":
		return "OUTDATED: fixed in " + pk.FixedVersion
	case *pk.Outdated:
		return "OUTDATED: no fixed release in this line"
	case pk.FixedVersion != "":
		return "ok (fixed in " + pk.FixedVersion + ")"
	}
	return "ok"
}

// labelled is a continuation line of a table row.
type labelled struct{ label, text string }

// packageExtras lists the continuation lines of a package row: the note when
// it is not already the verdict, where the version was read from, and in
// verbose mode the reference.
func packageExtras(pk scan.PackageStatus, verbose bool) []labelled {
	var out []labelled
	if pk.Note != "" && pk.Outdated != nil {
		out = append(out, labelled{"note: ", pk.Note})
	}
	if pk.Path != "" {
		out = append(out, labelled{"from: ", pk.Path})
	}
	if verbose && pk.Reference != "" {
		out = append(out, labelled{"ref:  ", pk.Reference})
	}
	return out
}

// findings prints the significant findings grouped by store path, then the
// low/info ones.
func (p *printer) findings(r *scan.Result, verbose bool) {
	var main, low []scan.Finding
	for _, f := range r.Findings {
		if f.Severity >= blocklist.SeverityMedium {
			main = append(main, f)
		} else {
			low = append(low, f)
		}
	}
	if len(r.Findings) == 0 {
		p.para("Findings: ", noFindingsText(r))
		p.bundleNote(r)
		p.line("")
		return
	}
	p.line("Findings (%s):", countsText(r))
	p.bundleNote(r)
	if len(main) > 0 {
		p.groups(main, verbose)
	} else {
		p.line("  none at medium severity or above")
	}
	p.line("")
	if len(low) > 0 {
		const heading = "Low/info findings (related roots, distrusted or disabled copies, heuristics"
		if verbose {
			p.line("%s):", heading)
			p.groups(low, verbose)
		} else {
			p.line("%s; run with --verbose for details):", heading)
			for _, f := range low {
				p.line("  [%s] %s (%s) in %s (%s%s)", strings.ToUpper(f.Severity.String()), headline(f), f.Category, f.Path, f.Trust.State, matchSuffix(f))
			}
		}
		p.line("")
	}
}

// noFindingsText states that nothing was found, honestly: it counts the
// stores that could be read and the files that could not be inspected.
func noFindingsText(r *scan.Result) string {
	n := countStores(r)
	unreadable := unreadableFiles(r.Warnings)
	switch {
	case unreadable > 0 && n > 0:
		return fmt.Sprintf("none in the %s that could be read; %s could not be inspected (see Warnings).",
			units.Plural(n, "store", "stores"), units.Plural(unreadable, "file", "files"))
	case unreadable > 0:
		return fmt.Sprintf("none in the files that could be read; %s could not be inspected (see Warnings).", units.Plural(unreadable, "file", "files"))
	case n == 0:
		return "none. No certificate at all was found in the image."
	}
	return fmt.Sprintf("none. No certificate affected by the eMudhra compromise was found in any of the %s that hold certificates.", units.Plural(n, "store", "stores"))
}

// unreadableMarkers identify warnings about a trust store that could not be
// read in full: keystores that did not open or were cut short, and files or
// objects beyond the parser limits.
var unreadableMarkers = []string{": pkcs12: ", ": jks: ", "whole-file parser limit", "is longer than the buffer limit"}

// unreadableFiles counts the distinct files whose warnings say that they
// could not be inspected in full.
func unreadableFiles(warnings []string) int {
	seen := map[string]bool{}
	for _, w := range warnings {
		for _, m := range unreadableMarkers {
			if strings.Contains(w, m) {
				file, _, _ := strings.Cut(w, ": ")
				seen[file] = true
				break
			}
		}
	}
	return len(seen)
}

// bundleNote says when the image has no system CA bundle, whether the
// ca-certificates package is installed anyway and, when it is not, which
// version to add for the detected distribution.
func (p *printer) bundleNote(r *scan.Result) {
	if r.Summary.SystemBundleFound {
		return
	}
	var sb strings.Builder
	pk := caCertificatesPackage(r.Packages)
	if pk != nil {
		fmt.Fprintf(&sb, "no system CA bundle was found although %s %s (%s) is installed: the bundle file is missing or lives at a path the scanner does not know. ", pk.Name, pk.Version, pk.Manager)
	} else {
		sb.WriteString("the image carries no system CA bundle (no ca-certificates package). ")
	}
	sb.WriteString("Programs in it cannot verify TLS peers unless they bring their own trust store.")
	if pk == nil {
		if fix, ok := stores.CACertificatesFix(r.OS); ok && fix.FixedVersion != "" {
			fmt.Fprintf(&sb, " If one is added, use %s %s or later.", fix.Component, fix.FixedVersion)
		}
	}
	p.para("Note: ", sb.String())
}

// caCertificatesPackage returns the installed package that carries the
// system trust store, or nil.
func caCertificatesPackage(pkgs []scan.PackageStatus) *scan.PackageStatus {
	for i := range pkgs {
		switch pkgs[i].Name {
		case "ca-certificates", "ca-certificates-bundle", "ca-certificates-mozilla":
			return &pkgs[i]
		}
	}
	return nil
}

// headline names a finding: the entry name, or for a certificate issued by
// a listed CA its own name with the issuer.
func headline(f scan.Finding) string {
	if f.Category == blocklist.CategoryIssuedBy && f.IssuerEntryName != "" {
		return f.EntryName + " issued by " + f.IssuerEntryName
	}
	return f.EntryName
}

func matchSuffix(f scan.Finding) string {
	if f.Match == blocklist.MatchFingerprint {
		return ""
	}
	return ", " + string(f.Match) + " match"
}

// groups prints findings grouped by path, in the order given (already sorted
// by severity then path): the findings, the store and every distinct
// remediation.
func (p *printer) groups(findings []scan.Finding, verbose bool) {
	byPath := map[string][]scan.Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := byPath[f.Path]; !ok {
			order = append(order, f.Path)
		}
		byPath[f.Path] = append(byPath[f.Path], f)
	}
	for _, path := range order {
		group := byPath[path]
		p.line("")
		p.line("%s", path)
		for _, f := range group {
			p.finding(f, verbose)
		}
		st := group[0].Store
		p.para("  store: ", fmt.Sprintf("%s (%s, %s); consumers: %s", st.Name, st.Class, st.Ecosystem, strings.Join(st.Consumers, ", ")))
		p.remediations(group)
	}
}

// remediations prints the group's remediation once when every finding
// shares it, otherwise each distinct text with the findings it applies to.
func (p *printer) remediations(group []scan.Finding) {
	type rem struct {
		text  string
		names []string
	}
	var rems []*rem
	byText := map[string]*rem{}
	for _, f := range group {
		r := byText[f.Remediation]
		if r == nil {
			r = &rem{text: f.Remediation}
			byText[f.Remediation] = r
			rems = append(rems, r)
		}
		if name := headline(f); !slices.Contains(r.names, name) {
			r.names = append(r.names, name)
		}
	}
	const prefix = "  remediation: "
	if len(rems) == 1 {
		p.para(prefix, rems[0].text)
		return
	}
	for _, r := range rems {
		p.hang("  remediation for "+strings.Join(r.names, ", ")+": ", len(prefix), r.text)
	}
}

// finding prints one finding.
func (p *printer) finding(f scan.Finding, verbose bool) {
	p.line("  [%s] %s (%s, %s match)", strings.ToUpper(f.Severity.String()), headline(f), f.Category, f.Match)
	c := f.Certificate
	if c.Subject != "" {
		p.para("         subject: ", c.Subject)
	}
	if c.SHA256 != "" {
		p.line("         sha256:  %s", c.SHA256)
	} else if c.SPKISHA256 != "" {
		p.line("         spki:    %s (public key only)", c.SPKISHA256)
	}
	if !c.NotAfter.IsZero() {
		p.line("         valid:   %s to %s", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	}
	p.para("         trust:   ", f.Trust.State+" - "+f.Trust.Detail)
	if f.Trust.Purposes != nil {
		purposes := strings.Join(f.Trust.Purposes, ", ")
		if purposes == "" {
			purposes = "none of the standard purposes"
		}
		p.para("         trusted for: ", purposes)
	}
	ex := splitExplanation(f)
	where := fmt.Sprintf("%s at offset %d", c.Kind, c.Offset)
	if ex.alsoAt != "" {
		where += " (also at offset " + ex.alsoAt + ")"
	}
	if c.Label != "" {
		where = fmt.Sprintf("label/alias %q, %s", c.Label, where)
	}
	p.para("         found:   ", where)
	if len(f.Aliases) > 0 {
		p.para("         aliases: ", strings.Join(f.Aliases, ", "))
	}
	if ex.note != "" {
		p.para("         note:    ", ex.note)
	}
	if verbose {
		if ex.why != "" {
			p.para("         why:     ", ex.why)
		}
		if len(f.References) > 0 {
			p.para("         refs:    ", strings.Join(f.References, ", "))
		}
	}
}

// explanation is Finding.Explanation taken apart: the reasoning, the other
// offsets of the same certificate in the file and the parser note.
type explanation struct {
	why    string
	alsoAt string
	note   string
}

// Markers of the sentences the scan engine appends to an explanation.
const (
	trustMarker  = " Trust: "
	alsoAtMarker = " The same certificate appears again at offset "
	alsoAtEnd    = " of this file."
	noteMarker   = " Parser note: "
)

// splitExplanation separates the parts of a finding's explanation. The scan
// engine composes it as reasoning, then "Trust: <state> (<detail>).", then
// optionally "The same certificate appears again at offset N, M of this
// file." and "Parser note: <note>."; the trust sentence duplicates the trust
// line of the report and is dropped.
func splitExplanation(f scan.Finding) explanation {
	ex := explanation{why: strings.TrimSpace(f.Explanation)}
	text := " " + ex.why
	tail := ""
	if i := strings.LastIndex(text, trustMarker+f.Trust.State+" ("); i >= 0 {
		ex.why = strings.TrimSpace(text[:i])
		tail = text[i:]
	} else if i := strings.Index(text, alsoAtMarker); i >= 0 {
		ex.why, tail = strings.TrimSpace(text[:i]), text[i:]
	} else if i := strings.Index(text, noteMarker); i >= 0 {
		ex.why, tail = strings.TrimSpace(text[:i]), text[i:]
	}
	if i := strings.Index(tail, noteMarker); i >= 0 {
		ex.note = strings.TrimSuffix(strings.TrimSpace(tail[i+len(noteMarker):]), ".")
		tail = tail[:i]
	}
	if i := strings.Index(tail, alsoAtMarker); i >= 0 {
		ex.alsoAt = strings.TrimSuffix(strings.TrimSpace(tail[i+len(alsoAtMarker):]), alsoAtEnd)
	}
	return ex
}

// countsText renders "1 critical, 3 high, 2 low; 4 distinct certificates".
func countsText(r *scan.Result) string {
	var parts []string
	for _, s := range severities {
		if n := r.Summary.FindingsBySeverity[s.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	text := strings.Join(parts, ", ")
	if n := r.Summary.AffectedCertificates; n > 0 {
		text += "; " + units.Plural(n, "distinct certificate", "distinct certificates")
	}
	return text
}

// summary prints the counts, the stores and the warnings.
func (p *printer) summary(r *scan.Result, verbose bool) {
	p.line("Summary:")
	for _, s := range severities {
		p.line("  %-9s %d", s, r.Summary.FindingsBySeverity[s.String()])
	}
	p.line("  %s in %s scanned (%s), %s with certificates, %d ms",
		units.Plural(r.Summary.CertificatesFound, "certificate", "certificates"),
		units.Plural(r.Summary.FilesScanned, "file", "files"),
		units.Bytes(r.Summary.BytesScanned),
		units.Plural(countStores(r), "store", "stores"),
		r.Summary.DurationMS)
	p.stores(r, verbose)
	if len(r.Warnings) > 0 {
		p.line("Warnings (%d):", len(r.Warnings))
		limit := len(r.Warnings)
		if !verbose && limit > 20 {
			limit = 20
		}
		for _, wmsg := range r.Warnings[:limit] {
			p.para("  - ", wmsg)
		}
		if limit < len(r.Warnings) {
			p.line("  ... %d more (run with --verbose)", len(r.Warnings)-limit)
		}
	}
}

// storeRow is one line of the store table: a store, or in verbose mode a
// directory of stores without findings collapsed into one row.
type storeRow struct {
	path         string
	class        stores.Class
	certificates int
	duplicates   int
	findings     int
	files        int // > 1 for a collapsed directory
	aliases      []string
	classifiedBy string
}

// stores prints the store table: every store with findings, and in verbose
// mode every store seen, with per-certificate directories (Debian sources,
// p11-kit directory hashes) collapsed to one row per directory.
func (p *printer) stores(r *scan.Result, verbose bool) {
	var rows []storeRow
	if verbose {
		rows = collapseStores(r.Stores)
	} else {
		for _, s := range r.Stores {
			if s.Findings > 0 {
				rows = append(rows, rowOf(s))
			}
		}
	}
	switch {
	case verbose && len(rows) == 0:
		p.line("Stores scanned: no file holding certificates among the %s examined", units.Plural(r.Summary.FilesScanned, "file", "files"))
		return
	case verbose:
		p.line("Stores scanned (%d with certificates):", countStores(r))
	case len(rows) == 0:
		p.line("Stores with findings: none")
		return
	default:
		p.line("Stores with findings:")
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].path < rows[j].path })
	classW, copies := len("class"), false
	for _, row := range rows {
		classW = max(classW, len(row.class))
		copies = copies || row.duplicates > 0
	}
	const certW, findW = 12, 8
	p.line("  %*s  %*s  %-*s  %s", certW, "certificates", findW, "findings", classW, "class", "path")
	// Continuation lines hang at the class column: long alias lists then
	// keep most of the width.
	indent := strings.Repeat(" ", 2+certW+2+findW+2)
	for _, row := range rows {
		certs := fmt.Sprint(row.certificates)
		if row.duplicates > 0 {
			certs += fmt.Sprintf(" (+%d)", row.duplicates)
		}
		path := row.path
		if row.files > 1 {
			path += fmt.Sprintf(" (%s)", units.Plural(row.files, "file", "files"))
		}
		p.line("  %*s  %*d  %-*s  %s", certW, certs, findW, row.findings, classW, row.class, path)
		if row.classifiedBy != "" {
			p.para(indent+"classified by link name: ", row.classifiedBy)
		}
		if len(row.aliases) > 0 {
			p.para(indent+"also: ", strings.Join(row.aliases, ", "))
		}
	}
	if copies {
		p.line("  (+N): further copies of the same certificates in the file")
	}
}

func rowOf(s scan.StoreSummary) storeRow {
	return storeRow{path: s.Path, class: s.Class, certificates: s.Certificates, duplicates: s.Duplicates, findings: s.Findings, files: 1, aliases: s.Aliases, classifiedBy: s.ClassifiedBy}
}

// collapseStores keeps every store with findings as its own row and merges
// the stores without findings that share a directory, class and store name
// (the per-certificate files of a source or hash directory) into one row
// per directory.
func collapseStores(all []scan.StoreSummary) []storeRow {
	type key struct {
		dir, name string
		class     stores.Class
	}
	var rows []storeRow
	groups := map[key]int{}
	for _, s := range all {
		if s.Findings > 0 {
			rows = append(rows, rowOf(s))
			continue
		}
		k := key{dir: path.Dir(s.Path), name: s.Name, class: s.Class}
		if i, ok := groups[k]; ok {
			rows[i].files++
			rows[i].certificates += s.Certificates
			rows[i].duplicates += s.Duplicates
			rows[i].aliases, rows[i].classifiedBy = nil, ""
			continue
		}
		groups[k] = len(rows)
		rows = append(rows, rowOf(s))
	}
	for i := range rows {
		if rows[i].files > 1 {
			rows[i].path = path.Dir(rows[i].path) + "/"
		}
	}
	return rows
}

func countStores(r *scan.Result) int {
	n := 0
	for _, s := range r.Stores {
		if s.Certificates > 0 {
			n++
		}
	}
	return n
}

// ExitLine explains the exit code for a threshold.
func ExitLine(r *scan.Result, threshold blocklist.Severity, enabled bool) string {
	if !enabled {
		return "Exit code: 0 (--fail-on never)"
	}
	if len(r.Findings) > 0 && r.MaxSeverity() >= threshold {
		return fmt.Sprintf("Exit code: 2 (findings at or above %s; highest is %s)", threshold, r.MaxSeverity())
	}
	if len(r.Findings) > 0 {
		return fmt.Sprintf("Exit code: 0 (no findings at or above %s; highest is %s)", threshold, r.MaxSeverity())
	}
	return "Exit code: 0 (no findings)"
}
