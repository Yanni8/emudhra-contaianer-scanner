package scan

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Yanni8/emudhra-container-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-container-scanner/internal/certs"
	"github.com/Yanni8/emudhra-container-scanner/internal/stores"
)

// finish resolves aliases, store classes, trust and severity for every
// candidate and assembles the result.
func (w *walker) finish() *Result {
	version := w.opts.Version
	if version == "" {
		version = Version
	}
	res := &Result{
		Scanner:  Scanner{Name: Name, Version: version, BlocklistVersion: w.bl.Version},
		Warnings: w.warnings,
	}
	res.OS = w.osInfo()
	w.os = res.OS
	res.EnvHints = stores.EnvHints(w.opts.Env)
	w.hints = res.EnvHints
	res.Packages = w.packages(res.OS)
	w.facts.HasDebianConf = w.caConf != nil
	w.facts.HasUpdateCACertificates = w.updateCACerts
	w.facts.HasPackageManager = w.pkgManager
	if w.caConf != nil {
		c := stores.ParseDebianConf(w.caConf)
		w.conf = &c
	}
	w.aliases = w.aliasIndex()
	w.promoteStores()
	w.collectDistrust()

	affected := map[string]bool{}
	for i := range w.candidates {
		c := &w.candidates[i]
		res.Findings = append(res.Findings, w.finding(c))
		w.stores[c.path].findings++
		affected[c.identity] = true
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Certificate.Subject != b.Certificate.Subject {
			return a.Certificate.Subject < b.Certificate.Subject
		}
		return a.Certificate.Offset < b.Certificate.Offset
	})

	bundleFound := false
	for _, p := range w.storeList {
		ss := w.stores[p]
		if ss.final.Class == stores.ClassSystemBundle && ss.certs > 0 {
			bundleFound = true
		}
		res.Stores = append(res.Stores, StoreSummary{
			Path:         p,
			Class:        ss.final.Class,
			Name:         ss.final.Name,
			Ecosystem:    ss.final.Ecosystem,
			ClassifiedBy: ss.via,
			Aliases:      w.aliases[p],
			Certificates: ss.certs,
			Duplicates:   ss.blocks - ss.certs,
			Findings:     ss.findings,
		})
	}
	sort.SliceStable(res.Stores, func(i, j int) bool { return res.Stores[i].Path < res.Stores[j].Path })

	res.Summary = Summary{
		FilesScanned:         w.files,
		BytesScanned:         w.bytes,
		CertificatesFound:    w.certsFound,
		AffectedCertificates: len(affected),
		FindingsBySeverity:   map[string]int{},
		SystemBundleFound:    bundleFound,
		PackageDatabase:      "none",
		DurationMS:           time.Since(w.start).Milliseconds(),
	}
	for sev := blocklist.SeverityInfo; sev <= blocklist.SeverityCritical; sev++ {
		res.Summary.FindingsBySeverity[sev.String()] = 0
	}
	for _, f := range res.Findings {
		res.Summary.FindingsBySeverity[f.Severity.String()]++
	}
	if len(res.Findings) > 0 {
		res.Summary.MaxSeverity = res.MaxSeverity().String()
	}
	if len(w.packageDBs) > 0 {
		res.Summary.PackageDatabase = strings.Join(w.packageDBs, ", ")
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	if res.Stores == nil {
		res.Stores = []StoreSummary{}
	}
	if res.Packages == nil {
		res.Packages = []PackageStatus{}
	}
	if res.EnvHints == nil {
		res.EnvHints = []stores.EnvHint{}
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	return res
}

// osInfo parses os-release, preferring /etc over /usr/lib.
func (w *walker) osInfo() stores.OSInfo {
	if w.osRelease != nil {
		return stores.ParseOSRelease(w.osRelease)
	}
	if w.libOSRelease != nil {
		return stores.ParseOSRelease(w.libOSRelease)
	}
	return stores.OSInfo{}
}

// standardPurposes lists the purposes stores record trust for, in the order
// they are reported.
var standardPurposes = []certs.Purpose{certs.PurposeServerAuth, certs.PurposeClientAuth, certs.PurposeCodeSigning, certs.PurposeEmailProtection}

// relevantPurposes returns the purposes an entry's trust matters for: TLS
// server authentication for the TLS intermediates, code signing for the
// code-signing ones, both for the roots that anchor them.
func relevantPurposes(e *blocklist.Entry) []certs.Purpose {
	if e != nil {
		switch e.Usage {
		case "tls":
			return []certs.Purpose{certs.PurposeServerAuth}
		case "code-signing":
			return []certs.Purpose{certs.PurposeCodeSigning}
		}
	}
	return []certs.Purpose{certs.PurposeServerAuth, certs.PurposeCodeSigning}
}

// trustFor resolves the container's per-purpose trust for the candidate.
func (c *candidate) trustFor(purposes ...certs.Purpose) (certs.TrustState, string) {
	f := certs.Found{Trust: c.trust, TrustDetail: c.detail, Purposes: c.purposes}
	return f.TrustFor(purposes...)
}

// effectivePurposes lists the standard purposes the store anchors the
// certificate for, when the container records trust per purpose: the
// explicitly anchored ones, or, in a store that trusts its content by
// default and records no anchor at all, every purpose that is not
// rejected (OpenSSL treats a certificate with only a reject list that way).
// ok is false when the container carries no purpose information.
func effectivePurposes(c *candidate, trustedByDefault bool) (anchors []string, ok bool) {
	if c.purposes == nil {
		return nil, false
	}
	anchors = []string{}
	for _, p := range standardPurposes {
		if c.purposes[p] == certs.TrustAnchor {
			anchors = append(anchors, string(p))
		}
	}
	if len(anchors) == 0 && trustedByDefault {
		for _, p := range standardPurposes {
			if c.purposes[p] != certs.TrustDistrusted {
				anchors = append(anchors, string(p))
			}
		}
	}
	return anchors, true
}

// verdict is the outcome of trustOf: the trust to report and, when the
// decision implies an action of its own (a stale generated file), that
// action for the remediation.
type verdict struct {
	trust  TrustInfo
	action string
}

func trusted(detail string, purposes []string) verdict {
	return verdict{trust: TrustInfo{State: TrustTrusted, Detail: detail, Purposes: purposes}}
}

func distrusted(detail string) verdict {
	return verdict{trust: TrustInfo{State: TrustDistrusted, Detail: detail}}
}

func embedded(detail string) verdict {
	return verdict{trust: TrustInfo{State: TrustEmbedded, Detail: detail}}
}

func unknown(detail string) verdict {
	return verdict{trust: TrustInfo{State: TrustUnknown, Detail: detail}}
}

// isExecutableClass reports whether the store is an executable or shared library.
func isExecutableClass(class stores.Class) bool {
	return class == stores.ClassEmbeddedRuntime || class == stores.ClassEmbeddedBinary
}

// regenTool names the command that regenerates a p11-kit family store.
func regenTool(st stores.Store) string {
	if strings.Contains(st.Name, "SUSE") {
		return "update-ca-certificates"
	}
	return "update-ca-trust"
}

// trustOf decides whether the image trusts the candidate's certificate, in
// the store it was promoted to.
func (w *walker) trustOf(c *candidate, ss *storeState, aliases []string, primary blocklist.Match) verdict {
	st := ss.final
	entry := primary.Entry

	// Blocklist directories, by real path or by any link name.
	if name, ok := blocklistName(c.path, aliases); ok {
		if name != c.path {
			return distrusted("linked from a blocklist directory as " + name + ": explicitly distrusted")
		}
		return distrusted("stored in a blocklist directory (" + st.Name + "): explicitly distrusted")
	}

	// Bare public keys inside executables are tables: the SPKI blocklist a
	// fixed runtime carries when the key is compromised, a trust-anchor
	// table (webpki-roots layout) otherwise.
	if c.info.Kind == certs.KindSPKI && isExecutableClass(st.Class) {
		if entry != nil && entry.Category == blocklist.CategoryCompromisedKey {
			return distrusted("bare public key of a compromised intermediate found in an executable: this is the SPKI blocklist a fixed runtime carries, evidence that the program rejects the leaked keys")
		}
		if st.Class == stores.ClassEmbeddedRuntime {
			return embedded("compiled into " + runtimeName(st) + " as a bare trust-anchor table (webpki-roots layout): trusted by every program that uses this runtime's bundled store")
		}
		return embedded("bare trust-anchor table (webpki-roots layout) embedded in the executable: the program uses the key as a trust anchor")
	}

	// Whole distrust recorded by the container itself.
	if c.trust == certs.TrustDistrusted {
		return distrusted("marked distrusted by the store itself (" + c.detail + ")")
	}

	// The p11-kit blocklist (and x-distrusted objects) wins over every
	// other source of the same tree; a generated file that still carries a
	// blocklisted certificate is stale.
	if p11KitFamily(c.path, aliases) {
		if src, ok := w.distrust.lookup(c.info); ok && src != c.path {
			if st.SystemGenerated {
				tool := regenTool(st)
				return verdict{
					trust:  TrustInfo{State: TrustTrusted, Detail: "blocklisted by " + src + " but this generated store still carries the certificate (stale: run " + tool + " to regenerate it)"},
					action: "Run " + tool + " so that the generated stores drop the blocklisted certificate, and rebuild the image.",
				}
			}
			return distrusted("blocklisted by " + src + ": p11-kit gives the blocklist precedence over every trust source")
		}
	}

	// Per-purpose trust recorded by the container (OpenSSL trust/reject
	// attributes, certdata CKA_TRUST_*, p11-kit objects).
	anchors, hasPurposes := effectivePurposes(c, st.TrustedByDefault)
	if hasPurposes && len(anchors) == 0 {
		if state, text := c.trustFor(relevantPurposes(entry)...); state == certs.TrustDistrusted {
			return distrusted("rejected by the store for the purposes that matter here (" + text + ")")
		}
	}

	// A deselected Debian source file is decided by its configuration even
	// when a variable names the hashed directory its stale links sit in.
	if st.Class == stores.ClassSystemSource {
		if v, ok := w.deselectedSource(c, aliases); ok {
			return v
		}
	}
	if h, ok := w.envSelects(c.path, aliases, st); ok {
		how := "selected"
		if h.Default {
			how = "explicitly selected"
		}
		return trusted(fmt.Sprintf("%s by %s=%s: %s", how, h.Variable, h.Value, h.Description), purposeList(anchors, hasPurposes))
	}

	switch st.Class {
	case stores.ClassSystemSource:
		return w.sourceTrust(c, aliases, anchors, hasPurposes)
	case stores.ClassEmbeddedRuntime:
		return embedded("compiled into " + runtimeName(st) + ": trusted by every program that uses this runtime's bundled store")
	case stores.ClassEmbeddedBinary:
		return embedded("embedded in an executable or shared library; whether the program uses it as a trust anchor is unknown")
	case stores.ClassSystemBlocklist:
		return distrusted("stored in a blocklist directory: explicitly distrusted")
	case stores.ClassNSSDB:
		return unknown("NSS trust flags are per certificate and were not parsed; check them with certutil -L -d " + path.Dir(c.path))
	}
	if st.TrustedByDefault {
		switch {
		case st.LimitedTo != "":
			return trusted(st.Name+": certificates in this store are trusted for "+st.LimitedTo+" only", []string{st.LimitedTo})
		case hasPurposes:
			detail := st.Name + ": certificates in this store are trusted without further configuration"
			if c.detail != "" {
				detail += " (store flags: " + c.detail + ")"
			}
			return trusted(detail, anchors)
		}
		return trusted(st.Name+": certificates in this store are trusted without further configuration", nil)
	}
	if hasPurposes && len(anchors) > 0 || !hasPurposes && c.trust == certs.TrustAnchor {
		return trusted("marked as a trust anchor by the store itself ("+c.detail+")", purposeList(anchors, hasPurposes))
	}
	switch st.Class {
	case stores.ClassJavaKeystore:
		return unknown("keystore of unknown purpose: only matters if an application loads it as a truststore")
	case stores.ClassAppBundle:
		return unknown(st.Name + ": only trusted if the package that ships it loads it as a CA bundle")
	}
	return unknown("file outside any known trust store; an application may still point at it")
}

// purposeList returns the anchored purposes when the container records
// them, nil otherwise.
func purposeList(anchors []string, hasPurposes bool) []string {
	if !hasPurposes {
		return nil
	}
	return anchors
}

// sslCertsAlias returns the first alias inside the OpenSSL hashed directory.
func sslCertsAlias(aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "/etc/ssl/certs/") {
			return a
		}
	}
	return ""
}

// isDebianSource reports whether the file is selected through
// /etc/ca-certificates.conf (the configuration was captured).
func (w *walker) isDebianSource(p string) bool {
	return w.conf != nil && strings.HasPrefix(p, "/usr/share/ca-certificates/")
}

// deselectedSource handles a source file deselected ('!') in
// /etc/ca-certificates.conf: disabled when the generated bundle and the
// hashed directory agree, stale (still trusted) when either still carries
// the certificate because update-ca-certificates was not run.
func (w *walker) deselectedSource(c *candidate, aliases []string) (verdict, bool) {
	if !w.isDebianSource(c.path) {
		return verdict{}, false
	}
	if enabled, known := w.conf.Status(c.path); !known || enabled {
		return verdict{}, false
	}
	var stale []string
	if bundle, ok := w.bundleFP[c.info.SHA256]; ok {
		stale = append(stale, "the generated bundle "+bundle+" still contains it")
	}
	if a := sslCertsAlias(aliases); a != "" {
		stale = append(stale, "it is still linked from /etc/ssl/certs as "+a)
	}
	if len(stale) > 0 {
		return verdict{
			trust:  TrustInfo{State: TrustTrusted, Detail: "deselected ('!') in /etc/ca-certificates.conf but " + strings.Join(stale, " and ") + " (stale: run update-ca-certificates)"},
			action: "Run update-ca-certificates (and rebuild the image) so that the deselection takes effect: the generated bundle or the /etc/ssl/certs links still carry the certificate.",
		}, true
	}
	return verdict{trust: TrustInfo{State: TrustDisabled, Detail: "deselected ('!') in /etc/ca-certificates.conf: not copied into /etc/ssl/certs"}}, true
}

// sourceTrust decides trust for a per-CA source file: Debian's
// configuration (a deselection was handled by deselectedSource), the trust
// attributes of p11-kit sources, and the generated bundle or hashed
// directory that still carries the certificate.
func (w *walker) sourceTrust(c *candidate, aliases []string, anchors []string, hasPurposes bool) verdict {
	debian := w.isDebianSource(c.path)
	if debian {
		if _, known := w.conf.Status(c.path); known {
			return trusted("enabled in /etc/ca-certificates.conf: linked into /etc/ssl/certs and part of the generated bundle", nil)
		}
	}
	if hasPurposes && len(anchors) > 0 || !hasPurposes && c.trust == certs.TrustAnchor {
		return trusted("marked as a trust anchor by the store itself ("+c.detail+")", purposeList(anchors, hasPurposes))
	}
	if bundle, ok := w.bundleFP[c.info.SHA256]; ok {
		return trusted("the same certificate is present in the generated system bundle "+bundle, nil)
	}
	if a := sslCertsAlias(aliases); a != "" {
		return trusted("linked from the OpenSSL certificate directory as "+a, nil)
	}
	if debian {
		return unknown("not listed in /etc/ca-certificates.conf and not found in a generated bundle")
	}
	if hasPurposes && c.detail != "" {
		return unknown("source file without anchor flags (" + c.detail + ")")
	}
	return unknown("source file whose selection configuration was not found")
}

// severityOf ranks a finding. A certificate counts as anchored when the
// store trusts it or it is compiled into a runtime, or it is a bare key in
// a trust-anchor table of any executable; purposes recorded by the store
// lower an anchor's severity when they exclude TLS server authentication.
func severityOf(primary blocklist.Match, trust TrustInfo, class stores.Class, kind certs.Kind) blocklist.Severity {
	if primary.Kind == blocklist.MatchOperator || primary.Entry == nil {
		return blocklist.SeverityInfo
	}
	e := primary.Entry
	inactive := trust.State == TrustDistrusted || trust.State == TrustDisabled
	if primary.Kind == blocklist.MatchIssuedBy {
		if inactive {
			return blocklist.SeverityInfo
		}
		switch e.Category {
		case blocklist.CategoryCompromisedKey:
			return blocklist.SeverityMedium
		case blocklist.CategoryAnchor, blocklist.CategoryCustom:
			return blocklist.SeverityLow
		}
		return blocklist.SeverityInfo
	}
	anchored := trust.State == TrustTrusted || trust.State == TrustEmbedded && (class == stores.ClassEmbeddedRuntime || kind == certs.KindSPKI)
	switch e.Category {
	case blocklist.CategoryCompromisedKey:
		if inactive {
			return blocklist.SeverityInfo
		}
		return blocklist.SeverityCritical
	case blocklist.CategoryAnchor, blocklist.CategoryCustom:
		switch {
		case inactive:
			return blocklist.SeverityInfo
		case anchored:
			return anchorSeverity(trust.Purposes)
		}
		return blocklist.SeverityMedium
	case blocklist.CategoryRelated:
		if anchored && (trust.Purposes == nil || len(trust.Purposes) > 0) {
			return blocklist.SeverityLow
		}
		return blocklist.SeverityInfo
	}
	return e.Severity
}

// anchorSeverity rates a trusted anchor by the purposes the store records:
// high when it anchors TLS server authentication (or the store records no
// purposes), medium when it anchors code signing only, low when it is
// trusted for e-mail or client authentication only (no exposure to the
// compromised intermediates) or for nothing relevant.
func anchorSeverity(purposes []string) blocklist.Severity {
	if purposes == nil {
		return blocklist.SeverityHigh
	}
	has := map[string]bool{}
	for _, p := range purposes {
		has[p] = true
	}
	switch {
	case has[string(certs.PurposeServerAuth)]:
		return blocklist.SeverityHigh
	case has[string(certs.PurposeCodeSigning)]:
		return blocklist.SeverityMedium
	}
	return blocklist.SeverityLow
}

// purposeQualifier explains an anchor's limited purposes in the trust detail.
func purposeQualifier(category blocklist.Category, trust TrustInfo) string {
	if trust.Purposes == nil || trust.State != TrustTrusted && trust.State != TrustEmbedded {
		return ""
	}
	if category != blocklist.CategoryAnchor && category != blocklist.CategoryCustom {
		return ""
	}
	has := map[string]bool{}
	for _, p := range trust.Purposes {
		has[p] = true
	}
	list := strings.Join(trust.Purposes, ", ")
	switch {
	case has[string(certs.PurposeServerAuth)]:
		return ""
	case has[string(certs.PurposeCodeSigning)]:
		return "trusted for " + list + " only, not for TLS server authentication"
	case len(trust.Purposes) > 0:
		return "trusted for " + list + " only: no exposure to the compromised intermediates"
	}
	return "trusted for none of the standard purposes"
}

var categoryText = map[blocklist.Category]string{
	blocklist.CategoryCompromisedKey: "its private key is public knowledge, so anyone can issue certificates or sign code under it",
	blocklist.CategoryAnchor:         "it anchors the compromised eMudhra intermediates: a store that trusts it validates certificates forged with the leaked keys",
	blocklist.CategoryRelated:        "an eMudhra-operated root that is not known to be compromised, reported for awareness only",
	blocklist.CategoryCustom:         "it was supplied through a custom blocklist",
}

// matchText describes one match.
func matchText(m blocklist.Match, kind certs.Kind) string {
	e := m.Entry
	switch m.Kind {
	case blocklist.MatchFingerprint:
		return fmt.Sprintf("byte-for-byte the listed certificate %q (%s)", e.Name, e.Category)
	case blocklist.MatchSPKI:
		if kind == certs.KindSPKI {
			return fmt.Sprintf("the bare public key of the listed certificate %q (%s), embedded without a certificate as Rust webpki-roots trust-anchor tables and SPKI blocklists do", e.Name, e.Category)
		}
		return fmt.Sprintf("a certificate carrying the public key of the listed certificate %q (%s): a cross-signed or re-issued variant", e.Name, e.Category)
	case blocklist.MatchIssuedBy:
		verified := "signature verified"
		if e.Certificate == nil {
			verified = "matched by issuer name only"
		}
		return fmt.Sprintf("a certificate issued by the listed CA %q (%s; %s)", e.Name, e.Category, verified)
	}
	return "a certificate whose subject names eMudhra/emSign but which is not on the list (heuristic)"
}

// commonName extracts the CN attribute of an RFC 2253 subject string, or
// returns the whole string when it has none.
func commonName(subject string) string {
	rest := subject
	for rest != "" {
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if rest[i] == ',' {
				end = i
				break
			}
		}
		attr := rest[:end]
		if strings.HasPrefix(attr, "CN=") {
			return strings.ReplaceAll(attr[3:], `\,`, ",")
		}
		if end == len(rest) {
			break
		}
		rest = rest[end+1:]
	}
	return subject
}

// finding builds the report entry for a candidate.
func (w *walker) finding(c *candidate) Finding {
	ss := w.stores[c.path]
	aliases := w.aliases[c.path]
	primary := c.matches[0]
	v := w.trustOf(c, ss, aliases, primary)
	trust := v.trust
	f := Finding{
		Match:       primary.Kind,
		Path:        c.path,
		Aliases:     aliases,
		Store:       ss.final,
		Certificate: c.info,
	}
	if e := primary.Entry; e != nil {
		f.Category, f.EntryID, f.EntryName = e.Category, e.ID, e.Name
		f.References = append([]string(nil), e.References...)
		if primary.Kind == blocklist.MatchIssuedBy {
			f.Category = blocklist.CategoryIssuedBy
			f.IssuerEntryID, f.IssuerEntryName = e.ID, e.Name
			f.EntryName = commonName(c.info.Subject)
		}
	} else {
		f.Category = blocklist.CategoryRelated
		f.EntryID, f.EntryName = "operator-heuristic", "eMudhra/emSign subject (heuristic)"
	}
	if q := purposeQualifier(f.Category, trust); q != "" {
		trust.Detail += "; " + q
	}
	if ss.via != "" {
		trust.Detail += "; the store is identified by the link name " + ss.via
	}
	f.Trust = trust
	f.Severity = severityOf(primary, trust, ss.final.Class, c.info.Kind)

	var sb strings.Builder
	sb.WriteString("This is ")
	sb.WriteString(matchText(primary, c.info.Kind))
	sb.WriteString(".")
	if e := primary.Entry; e != nil {
		if txt := categoryText[e.Category]; txt != "" {
			sb.WriteString(" The entry matters because " + txt + ".")
		}
		if e.Notes != "" {
			sb.WriteString(" " + e.Notes)
		}
	} else {
		sb.WriteString(" No listed certificate matched; the operator heuristic only flags the name.")
	}
	if len(c.matches) > 1 {
		var others []string
		for _, m := range c.matches[1:] {
			if m.Entry != nil {
				others = append(others, fmt.Sprintf("%s %s", m.Kind, m.Entry.ID))
			}
		}
		if len(others) > 0 {
			sb.WriteString(" Also matches: " + strings.Join(others, ", ") + ".")
		}
	}
	sb.WriteString(fmt.Sprintf(" Trust: %s (%s).", trust.State, trust.Detail))
	if len(c.alsoAt) > 0 {
		offsets := make([]string, len(c.alsoAt))
		for i, o := range c.alsoAt {
			offsets[i] = fmt.Sprint(o)
		}
		sb.WriteString(" The same certificate appears again at offset " + strings.Join(offsets, ", ") + " of this file.")
	}
	if c.note != "" {
		sb.WriteString(" Parser note: " + c.note + ".")
	}
	f.Explanation = sb.String()
	f.Remediation = w.remediation(c, ss, primary, v)
	return f
}

// isSystemStore reports whether the store is part of the operating system's
// trust store, whose remediation is the distribution's.
func isSystemStore(st stores.Store) bool {
	switch st.Class {
	case stores.ClassSystemBundle, stores.ClassSystemSource, stores.ClassSystemAnchorDir:
		return true
	case stores.ClassJavaKeystore:
		return st.SystemGenerated
	}
	return false
}

// remediation composes the advice for a finding: nothing to do for related
// roots, distrusted and disabled copies and SPKI blocklists; the store's own
// sentence plus the distribution's action for system stores; the store's
// sentence plus the ecosystem fix (or the fact that the runtime is already
// fixed) for application and runtime stores.
func (w *walker) remediation(c *candidate, ss *storeState, primary blocklist.Match, v verdict) string {
	e := primary.Entry
	trust := v.trust
	if e == nil {
		return "No action is required: the certificate is not on the blocklist; it is reported because its subject names eMudhra/emSign."
	}
	if primary.Kind == blocklist.MatchIssuedBy {
		switch {
		case trust.State == TrustDistrusted:
			return "No action needed: the certificate is explicitly distrusted here."
		case e.Category == blocklist.CategoryCompromisedKey:
			return "This certificate was issued by a CA with a leaked key: anyone can forge an equivalent certificate. Replace it with one from a different CA."
		case e.Category == blocklist.CategoryRelated:
			return "No action is required: the certificate chains to an eMudhra root that is not known to be compromised."
		}
		return "This certificate chains to a distrusted root: obtain a replacement from a CA that is still trusted."
	}
	if e.Category == blocklist.CategoryRelated {
		return "No action is required for this certificate: it is an eMudhra root that is not known to be compromised."
	}
	st := ss.final
	switch trust.State {
	case TrustDistrusted:
		if c.info.Kind == certs.KindSPKI && isExecutableClass(st.Class) {
			return "No action needed: the bare key is part of the program's SPKI blocklist, which rejects certificates issued under the compromised keys."
		}
		return "No action needed: the certificate is explicitly distrusted here; keep it that way."
	case TrustDisabled:
		return "No action needed: the source file is deselected; the certificate is not part of the generated bundle."
	}
	var parts []string
	if v.action != "" {
		parts = append(parts, v.action)
	}
	switch {
	case isSystemStore(st):
		if st.Remediation != "" {
			parts = append(parts, st.Remediation)
		}
		parts = append(parts, stores.SystemRemediation(w.os, w.facts))
	default:
		if rt, ok := w.runtimeVersion(st); ok && !rt.outdated && e.Category != blocklist.CategoryCompromisedKey {
			parts = append(parts, fmt.Sprintf("%s %s is already at a fixed release (first fixed: %s); the remaining listed roots are not compromised.", runtimeName(st), rt.version, rt.fixed))
			break
		}
		if st.Remediation != "" {
			parts = append(parts, st.Remediation)
		}
		if fix, ok := stores.FixForStore(st); ok {
			parts = appendFix(parts, st, fix)
		}
	}
	return strings.Join(parts, " ")
}

// appendFix adds the ecosystem fix unless the store's own sentence already
// names the fixed version.
func appendFix(parts []string, st stores.Store, fix stores.Fix) []string {
	if fix.FixedVersion == "" {
		if fix.Note != "" {
			return append(parts, fmt.Sprintf("%s: %s (%s).", fix.Component, fix.Note, fix.Reference))
		}
		return parts
	}
	if strings.Contains(st.Remediation, fix.FixedVersion) {
		return parts
	}
	s := fmt.Sprintf("Fixed in %s %s (%s).", fix.Component, fix.FixedVersion, fix.Reference)
	if fix.Note != "" {
		s += " Note: " + fix.Note + "."
	}
	return append(parts, s)
}
