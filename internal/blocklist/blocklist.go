// Package blocklist carries the set of CA certificates affected by the October 2026
// eMudhra key compromise and knows how to match certificates found in a container
// image against it.
//
// The embedded data set (data/entries.json) has three categories of entries:
//
//   - compromised-key: the eight eMudhra intermediate CAs (six TLS, two code
//     signing) whose P-384 private keys are trivially recoverable, plus the eight
//     Sectigo cross-certificates that carry the same keys. Matching happens by
//     certificate fingerprint and, more importantly, by public key (SPKI), which is
//     how Go, Node.js and Chrome block them.
//   - anchor: the roots that make those intermediates chain to something trusted:
//     "emSign ECC Root CA - G3", Sectigo's "AAA Certificate Services" (NSS label
//     "Comodo AAA Services root") and the two self-signed sub-roots that issued
//     the intermediates directly. Root programs and Linux distributions removed or
//     blocklisted these in October 2026.
//   - related: other eMudhra-operated roots that are not known to be compromised.
//     They are reported at low severity for situational awareness only.
//
// Every fact in the data set was recomputed from the actual certificates with
// OpenSSL while the list was generated; the test suite re-verifies fingerprints
// and public-key hashes against the certificates at test time and against the
// SPKI hashes hard-coded in Go's own crypto/x509 mitigation (golang/go#82345).
package blocklist

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed data/entries.json
var embeddedJSON []byte

// Category classifies why a certificate is on the list.
type Category string

const (
	// CategoryCompromisedKey marks a certificate whose private key is public knowledge.
	CategoryCompromisedKey Category = "compromised-key"
	// CategoryAnchor marks a CA that directly validates (issued or cross-signed) a
	// compromised-key certificate. Trusting it means trusting the leaked keys.
	CategoryAnchor Category = "anchor"
	// CategoryRelated marks other CA certificates operated by eMudhra that are not
	// known to be compromised.
	CategoryRelated Category = "related"
	// CategoryCustom marks entries supplied by the user through Load.
	CategoryCustom Category = "custom"
	// CategoryIssuedBy is a finding category, not an entry category: it marks
	// a certificate that is not on the list itself but was issued by a listed
	// CA (MatchIssuedBy). Entries with this category are rejected by Load.
	CategoryIssuedBy Category = "issued-by"
)

// Severity ranks findings. Higher is worse.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// ParseSeverity accepts the names printed by String (case-insensitive).
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if strings.EqualFold(name, s) {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of info, low, medium, high, critical)", s)
}

// MarshalText implements encoding.TextMarshaler so Severity serialises as its name.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Entry is one certificate (or, for entries without PEM, one fingerprint) on the list.
type Entry struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Category      Category  `json:"category"`
	Severity      Severity  `json:"severity"`
	Operator      string    `json:"operator,omitempty"`
	Usage         string    `json:"usage,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	Serial        string    `json:"serial,omitempty"`
	SHA256        string    `json:"sha256"`                // lowercase hex of the DER certificate
	SPKISHA256    string    `json:"spki_sha256,omitempty"` // lowercase hex of the DER SubjectPublicKeyInfo
	SKI           string    `json:"ski,omitempty"`
	AKI           string    `json:"aki,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	CrossSignedBy string    `json:"cross_signed_by,omitempty"`
	RevokedAt     string    `json:"revoked_at,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	Remediation   string    `json:"remediation,omitempty"`
	References    []string  `json:"references,omitempty"`
	PEM           string    `json:"pem,omitempty"`

	// Certificate is the parsed certificate when PEM is present, nil otherwise.
	Certificate *x509.Certificate `json:"-"`
}

// Compromised reports whether the entry's private key is known to be public.
func (e *Entry) Compromised() bool { return e.Category == CategoryCompromisedKey }

// MatchKind describes how strongly a certificate relates to an entry.
type MatchKind string

const (
	// MatchFingerprint: byte-for-byte the listed certificate.
	MatchFingerprint MatchKind = "fingerprint"
	// MatchSPKI: a different certificate carrying the listed public key (for
	// example a cross-signed or re-issued variant).
	MatchSPKI MatchKind = "spki"
	// MatchIssuedBy: a certificate issued by a listed CA (signature verified when
	// the issuer certificate is available).
	MatchIssuedBy MatchKind = "issued-by"
	// MatchOperator: heuristic; the subject names eMudhra/emSign but the
	// certificate is not on the list.
	MatchOperator MatchKind = "operator"
)

// Match is the result of comparing one certificate with the list.
type Match struct {
	Entry *Entry // nil for MatchOperator
	Kind  MatchKind
}

// SPKIPattern is a byte pattern that identifies a listed public key inside
// arbitrary data. Pattern is the DER SubjectPublicKeyInfo *without* its outer
// SEQUENCE tag and length, so that it also matches the trust-anchor tables
// embedded in Rust binaries (webpki-roots stores exactly that inner value) as
// well as full SPKI and full certificate encodings.
type SPKIPattern struct {
	Entry   *Entry
	Pattern []byte
}

// List is an immutable, indexed collection of entries.
type List struct {
	Version    string
	Incident   string
	References []string

	entries   []*Entry
	byFP      map[string]*Entry
	bySPKI    map[string][]*Entry
	bySKI     map[string][]*Entry
	bySubject map[string][]*Entry // key: hex of raw subject DER
	byDN      map[string][]*Entry // key: normalised subject string (fallback for entries without PEM)
}

type fileDocument struct {
	Version    string   `json:"version"`
	Incident   string   `json:"incident"`
	References []string `json:"references"`
	Entries    []*Entry `json:"entries"`
}

var (
	defaultOnce sync.Once
	defaultList *List
	defaultErr  error
)

// Default returns the embedded list. The data is validated by the package tests,
// so a parse failure here is a build defect and panics.
func Default() *List {
	defaultOnce.Do(func() {
		defaultList, defaultErr = parseJSON(bytes.NewReader(embeddedJSON))
	})
	if defaultErr != nil {
		panic("blocklist: embedded data is invalid: " + defaultErr.Error())
	}
	return defaultList
}

// Load reads a user-supplied list. Two formats are accepted:
//
//   - JSON with the same schema as the embedded data/entries.json (entries with
//     a "pem" field have their fingerprints recomputed and verified; entries
//     without PEM must carry "sha256").
//   - A PEM file. Every CERTIFICATE block becomes an entry of CategoryCustom with
//     SeverityHigh, named after its subject common name.
func Load(r io.Reader) (*List, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("blocklist: empty input")
	}
	if trimmed[0] == '{' {
		return parseJSON(bytes.NewReader(trimmed))
	}
	if bytes.Contains(trimmed, []byte("-----BEGIN ")) {
		return parsePEM(trimmed)
	}
	return nil, errors.New("blocklist: input is neither JSON nor PEM")
}

// Merge returns a new list containing the entries of l followed by those of
// others. Entries with an ID that is already present are skipped.
func (l *List) Merge(others ...*List) *List {
	out := &List{Version: l.Version, Incident: l.Incident, References: append([]string(nil), l.References...)}
	seen := map[string]bool{}
	var all []*Entry
	for _, src := range append([]*List{l}, others...) {
		if src == nil {
			continue
		}
		for _, e := range src.entries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			all = append(all, e)
		}
	}
	out.entries = all
	out.index()
	return out
}

// Entries returns the entries in list order (compromised keys first, then
// anchors, then related certificates).
func (l *List) Entries() []*Entry { return append([]*Entry(nil), l.entries...) }

// ByID looks an entry up by its identifier.
func (l *List) ByID(id string) *Entry {
	for _, e := range l.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// ByFingerprint looks an entry up by certificate SHA-256 (hex, any case, with or
// without colons).
func (l *List) ByFingerprint(hexFP string) *Entry {
	return l.byFP[normaliseHex(hexFP)]
}

// MatchSPKIHash returns the entries whose public key has the given SHA-256,
// eMudhra-issued entries before cross-signed ones.
func (l *List) MatchSPKIHash(sum [32]byte) []*Entry {
	return append([]*Entry(nil), l.bySPKI[hex.EncodeToString(sum[:])]...)
}

// CompromisedSPKIHashes returns the SHA-256 hashes of every public key that is
// known to be compromised. This is the same set Go's crypto/x509 rejects.
func (l *List) CompromisedSPKIHashes() [][32]byte {
	seen := map[string]bool{}
	var out [][32]byte
	for _, e := range l.entries {
		if !e.Compromised() || e.SPKISHA256 == "" || seen[e.SPKISHA256] {
			continue
		}
		seen[e.SPKISHA256] = true
		var sum [32]byte
		b, err := hex.DecodeString(e.SPKISHA256)
		if err != nil || len(b) != 32 {
			continue
		}
		copy(sum[:], b)
		out = append(out, sum)
	}
	return out
}

// SPKIPatterns returns one pattern per distinct listed public key. Entries that
// share a key (eMudhra-issued and Sectigo cross-signed variants) are collapsed
// onto the first entry in list order.
func (l *List) SPKIPatterns() []SPKIPattern {
	seen := map[string]bool{}
	var out []SPKIPattern
	for _, e := range l.entries {
		if e.Certificate == nil || seen[e.SPKISHA256] {
			continue
		}
		inner, ok := derContents(e.Certificate.RawSubjectPublicKeyInfo)
		if !ok || len(inner) < 16 {
			continue
		}
		seen[e.SPKISHA256] = true
		out = append(out, SPKIPattern{Entry: e, Pattern: inner})
	}
	return out
}

// MatchCertificate compares c with the list and returns every applicable
// relation, strongest first. The operator heuristic is only reported when no
// listed entry matched.
func (l *List) MatchCertificate(c *x509.Certificate) []Match {
	if c == nil {
		return nil
	}
	var out []Match
	fp := sha256.Sum256(c.Raw)
	exact := l.byFP[hex.EncodeToString(fp[:])]
	if exact != nil {
		out = append(out, Match{Entry: exact, Kind: MatchFingerprint})
	}
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	for _, e := range l.bySPKI[hex.EncodeToString(spki[:])] {
		if e == exact {
			continue
		}
		out = append(out, Match{Entry: e, Kind: MatchSPKI})
		break // one representative entry per key is enough
	}
	for _, e := range l.issuersOf(c) {
		if e == exact {
			continue
		}
		out = append(out, Match{Entry: e, Kind: MatchIssuedBy})
	}
	if len(out) == 0 && IsEmudhraSubject(c.Subject) {
		out = append(out, Match{Kind: MatchOperator})
	}
	return out
}

// issuersOf finds listed entries that issued c. Candidates come from the
// authority key identifier (preferred) or the issuer name; when the candidate's
// certificate is available the signature must verify.
func (l *List) issuersOf(c *x509.Certificate) []*Entry {
	var candidates []*Entry
	if len(c.AuthorityKeyId) > 0 {
		candidates = l.bySKI[hex.EncodeToString(c.AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = l.bySubject[hex.EncodeToString(c.RawIssuer)]
	}
	if len(candidates) == 0 {
		candidates = l.byDN[normaliseDN(c.Issuer)]
	}
	var out []*Entry
	seenKey := map[string]bool{}
	for _, e := range candidates {
		if bytes.Equal(c.RawIssuer, c.RawSubject) && e.Certificate != nil && bytes.Equal(e.Certificate.Raw, c.Raw) {
			continue // self-signed listed certificate: not "issued by" itself
		}
		if e.Certificate != nil {
			if err := c.CheckSignatureFrom(e.Certificate); err != nil {
				continue
			}
		}
		// Collapse entries that share a key (the signature verifies under all of them).
		if seenKey[e.SPKISHA256] {
			continue
		}
		seenKey[e.SPKISHA256] = true
		out = append(out, e)
	}
	return out
}

// IsEmudhraSubject reports whether a distinguished name belongs to eMudhra's
// PKI: organisation contains "emudhra", organisational unit is "emSign PKI", or
// the common name starts with "emSign".
func IsEmudhraSubject(n pkix.Name) bool {
	for _, o := range n.Organization {
		if strings.Contains(strings.ToLower(o), "emudhra") {
			return true
		}
	}
	for _, ou := range n.OrganizationalUnit {
		if strings.EqualFold(strings.TrimSpace(ou), "emSign PKI") {
			return true
		}
	}
	cn := strings.TrimSpace(n.CommonName)
	return strings.HasPrefix(strings.ToLower(cn), "emsign ")
}

func parseJSON(r io.Reader) (*List, error) {
	var doc fileDocument
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("blocklist: decoding JSON: %w", err)
	}
	l := &List{Version: doc.Version, Incident: doc.Incident, References: doc.References}
	seen := map[string]bool{}
	for i, e := range doc.Entries {
		if e == nil {
			return nil, fmt.Errorf("blocklist: entry %d is null", i)
		}
		if err := prepareEntry(e); err != nil {
			return nil, fmt.Errorf("blocklist: entry %d (%s): %w", i, e.ID, err)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("blocklist: duplicate entry id %q", e.ID)
		}
		seen[e.ID] = true
		l.entries = append(l.entries, e)
	}
	sortByCategory(l.entries)
	l.index()
	return l, nil
}

func parsePEM(data []byte) (*List, error) {
	l := &List{Version: "custom"}
	rest := data
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" && block.Type != "X509 CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		der := block.Bytes
		if block.Type == "TRUSTED CERTIFICATE" {
			if l, ok := derLength(der); ok && l <= len(der) {
				der = der[:l] // drop the OpenSSL CertAux trailer
			}
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("blocklist: certificate %d in PEM input: %w", n+1, err)
		}
		n++
		fp := sha256.Sum256(cert.Raw)
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}
		e := &Entry{
			ID:       fmt.Sprintf("custom-%s", hex.EncodeToString(fp[:8])),
			Name:     name,
			Category: CategoryCustom,
			Severity: SeverityHigh,
			Notes:    "Supplied through a custom blocklist.",
			PEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		}
		if err := prepareEntry(e); err != nil {
			return nil, err
		}
		l.entries = append(l.entries, e)
	}
	if n == 0 {
		return nil, errors.New("blocklist: no CERTIFICATE blocks in PEM input")
	}
	l.index()
	return l, nil
}

// prepareEntry fills derived fields, parses the PEM and verifies that any
// fingerprints stated in the data agree with the certificate.
func prepareEntry(e *Entry) error {
	if e.ID == "" {
		return errors.New("missing id")
	}
	switch e.Category {
	case CategoryCompromisedKey, CategoryAnchor, CategoryRelated, CategoryCustom:
	case "":
		return errors.New("missing category")
	default:
		return fmt.Errorf("unknown category %q", e.Category)
	}
	if _, ok := severityNames[e.Severity]; !ok {
		return fmt.Errorf("invalid severity %d", int(e.Severity))
	}
	e.SHA256 = normaliseHex(e.SHA256)
	e.SPKISHA256 = normaliseHex(e.SPKISHA256)
	e.SKI = normaliseHex(e.SKI)
	e.AKI = normaliseHex(e.AKI)
	if strings.TrimSpace(e.PEM) == "" {
		if len(e.SHA256) != 64 {
			return errors.New("entries without pem must carry a 64-hex-digit sha256")
		}
		return nil
	}
	block, _ := pem.Decode([]byte(e.PEM))
	if block == nil {
		return errors.New("pem field does not contain a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing pem: %w", err)
	}
	fp := sha256.Sum256(cert.Raw)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if e.SHA256 != "" && e.SHA256 != hex.EncodeToString(fp[:]) {
		return fmt.Errorf("sha256 %s does not match certificate (%x)", e.SHA256, fp)
	}
	if e.SPKISHA256 != "" && e.SPKISHA256 != hex.EncodeToString(spki[:]) {
		return fmt.Errorf("spki_sha256 %s does not match certificate (%x)", e.SPKISHA256, spki)
	}
	e.SHA256 = hex.EncodeToString(fp[:])
	e.SPKISHA256 = hex.EncodeToString(spki[:])
	if e.SKI == "" && len(cert.SubjectKeyId) > 0 {
		e.SKI = hex.EncodeToString(cert.SubjectKeyId)
	}
	if e.AKI == "" && len(cert.AuthorityKeyId) > 0 {
		e.AKI = hex.EncodeToString(cert.AuthorityKeyId)
	}
	if e.Subject == "" {
		e.Subject = cert.Subject.String()
	}
	if e.Issuer == "" {
		e.Issuer = cert.Issuer.String()
	}
	if e.Serial == "" && cert.SerialNumber != nil {
		e.Serial = strings.ToLower(cert.SerialNumber.Text(16))
	}
	if e.NotBefore.IsZero() {
		e.NotBefore = cert.NotBefore
	}
	if e.NotAfter.IsZero() {
		e.NotAfter = cert.NotAfter
	}
	if e.Name == "" {
		e.Name = cert.Subject.CommonName
	}
	e.Certificate = cert
	return nil
}

func (l *List) index() {
	l.byFP = map[string]*Entry{}
	l.bySPKI = map[string][]*Entry{}
	l.bySKI = map[string][]*Entry{}
	l.bySubject = map[string][]*Entry{}
	l.byDN = map[string][]*Entry{}
	for _, e := range l.entries {
		if e.SHA256 != "" {
			l.byFP[e.SHA256] = e
		}
		if e.SPKISHA256 != "" {
			l.bySPKI[e.SPKISHA256] = append(l.bySPKI[e.SPKISHA256], e)
		}
		if e.SKI != "" {
			l.bySKI[e.SKI] = append(l.bySKI[e.SKI], e)
		}
		if e.Certificate != nil {
			k := hex.EncodeToString(e.Certificate.RawSubject)
			l.bySubject[k] = append(l.bySubject[k], e)
			dn := normaliseDN(e.Certificate.Subject)
			l.byDN[dn] = append(l.byDN[dn], e)
		} else if e.Subject != "" {
			l.byDN[normaliseDNString(e.Subject)] = append(l.byDN[normaliseDNString(e.Subject)], e)
		}
	}
}

var categoryOrder = map[Category]int{CategoryCompromisedKey: 0, CategoryAnchor: 1, CategoryCustom: 2, CategoryRelated: 3}

func sortByCategory(entries []*Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ci, cj := categoryOrder[entries[i].Category], categoryOrder[entries[j].Category]
		if ci != cj {
			return ci < cj
		}
		// Within a category keep eMudhra-issued certificates ahead of cross-signed ones.
		xi, xj := entries[i].CrossSignedBy != "", entries[j].CrossSignedBy != ""
		if xi != xj {
			return !xi
		}
		return false
	})
}

func normaliseHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// normaliseDN produces a comparison key for a distinguished name that is
// insensitive to attribute order and case.
func normaliseDN(n pkix.Name) string {
	var parts []string
	for _, atv := range n.ToRDNSequence() {
		for _, a := range atv {
			parts = append(parts, strings.ToLower(fmt.Sprintf("%v=%v", a.Type, a.Value)))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// normaliseDNString handles the RFC 2253 strings stored for entries without PEM
// ("CN=x,O=y,C=z"), mapping attribute names to the OIDs used by normaliseDN.
func normaliseDNString(s string) string {
	oids := map[string]string{"cn": "2.5.4.3", "o": "2.5.4.10", "ou": "2.5.4.11", "c": "2.5.4.6", "st": "2.5.4.8", "l": "2.5.4.7"}
	var parts []string
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if oid, ok := oids[k]; ok {
			k = oid
		}
		parts = append(parts, strings.ToLower(k+"="+strings.TrimSpace(v)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// derLength returns the total length (header included) of the first DER TLV in b.
func derLength(b []byte) (int, bool) {
	if len(b) < 2 {
		return 0, false
	}
	n := int(b[1])
	hdr := 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return 0, false
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(b[2+i])
		}
		hdr = 2 + k
	}
	if n < 0 || hdr+n > len(b) {
		return 0, false
	}
	return hdr + n, true
}

// derContents returns the value bytes of the first DER TLV in b (tag and
// length stripped).
func derContents(b []byte) ([]byte, bool) {
	total, ok := derLength(b)
	if !ok {
		return nil, false
	}
	hdr := 2
	if b[1]&0x80 != 0 {
		hdr = 2 + int(b[1]&0x7f)
	}
	return b[hdr:total], true
}
