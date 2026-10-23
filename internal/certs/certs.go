// Package certs finds X.509 certificates (and bare public keys) inside
// arbitrary file contents.
//
// It understands the containers in which CA trust material ships inside
// container images:
//
//   - PEM: CERTIFICATE, X509 CERTIFICATE, TRUSTED CERTIFICATE (OpenSSL format
//     with a CertAux trust trailer), PKCS7 bundles and PUBLIC KEY blocks,
//     including blocks that are indented (YAML, Helm values, source code) or
//     JSON-escaped.
//   - Raw DER certificates, whether a file is one certificate or the
//     certificate is embedded somewhere inside a larger blob (shared objects
//     such as libnssckbi.so, Chromium/Electron binaries, NSS cert8.db/cert9.db
//     databases, PKCS#7 .p7b/.p7c bundles). Carving looks for the byte shape of
//     an X.509 certificate and validates each candidate by parsing it.
//   - Java keystores (JKS/JCEKS) and PKCS#12 files (via package keystore).
//   - Mozilla certdata.txt (NSS source format with CKA_VALUE MULTILINE_OCTAL
//     blocks and CKA_TRUST_* flags).
//   - p11-kit trust files ([p11-kit-object-v1] sections with PEM payloads,
//     "trusted"/"x-distrusted" attributes and extended-key-usage extension
//     objects).
//   - Bare SubjectPublicKeyInfo byte patterns, which is how Rust binaries built
//     with webpki-roots embed their root store (no certificate, only the
//     subject and the public key).
//
// Containers that record trust do so per purpose (TLS server, TLS client,
// code signing, e-mail); Found keeps that information so that a certificate
// trusted only for e-mail is not taken for a TLS anchor.
//
// Scan is streaming: a file of any size is read in chunks with an overlap large
// enough to hold a certificate, so memory stays bounded; an object longer than
// the overlap is completed by growing the window, up to Options.MaxBuffer (8
// MiB for a PEM block). Only the keystore and text formats that need the whole
// file are buffered, and only up to Options.MaxBuffer.
package certs

import (
	"bytes"
	"crypto/x509"
	"io"
	"strings"
)

// Kind describes the container in which an object was found.
type Kind string

const (
	KindPEM        Kind = "pem"         // PEM CERTIFICATE / X509 CERTIFICATE
	KindPEMTrusted Kind = "pem-trusted" // OpenSSL TRUSTED CERTIFICATE with CertAux
	KindPKCS7      Kind = "pkcs7"       // PEM PKCS7 block or DER .p7b/.p7c bundle
	KindDER        Kind = "der"         // DER certificate, standalone or embedded in a blob
	KindJKS        Kind = "jks"         // Java keystore (JKS/JCEKS)
	KindPKCS12     Kind = "pkcs12"      // PKCS#12 / PFX
	KindCertdata   Kind = "certdata"    // Mozilla certdata.txt
	KindP11Kit     Kind = "p11-kit"     // p11-kit trust file
	KindSPKI       Kind = "spki"        // bare public key pattern match (no certificate)
)

// TrustState is trust information carried by the container format itself.
type TrustState int

const (
	// TrustUnknown: the format carries no trust flags (plain PEM/DER, keystores).
	TrustUnknown TrustState = iota
	// TrustAnchor: explicitly marked as a trust anchor for at least one
	// purpose (certdata CKT_NSS_TRUSTED_DELEGATOR, p11-kit "trusted: true",
	// CertAux trust OIDs).
	TrustAnchor
	// TrustDistrusted: explicitly distrusted as a whole (certdata
	// CKT_NSS_NOT_TRUSTED for every purpose, p11-kit "x-distrusted: true",
	// CertAux rejecting anyExtendedKeyUsage or every standard purpose).
	TrustDistrusted
	// TrustNeutral: present but neither an anchor nor distrusted (certdata
	// CKT_NSS_MUST_VERIFY_TRUST, p11-kit "trusted: false" without distrust,
	// a CertAux reject list for some purposes only).
	TrustNeutral
)

func (t TrustState) String() string {
	switch t {
	case TrustAnchor:
		return "anchor"
	case TrustDistrusted:
		return "distrusted"
	case TrustNeutral:
		return "neutral"
	default:
		return "unknown"
	}
}

// Purpose is an extended key usage that a trust store grants or withholds
// trust for separately. OpenSSL's trust and reject lists, Mozilla's
// CKA_TRUST_* attributes and p11-kit's extension objects all speak in these
// terms.
type Purpose string

const (
	// PurposeServerAuth is TLS server authentication (1.3.6.1.5.5.7.3.1).
	PurposeServerAuth Purpose = "serverAuth"
	// PurposeClientAuth is TLS client authentication (1.3.6.1.5.5.7.3.2).
	PurposeClientAuth Purpose = "clientAuth"
	// PurposeCodeSigning is code signing (1.3.6.1.5.5.7.3.3).
	PurposeCodeSigning Purpose = "codeSigning"
	// PurposeEmailProtection is S/MIME e-mail protection (1.3.6.1.5.5.7.3.4).
	PurposeEmailProtection Purpose = "emailProtection"
)

// standardPurposes lists the purposes Found.Purposes is keyed by, in the
// order messages print them.
var standardPurposes = []Purpose{PurposeServerAuth, PurposeClientAuth, PurposeCodeSigning, PurposeEmailProtection}

// purposeOIDs maps the extended-key-usage OIDs to the standard purposes.
var purposeOIDs = map[string]Purpose{
	"1.3.6.1.5.5.7.3.1": PurposeServerAuth,
	"1.3.6.1.5.5.7.3.2": PurposeClientAuth,
	"1.3.6.1.5.5.7.3.3": PurposeCodeSigning,
	"1.3.6.1.5.5.7.3.4": PurposeEmailProtection,
}

// Found is one certificate or public key located in the scanned data.
type Found struct {
	// Certificate is nil for KindSPKI.
	Certificate *x509.Certificate
	// Raw is the DER certificate (or, for KindSPKI, the bytes that matched).
	Raw []byte
	// Kind is the container the object was found in.
	Kind Kind
	// Offset is the byte offset of the object within the scanned file. For
	// objects inside decoded containers (PEM, keystores, certdata) it is the
	// offset of the enclosing block or entry.
	Offset int64
	// Label is the PEM header label, keystore alias, p11-kit/certdata label or
	// CertAux alias; empty when the container has none.
	Label string
	// Trust is the container's overall verdict: TrustAnchor when the
	// certificate is an anchor for at least one purpose, TrustDistrusted when
	// the container distrusts it as a whole, TrustNeutral when it is neither
	// (including "trusted for nothing relevant"), TrustUnknown when the
	// container carries no trust information.
	Trust TrustState
	// TrustDetail explains Trust in the container's own terms, for example
	// "CKA_TRUST_SERVER_AUTH=CKT_NSS_NOT_TRUSTED, CKA_TRUST_EMAIL_PROTECTION=CKT_NSS_TRUSTED_DELEGATOR",
	// "trust: codeSigning, emailProtection" or "x-distrusted: true".
	TrustDetail string
	// Purposes is the trust the container records per purpose, keyed by the
	// four standard purposes (a purpose missing from the map is neutral). It
	// is nil when the container carries no purpose information: plain PEM,
	// DER, JKS and PKCS#12. TrustFor resolves it for the purposes a caller
	// cares about.
	Purposes map[Purpose]TrustState
	// PatternID identifies which Options.SPKIPatterns entry matched (KindSPKI only).
	PatternID string
	// Note carries parser remarks such as "pkcs12 opened with password \"changeit\"".
	Note string
}

// TrustFor resolves the container's trust for the given purposes:
// TrustAnchor when any of them is an anchor, TrustDistrusted when the
// container distrusts the certificate as a whole or every given purpose,
// TrustNeutral otherwise. The string explains the outcome in store terms,
// such as "trusted for emailProtection only" or "rejected for serverAuth,
// codeSigning". Without purpose information (Purposes nil, or no purpose
// asked for) it returns Trust and TrustDetail unchanged.
func (f *Found) TrustFor(purposes ...Purpose) (TrustState, string) {
	if f.Purposes == nil || len(purposes) == 0 {
		return f.Trust, f.TrustDetail
	}
	anchor, allRejected := false, true
	for _, p := range purposes {
		switch f.Purposes[p] {
		case TrustAnchor:
			anchor = true
		case TrustDistrusted:
		default:
			allRejected = false
		}
	}
	anchors, rejected := f.purposesIn(TrustAnchor), f.purposesIn(TrustDistrusted)
	switch {
	case anchor:
		return TrustAnchor, "trusted for " + joinPurposes(anchors)
	case f.Trust == TrustDistrusted:
		return TrustDistrusted, "rejected for every purpose"
	case allRejected:
		return TrustDistrusted, "rejected for " + joinPurposes(rejected)
	}
	var parts []string
	if len(anchors) > 0 {
		parts = append(parts, "trusted for "+joinPurposes(anchors)+" only")
	} else {
		parts = append(parts, "not trusted for "+joinPurposes(purposes))
	}
	if len(rejected) > 0 {
		parts = append(parts, "rejected for "+joinPurposes(rejected))
	}
	return TrustNeutral, strings.Join(parts, "; ")
}

// purposesIn lists the standard purposes recorded with the given state.
func (f *Found) purposesIn(state TrustState) []Purpose {
	var out []Purpose
	for _, p := range standardPurposes {
		if f.Purposes[p] == state {
			out = append(out, p)
		}
	}
	return out
}

func joinPurposes(purposes []Purpose) string {
	names := make([]string, 0, len(purposes))
	for _, p := range purposes {
		names = append(names, string(p))
	}
	return strings.Join(names, ", ")
}

// summariseTrust reduces per-purpose trust to the overall verdict: anchor
// when any purpose is an anchor, distrusted when the container distrusts the
// certificate as a whole (wholeDistrust), neutral otherwise. A certificate
// trusted for nothing relevant (an explicit trust list naming none of the
// standard purposes) is neutral, not distrusted.
func summariseTrust(purposes map[Purpose]TrustState, wholeDistrust bool) TrustState {
	for _, p := range standardPurposes {
		if purposes[p] == TrustAnchor {
			return TrustAnchor
		}
	}
	if wholeDistrust {
		return TrustDistrusted
	}
	return TrustNeutral
}

// uniformPurposes records the same state for every standard purpose.
func uniformPurposes(state TrustState) map[Purpose]TrustState {
	out := make(map[Purpose]TrustState, len(standardPurposes))
	for _, p := range standardPurposes {
		out[p] = state
	}
	return out
}

// SPKIPattern is a byte pattern to look for in every scanned file. ID is
// returned in Found.PatternID when Pattern occurs in the data.
type SPKIPattern struct {
	ID      string
	Pattern []byte
}

// DefaultMaxBuffer bounds whole-file parsers (keystores, certdata, p11-kit)
// and the growth of a scan window around an oversized object.
const DefaultMaxBuffer int64 = 64 << 20

// DefaultPasswords are tried, in order, on PKCS#12 files.
var DefaultPasswords = []string{"", "changeit", "changeme", "password"}

// Options tunes Scan.
type Options struct {
	// SPKIPatterns are searched for in every file. Matches that fall inside a
	// certificate that was itself found are suppressed (the key is reported
	// once, as the certificate).
	SPKIPatterns []SPKIPattern
	// MaxBuffer bounds the whole-file parsers and the growth of a scan window
	// around an object longer than the window overlap (a PEM block grows it
	// by at most 8 MiB, whatever MaxBuffer is); 0 means DefaultMaxBuffer. A
	// keystore larger than this is only carved for DER certificates.
	MaxBuffer int64
	// KeystorePasswords are tried on PKCS#12 files; nil means DefaultPasswords.
	KeystorePasswords []string
	// Warn, when set, receives remarks about content that could not be fully
	// decoded (a PEM block the strict parser rejects, a keystore no password
	// opened, a file too large for its whole-file parser). Scan never fails
	// for such content.
	Warn func(msg string)
}

// Scan reads the contents of the file named path from r and returns every
// certificate and public-key pattern it finds. size is the file size when
// known, or -1. path is only used as a hint (for example a file called cacerts
// or *.jks is tried as a keystore first); detection is driven by content.
//
// Malformed or unrecognised content is never an error: Scan returns what it
// could decode. An error is returned only when reading from r fails.
func Scan(r io.Reader, path string, size int64, opts Options) ([]Found, error) {
	s := &scanner{path: path, opts: opts, patterns: newPatternSet(opts.SPKIPatterns)}
	return s.run(r, size)
}

// ScanBytes is Scan over in-memory data.
func ScanBytes(data []byte, path string, opts Options) []Found {
	found, _ := Scan(bytes.NewReader(data), path, int64(len(data)), opts)
	return found
}
