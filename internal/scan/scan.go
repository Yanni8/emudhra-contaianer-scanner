// Package scan walks a container image's root filesystem once and reports
// every certificate that is affected by the October 2026 eMudhra compromise,
// in every trust store the image carries: system CA bundles and their source
// directories, Java keystores, language-runtime bundles such as Python
// certifi, NSS databases, p11-kit trust sources and the root stores compiled
// into runtime binaries (Node.js, Deno, Chromium, Rust webpki-roots users).
//
// The walk is sequential and streaming: a tar entry is never held in memory
// as a whole except for the small configuration files and package databases
// that decide trust and versions (/etc/ca-certificates.conf, os-release,
// dpkg/apk/rpm databases). For every certificate the engine records the
// trust store it sits in (classified by its path and by every link name that
// reaches it), whether the image actually trusts it and for which purposes
// (a Debian source file may be deselected, a p11-kit object may be marked
// distrusted or limited to e-mail, a file may live in a blocklist directory,
// a bare public key inside a fixed runtime may be its SPKI blocklist) and
// the resulting severity.
package scan

import (
	"context"
	"io"
	"time"

	"emudhra-container-scanner/internal/blocklist"
	"emudhra-container-scanner/internal/certs"
	"emudhra-container-scanner/internal/image"
	"emudhra-container-scanner/internal/stores"
)

// Name is the scanner name written into results.
const Name = "emudhra-container-scanner"

// Version is the scanner version written into results when Options.Version
// is empty; the main package may override it from build information.
var Version = "dev"

// Options configures a scan.
type Options struct {
	// Blocklist is the list to match against; nil means blocklist.Default().
	Blocklist *blocklist.List
	// Progress, when set, receives one-line status messages.
	Progress func(string)
	// IncludeOperatorHeuristic reports certificates whose subject names
	// eMudhra/emSign without being on the list, at info severity.
	IncludeOperatorHeuristic bool
	// KeystorePasswords are tried on PKCS#12 files; nil means certs.DefaultPasswords.
	KeystorePasswords []string
	// MaxBuffer bounds whole-file parsers (keystores, certdata, p11-kit);
	// 0 means certs.DefaultMaxBuffer.
	MaxBuffer int64
	// Env is the image environment ("KEY=value") used for trust hints and
	// runtime versions (DENO_VERSION, GOLANG_VERSION, ...). Image fills it
	// from the image configuration when nil; Tar takes it as given.
	Env []string
	// Version is the scanner version written into Result.Scanner; when empty
	// the package-level Version is used.
	Version string
}

// Trust states of a finding.
const (
	// TrustTrusted: the store trusts the certificate as an anchor, for every
	// purpose or for the purposes listed in TrustInfo.Purposes.
	TrustTrusted = "trusted"
	// TrustDistrusted: the certificate is explicitly distrusted (blocklist
	// directory, p11-kit blocklist cross-reference, x-distrusted object,
	// CertAux reject, certdata NOT_TRUSTED, the SPKI blocklist of a fixed
	// runtime).
	TrustDistrusted = "distrusted"
	// TrustDisabled: a Debian-style source file deselected in /etc/ca-certificates.conf.
	TrustDisabled = "disabled"
	// TrustEmbedded: compiled into a runtime or into another executable as a
	// trust-anchor table (trusted by the program), or embedded as a full
	// certificate in an unknown executable (use unknown).
	TrustEmbedded = "embedded"
	// TrustUnknown: loose files, keystores of unknown purpose, NSS databases
	// (trust flags not parsed), source files without configuration.
	TrustUnknown = "unknown"
)

// Result is the outcome of a scan.
type Result struct {
	Scanner  Scanner          `json:"scanner"`
	Image    ImageInfo        `json:"image"`
	OS       stores.OSInfo    `json:"os"`
	Packages []PackageStatus  `json:"packages"`
	EnvHints []stores.EnvHint `json:"env_hints"`
	Stores   []StoreSummary   `json:"stores"`
	Findings []Finding        `json:"findings"`
	Summary  Summary          `json:"summary"`
	Warnings []string         `json:"warnings"`
	// Exit records the failure threshold and the exit decision of the
	// command line. The scan leaves it empty (and the JSON omits it); main
	// fills it before writing the report.
	Exit Exit `json:"exit,omitzero"`
}

// Exit is the exit decision of the command line for a result.
type Exit struct {
	// FailOn is the --fail-on threshold as given ("high", "never", ...).
	FailOn string `json:"fail_on"`
	// Code is the process exit code: 0 clean, 2 findings at or above FailOn.
	Code int `json:"code"`
	// ExtraBlocklists lists the --blocklist files merged into the built-in list.
	ExtraBlocklists []string `json:"extra_blocklists,omitempty"`
}

// Scanner identifies the scanner and its data.
type Scanner struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	BlocklistVersion string `json:"blocklist_version"`
}

// ImageInfo describes the scanned image.
type ImageInfo struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
	Platform  string `json:"platform"`
	Layers    int    `json:"layers"`
	// CompressedSize is the sum of the compressed layer sizes, or -1 when
	// the source does not report them.
	CompressedSize int64 `json:"compressed_size"`
}

// PackageStatus is a trust-relevant package or runtime found in the image,
// compared with the version that fixed the incident when one is known.
type PackageStatus struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Manager says where the version comes from: "dpkg", "apk" or "rpm" for
	// package databases, "pip" for Python dist-info directories and pip's
	// vendor list, "jdk" or "jre" for a Java release file, "node", "deno",
	// "bun" and "uv" for runtime version headers, binaries or environment
	// variables, "go" for the toolchain's VERSION file or GOLANG_VERSION.
	Manager string `json:"manager"`
	// FixedVersion is the first fixed version of the matching release line.
	// It is empty when no fix data applies to the package, and also when the
	// release line has no fixed release at all (Note then says so).
	FixedVersion string `json:"fixed_version,omitempty"`
	// Outdated is nil when no comparison could be made (no fix data for the
	// package or distribution), true when the version is below FixedVersion
	// or the release line has no fixed release (end-of-life Node.js lines,
	// Java 8), false when the version is at or above the fix.
	Outdated *bool `json:"outdated"`
	// Reference is the advisory or release post for the fix.
	Reference string `json:"reference,omitempty"`
	// Note qualifies the verdict: an unconfirmed release, an end-of-life
	// line and where to move to, a pending distribution fix.
	Note string `json:"note,omitempty"`
	// Path is where the version was read from when it is not a package
	// database: a file or directory, or an environment variable such as
	// "DENO_VERSION (image environment)".
	Path string `json:"path,omitempty"`
}

// StoreSummary is one file that holds certificates (or a store class that is
// listed even when empty: system bundles, keystores, NSS databases).
type StoreSummary struct {
	// Path is the real path of the file; Aliases are the link names that
	// reach it, including names below directory symlinks.
	Path string `json:"path"`
	// Class, Name and Ecosystem describe the strongest classification of
	// the path and its aliases (ClassifiedBy names the alias when the real
	// path alone would have given a weaker one).
	Class        stores.Class `json:"class"`
	Name         string       `json:"name"`
	Ecosystem    string       `json:"ecosystem"`
	ClassifiedBy string       `json:"classified_by,omitempty"`
	Aliases      []string     `json:"aliases,omitempty"`
	// Certificates counts the distinct certificates (by SHA-256) in the
	// file; Duplicates counts the further copies of those certificates in
	// the same file (a bundle built by concatenation often repeats roots).
	Certificates int `json:"certificates"`
	Duplicates   int `json:"duplicates,omitempty"`
	Findings     int `json:"findings"`
}

// Finding is one affected certificate (or bare public key) in one store. A
// certificate that appears several times in one file is reported once, at
// its first offset.
type Finding struct {
	Severity blocklist.Severity `json:"severity"`
	// Category is the matched entry's category, or blocklist.CategoryIssuedBy
	// for a certificate that was issued by a listed CA without being listed
	// itself.
	Category blocklist.Category  `json:"category"`
	Match    blocklist.MatchKind `json:"match"`
	// EntryID is the blocklist entry that matched. EntryName is its name,
	// except for issued-by findings, where it is the found certificate's own
	// common name and the issuing entry is recorded in IssuerEntryID and
	// IssuerEntryName.
	EntryID         string       `json:"entry_id"`
	EntryName       string       `json:"entry_name"`
	IssuerEntryID   string       `json:"issuer_entry_id,omitempty"`
	IssuerEntryName string       `json:"issuer_entry_name,omitempty"`
	Path            string       `json:"path"`
	Aliases         []string     `json:"aliases,omitempty"`
	Store           stores.Store `json:"store"`
	Certificate     CertInfo     `json:"certificate"`
	Trust           TrustInfo    `json:"trust"`
	Explanation     string       `json:"explanation"`
	Remediation     string       `json:"remediation"`
	References      []string     `json:"references,omitempty"`
}

// CertInfo summarises the certificate of a finding. For a bare public-key
// match (Kind certs.KindSPKI) Subject, Issuer and Serial come from the
// listed certificate that carries the key, SHA256 is empty and the validity
// is absent.
type CertInfo struct {
	Subject    string     `json:"subject"`
	Issuer     string     `json:"issuer,omitempty"`
	Serial     string     `json:"serial,omitempty"`
	SHA256     string     `json:"sha256,omitempty"`
	SPKISHA256 string     `json:"spki_sha256,omitempty"`
	NotBefore  time.Time  `json:"not_before,omitzero"`
	NotAfter   time.Time  `json:"not_after,omitzero"`
	Label      string     `json:"label,omitempty"`
	Kind       certs.Kind `json:"kind"`
	Offset     int64      `json:"offset"`
}

// TrustInfo records whether the image trusts the finding's certificate.
type TrustInfo struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	// Purposes lists the extended key usages (serverAuth, clientAuth,
	// codeSigning, emailProtection) the store trusts the certificate for,
	// when the store records trust per purpose (OpenSSL TRUSTED CERTIFICATE
	// attributes, certdata CKA_TRUST_*, p11-kit objects, the extracted
	// S/MIME and code-signing bundles). It is absent when the store carries
	// no purpose information and trust applies to every purpose.
	Purposes []string `json:"purposes,omitempty"`
}

// Summary carries the counters of a scan.
type Summary struct {
	FilesScanned int   `json:"files_scanned"`
	BytesScanned int64 `json:"bytes_scanned"`
	// CertificatesFound counts certificate blocks: every occurrence, so a
	// certificate that appears twice in one file counts twice (the store
	// summaries count distinct certificates).
	CertificatesFound int `json:"certificates_found"`
	// AffectedCertificates is the number of distinct certificates among the
	// findings (by SHA-256, or by public key for bare-key matches): a
	// certificate that sits in several files counts once.
	AffectedCertificates int `json:"affected_certificates"`
	// FindingsBySeverity always carries the five severity names as keys.
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	// MaxSeverity is the highest severity among the findings, or empty (and
	// omitted from the JSON) when there are none.
	MaxSeverity string `json:"max_severity,omitempty"`
	// SystemBundleFound is true when a system CA bundle holding at least
	// one certificate was found; otherwise programs in the image cannot
	// verify TLS peers unless they bring their own trust store.
	SystemBundleFound bool `json:"system_bundle_found"`
	// PackageDatabase names the package databases that were read ("dpkg",
	// "dpkg (status.d)", "apk", "rpm (sqlite)", "rpm (ndb)", "rpm (bdb)",
	// "rpm (<format>, not parsed: <reason>)", several joined with ", ") or
	// "none", so that an empty package list can be told from a database
	// that was not read.
	PackageDatabase string `json:"package_database"`
	DurationMS      int64  `json:"duration_ms"`
}

// MaxSeverity returns the highest severity among the findings, or
// blocklist.SeverityInfo when there are none; use len(r.Findings) to tell
// the two apart.
func (r *Result) MaxSeverity() blocklist.Severity {
	maxSev := blocklist.SeverityInfo
	for _, f := range r.Findings {
		if f.Severity > maxSev {
			maxSev = f.Severity
		}
	}
	return maxSev
}

// Image opens the image's flattened filesystem and scans it. Result.Image is
// filled from the image and the environment hints from its configuration.
func Image(ctx context.Context, im *image.Image, opts Options) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Env == nil {
		opts.Env = im.Env()
	}
	rc, err := im.Filesystem()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	res, err := Tar(ctx, rc, opts)
	if err != nil {
		return nil, err
	}
	res.Image = ImageInfo{
		Reference:      im.Reference,
		Digest:         im.Digest,
		Platform:       im.Platform,
		Layers:         im.Layers,
		CompressedSize: im.CompressedSize,
	}
	return res, nil
}

// Tar scans a flattened root filesystem tar stream. The stream is read once,
// sequentially; the scan stops with an error only when the stream cannot be
// read or ctx is cancelled. Malformed files are reported as warnings.
func Tar(ctx context.Context, r io.Reader, opts Options) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	w := newWalker(ctx, opts)
	if err := w.walk(r); err != nil {
		return nil, err
	}
	return w.finish(), nil
}
