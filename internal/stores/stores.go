// Package stores knows where CA trust material lives inside a Linux root
// filesystem and what consumes it.
//
// It classifies paths into trust-store kinds (system bundle, per-CA source
// directory, Java keystore, language-runtime bundle such as Python certifi,
// NSS database, runtime binaries that embed their own root store, ...),
// parses the configuration files that decide whether a certificate in a
// store is actually trusted (Debian's /etc/ca-certificates.conf, p11-kit
// blocklist directories), reads environment hints from the image
// configuration (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, ...), detects the
// operating system and installed package versions, knows the versions that
// fixed the October 2026 eMudhra compromise (one source of truth in
// versions.go) and phrases the OS-specific remediation for the system trust
// store.
package stores

// Class is the kind of trust store a path belongs to.
type Class string

const (
	// ClassSystemBundle is a generated CA bundle consumed by OpenSSL, GnuTLS and
	// most runtimes (/etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt,
	// /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, /etc/ssl/cert.pem,
	// /var/lib/ca-certificates/ca-bundle.pem, ...) or a generated hashed
	// certificate directory (directory-hash, SUSE /var/lib/ca-certificates/pem).
	ClassSystemBundle Class = "system-bundle"
	// ClassSystemSource is a per-CA source file whose trust depends on
	// configuration (/usr/share/ca-certificates/**, /usr/share/pki/ca-trust-source/**).
	ClassSystemSource Class = "system-source"
	// ClassSystemAnchorDir holds locally added anchors that are always trusted
	// (/usr/local/share/ca-certificates/**, /etc/pki/ca-trust/source/anchors/**,
	// /etc/ssl/certs/*.pem individual files, ...).
	ClassSystemAnchorDir Class = "system-anchor-dir"
	// ClassSystemBlocklist holds explicitly distrusted certificates
	// (/etc/pki/ca-trust/source/blocklist/**, /etc/ca-certificates/trust-source/blocklist/**, ...).
	ClassSystemBlocklist Class = "system-blocklist"
	// ClassJavaKeystore is a Java cacerts/JKS/PKCS#12 truststore.
	ClassJavaKeystore Class = "java-keystore"
	// ClassAppBundle is a CA bundle shipped by a library or application
	// (Python certifi, pip's vendored certifi, botocore, Perl Mozilla::CA,
	// PHP composer/ca-bundle, gRPC roots.pem, curl-ca-bundle.crt, Erlang certifi,
	// Homebrew ca-certificates, ...).
	ClassAppBundle Class = "app-bundle"
	// ClassNSSDB is an NSS certificate database (cert8.db / cert9.db). Its
	// trust flags are per certificate and are not parsed, so it is not
	// TrustedByDefault.
	ClassNSSDB Class = "nss-db"
	// ClassEmbeddedRuntime is an executable or shared object known to embed
	// its own root store (node, deno, bun, electron, chromium, libnssckbi.so, dart, ...).
	ClassEmbeddedRuntime Class = "embedded-runtime"
	// ClassEmbeddedBinary is any other executable or shared object.
	ClassEmbeddedBinary Class = "embedded-binary"
	// ClassLooseFile is anything else: a certificate file outside a known store.
	ClassLooseFile Class = "loose-file"
)

// Trust purposes a store can be limited to (Store.LimitedTo). A store
// limited to one of them does not anchor TLS server certificates.
const (
	PurposeEmailProtection = "emailProtection"
	PurposeCodeSigning     = "codeSigning"
)

// Store describes the trust store a path belongs to.
type Store struct {
	Class Class `json:"class"`
	// Name is a short human description, e.g. "Debian/Ubuntu/Alpine OpenSSL CA bundle",
	// "Python certifi bundle", "Java cacerts truststore".
	Name string `json:"name"`
	// Ecosystem groups stores: "system", "python", "java", "node", "deno",
	// "bun", "perl", "php", "ruby", "rust", "go", "dotnet", "erlang", "dart",
	// "browser", "cloud-cli", "homebrew", "other".
	Ecosystem string `json:"ecosystem"`
	// Consumers lists software that reads this store, e.g. "OpenSSL", "curl",
	// "Go (crypto/x509)", "Python ssl", "requests (via certifi)".
	Consumers []string `json:"consumers,omitempty"`
	// TrustedByDefault is true when a certificate present in this store is
	// trusted without further configuration (bundles, anchor dirs, keystores,
	// app bundles, embedded runtimes), false for source directories,
	// blocklists, NSS databases and loose files.
	TrustedByDefault bool `json:"trusted_by_default"`
	// Remediation is advice specific to this store kind. For system bundles
	// and sources it is one sentence that names no distribution commands;
	// SystemRemediation supplies the OS-specific action.
	Remediation string `json:"remediation,omitempty"`
	// SystemGenerated is true for files that the distribution's trust tooling
	// (update-ca-certificates, update-ca-trust, ca-certificates-java)
	// regenerates from its sources: the Debian/Alpine bundle, the RHEL, Arch
	// and SUSE extracted bundles and directories, and the Java cacerts
	// derived from them. Editing such a file or upgrading a JDK does not fix
	// it; the source (ca-certificates package, blocklist, configuration)
	// has to change. Generated Java cacerts carry no Java fix (FixForStore).
	SystemGenerated bool `json:"system_generated,omitempty"`
	// LimitedTo names the single purpose the store's certificates are
	// trusted for: PurposeEmailProtection for the extracted S/MIME bundles,
	// PurposeCodeSigning for the extracted code-signing bundles, "" when the
	// store is a general (TLS) trust store.
	LimitedTo string `json:"limited_to,omitempty"`
}

// Classify returns the store that the file at path (absolute, as inside the
// image root filesystem) belongs to. header holds the first bytes of the file
// (may be empty) and is used to recognise executables (ELF/PE/Mach-O magic).
func Classify(path string, header []byte) Store {
	return classify(path, header)
}

// IsBlocklistPath reports whether path lies in a directory whose contents are
// distrusted rather than trusted.
func IsBlocklistPath(path string) bool {
	return isBlocklistPath(path)
}

// DebianConf is the parsed content of /etc/ca-certificates.conf (Debian,
// Ubuntu and Alpine): one relative path per line below /usr/share/ca-certificates,
// prefixed with '!' when the certificate is deselected.
type DebianConf struct {
	// Enabled maps relative path (e.g. "mozilla/emSign_ECC_Root_CA_-_G3.crt")
	// to whether it is enabled.
	Enabled map[string]bool
}

// ParseDebianConf parses /etc/ca-certificates.conf. Comment and blank lines
// are ignored.
func ParseDebianConf(data []byte) DebianConf {
	return parseDebianConf(data)
}

// Status returns whether the source file at absPath
// (/usr/share/ca-certificates/<rel>) is enabled; known is false when the file
// is not mentioned in the configuration at all.
func (c DebianConf) Status(absPath string) (enabled, known bool) {
	return c.status(absPath)
}

// EnvHint is a trust-relevant environment variable found in the image config.
type EnvHint struct {
	Variable string `json:"variable"`
	Value    string `json:"value"`
	// Path is the trust store file or directory the variable points at, if any.
	Path string `json:"path,omitempty"`
	// Ecosystem names the consumer ("system", "python", "node", "deno", "java", ...).
	Ecosystem string `json:"ecosystem"`
	// Description explains the effect, e.g. "requests/pip read this bundle instead of certifi".
	Description string `json:"description"`
	// Warning is set for variables that weaken TLS verification altogether
	// (NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0, GIT_SSL_NO_VERIFY, ...).
	Warning bool `json:"warning"`
	// Default is set when a variable whose consumer reads the system store
	// anyway (SSL_CERT_FILE, SSL_CERT_DIR, CURL_CA_BUNDLE, GIT_SSL_CAINFO,
	// GIT_SSL_CAPATH) points at the system bundle as the catalogue classifies
	// it, or at a default OpenSSL certificate directory: the variable then
	// restates the default rather than redirecting its consumer, and
	// Description says so instead of "instead of the default system bundle".
	Default bool `json:"default,omitempty"`
}

// EnvHints extracts trust-relevant hints from "KEY=value" environment entries.
// Recognised variables include SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE,
// CURL_CA_BUNDLE, PIP_CERT, NODE_EXTRA_CA_CERTS, NODE_OPTIONS (--use-openssl-ca,
// --use-bundled-ca), GIT_SSL_CAINFO, AWS_CA_BUNDLE, DENO_CERT, CARGO_HTTP_CAINFO,
// NIX_SSL_CERT_FILE, HEX_CACERTS_PATH, PERL_LWP_SSL_CA_FILE,
// GRPC_DEFAULT_SSL_ROOTS_FILE_PATH, JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS /
// JAVA_OPTS (-Djavax.net.ssl.trustStore=), and the verification-disabling
// variables flagged with Warning.
func EnvHints(env []string) []EnvHint {
	return envHints(env)
}

// OSInfo is parsed from /etc/os-release (or /usr/lib/os-release).
type OSInfo struct {
	ID         string `json:"id"` // "debian", "ubuntu", "alpine", "rhel", "fedora", "ol", "amzn", "wolfi", ...
	IDLike     string `json:"id_like,omitempty"`
	VersionID  string `json:"version_id,omitempty"` // "12", "24.04", "3.20"
	PrettyName string `json:"pretty_name,omitempty"`
}

// ParseOSRelease parses os-release key=value content.
func ParseOSRelease(data []byte) OSInfo {
	return parseOSRelease(data)
}

// OSFamily groups a distribution by its trust-store tooling, from ID and then
// ID_LIKE: "debian" (Debian and derivatives other than Ubuntu), "ubuntu"
// (Ubuntu and derivatives), "alpine", "rhel" (RHEL, CentOS, Rocky, Alma,
// Oracle, UBI and unknown Fedora-like distributions), "fedora", "amzn"
// (Amazon Linux), "suse" (SLES, openSUSE, BCI), "arch", "wolfi"
// (Wolfi/Chainguard) or "" when unknown.
func OSFamily(os OSInfo) string {
	return string(osFamily(os))
}

// Package is an installed package relevant to trust.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Manager is "dpkg", "apk" or "rpm".
	Manager string `json:"manager"`
}

// TrustPackages are the package names worth reporting when installed.
var TrustPackages = []string{"ca-certificates", "ca-certificates-bundle", "openssl", "libssl3", "libssl3t64", "libnss3", "nss", "p11-kit", "p11-kit-trust", "ca-certificates-java", "openjdk-17-jre-headless", "default-jre-headless"}

// ParseDpkgStatus extracts installed packages named in names from
// /var/lib/dpkg/status (Status: install ok installed).
func ParseDpkgStatus(data []byte, names []string) []Package {
	return parseDpkgStatus(data, names)
}

// ParseDpkgStatusD extracts packages named in names from a
// /var/lib/dpkg/status.d/<package> file as distroless images write them: the
// same control stanzas as the status file but without a Status field, so a
// stanza without one counts as installed (a Status field, when present, is
// honoured). Feed each file of the directory through it separately and skip
// the *.md5sums files.
func ParseDpkgStatusD(data []byte, names []string) []Package {
	return parseDpkgStatusD(data, names)
}

// ParseApkInstalled extracts packages named in names from the apk database:
// /lib/apk/db/installed on Alpine, /usr/lib/apk/db/installed on
// Wolfi/Chainguard.
func ParseApkInstalled(data []byte, names []string) []Package {
	return parseApkInstalled(data, names)
}

// CompareDebVersion compares two Debian package versions (epoch:upstream-revision)
// following the dpkg algorithm; it returns -1, 0 or 1. Alpine apk versions use
// the same ordering for the versions that matter here.
func CompareDebVersion(a, b string) int {
	return compareDebVersion(a, b)
}

// CompareVersion compares two dotted or alphanumeric version strings and
// returns -1, 0 or 1. It applies the dpkg algorithm (CompareDebVersion):
// digit runs compare numerically, letters sort before other characters, '~'
// sorts before everything including the end of the string, and a leading
// "v" is ignored. That ordering is right for distribution package versions,
// PyPI date versions (2026.10.18 < 2026.10.19), Node.js, Deno, Bun, uv and
// Go releases, and JDK versions once JavaVersionMajor has normalised them
// (17.0.20.1 < 17.0.21 < 17.0.21+9 < 17.0.21.0.2). Caveat: a pre-release
// suffix after a hyphen ("1.0-rc1") is treated as a package revision and
// therefore sorts after the plain version.
func CompareVersion(a, b string) int {
	return compareVersion(a, b)
}

// JavaVersionMajor extracts the release line of a JDK version string as the
// release file or "java -version" prints it and returns the version in the
// modern dotted form, so that CompareVersion can compare it with the fixed
// versions: "17.0.20.1" -> 17, "17.0.20.1"; "21.0.9+7-LTS" -> 21; the
// legacy "1.8.0_462" -> 8, "8.0.462" (comparable with "8.0.512"-style
// strings once a fix exists). ok is false when no major version can be read.
func JavaVersionMajor(v string) (major int, normalised string, ok bool) {
	return javaVersionMajor(v)
}

// Fix records the version of a component that no longer trusts the compromised
// eMudhra material.
type Fix struct {
	// Component names the package or runtime, e.g. "ca-certificates (Debian 13)",
	// "Python certifi", "Node.js".
	Component string `json:"component"`
	// FixedVersion is the first fixed version; several alternatives are
	// separated by " / " when a component has parallel release lines. It is
	// empty when no fixed release exists yet (see Note).
	FixedVersion string `json:"fixed_version"`
	// Reference is a URL for the advisory or release.
	Reference string `json:"reference,omitempty"`
	// Note qualifies the fix: "pending", an unconfirmed release, a
	// recommended later version, a caveat such as "requires Ubuntu Pro".
	Note string `json:"note,omitempty"`
}

// LineFix is the fix for one release line of a component (Node.js 22, Java
// 17, Go 1.27, ...), as the per-line functions below return it.
type LineFix struct {
	// Component is the EcosystemFixes component name ("Node.js", "Deno", ...).
	Component string `json:"component"`
	// Line is the release line ("22", "17", "1.27"); "" for components with
	// a single line (certifi, pip, Deno, Bun, uv).
	Line string `json:"line,omitempty"`
	// FixedVersion is the first fixed version in the line, "" when the line
	// has no fixed release (EOL lines, Java 8 as of the data date).
	FixedVersion string `json:"fixed_version,omitempty"`
	// Reference is the release post or advisory for the line.
	Reference string `json:"reference,omitempty"`
	// Note qualifies the fix: unconfirmed release, recommended later version,
	// missing fix and what to do instead.
	Note string `json:"note,omitempty"`
	// EOL is true when the line is end-of-life (or not a release line) and
	// has no fixed release; Note names the lines to move to.
	EOL bool `json:"eol,omitempty"`
}

// NodeFix returns the fix for a Node.js release line: 22, 24 and 26 have a
// security release (FixedVersion, with the per-line release post as
// Reference); every other line is end-of-life with no fixed release
// (FixedVersion "", EOL true, Note naming the fixed lines).
func NodeFix(major int) LineFix {
	return nodeFix(major)
}

// JavaFix returns the fix for a Java release line covered by the OpenJDK
// advisory of 2026-10-21 (CVE-2026-91403): 27 -> 27.0.1.0.2, 25 -> 25.0.5.0.2,
// 21 -> 21.0.13.0.2, 17 -> 17.0.21.0.2, 11 -> 11.0.33.0.2 (Note: expected,
// not yet tagged), 8 -> FixedVersion "" with a Note that no fixed 8u release
// exists (8u512 and earlier are affected) and the blocked.certs mitigation.
// ok is false for other lines.
func JavaFix(major int) (LineFix, bool) {
	return javaFix(major)
}

// GoFix returns the fix for a Go release line: 1.27 -> 1.27.3, 1.26 -> 1.26.10
// (crypto/x509 blocks the compromised keys, CVE-2026-111943); older lines are
// EOL with no fixed release (Note says which toolchain to build with); lines
// newer than the data date have FixedVersion "" and a Note.
func GoFix(major, minor int) LineFix {
	return goFix(major, minor)
}

// CertifiFix returns the Python certifi fix: 2026.10.18 is the first release
// without the compromised root; Note recommends 2026.10.19, which restores
// the unaffected emSign G1/C1/C3 roots.
func CertifiFix() LineFix {
	return certifiFix()
}

// PipFix returns the pip fix: 26.2.2 is the first pip vendoring a fixed certifi.
func PipFix() LineFix {
	return pipFix()
}

// DenoFix returns the Deno fix (2.9.8).
func DenoFix() LineFix {
	return denoFix()
}

// BunFix returns the Bun fix (1.4.4).
func BunFix() LineFix {
	return bunFix()
}

// UVFix returns the uv fix: 0.13.4 replaced the bundled roots; Note says
// that 0.13.5 additionally blocks the compromised keys.
func UVFix() LineFix {
	return uvFix()
}

// CACertificatesFix returns the fixed ca-certificates (or equivalent) package
// version for the detected operating system, if known. ok is false for
// distributions without a fixed release; the returned Fix may still name the
// component and carry a Note ("pending" for Red Hat, "no fixed version known"
// for Amazon Linux, SUSE and Wolfi/Chainguard) so that the status can be shown.
func CACertificatesFix(os OSInfo) (fix Fix, ok bool) {
	return caCertificatesFix(os)
}

// EcosystemFixes lists fixed versions of runtimes and libraries that ship their
// own trust store or an SPKI blocklist (Go, Node.js, Python certifi, pip, uv,
// Java, Rust webpki-roots / rustls-webpki, Deno, Bun, Electron, Perl
// Mozilla::CA, PHP composer/ca-bundle, NSS, Firefox, Homebrew, Arch, Fedora,
// Alpine, Debian, Ubuntu, Red Hat, Amazon Linux, SUSE, Wolfi, Erlang certifi).
// Entries without a fixed release have an empty FixedVersion and a Note. The
// versions are the same ones the per-line functions return.
func EcosystemFixes() []Fix {
	return ecosystemFixesCopy()
}

// SystemFacts describes what the scan engine learned about the image's
// system trust-store tooling; SystemRemediation phrases its advice from it.
type SystemFacts struct {
	// HasDebianConf is true when /etc/ca-certificates.conf exists in the
	// image (Debian, Ubuntu, Alpine with the full ca-certificates package).
	HasDebianConf bool
	// HasUpdateCACertificates is true when the update-ca-certificates
	// program exists in the image.
	HasUpdateCACertificates bool
	// HasPackageManager is true when the image can install packages (apt,
	// apk, dnf/yum/microdnf, zypper or pacman present). Distroless and
	// scratch-based images carry package metadata at most, not a manager,
	// and get "rebuild on a newer base" advice.
	HasPackageManager bool
	// Packages are the trust-relevant packages found installed (ParseDpkgStatus,
	// ParseDpkgStatusD, ParseApkInstalled); on Alpine they decide whether
	// only ca-certificates-bundle or the full ca-certificates is present.
	Packages []Package
}

// SystemRemediation returns one OS-appropriate action sentence for a
// certificate found in the system trust store (system bundle, source
// directory or generated keystore): the package upgrade with its fixed
// version and the distribution's command, the interim deselect/blocklist
// workaround where the image has the tooling for it, "fix pending" or "no
// fixed version known" where that is the state of the distribution, and
// "rebuild on a newer base image or strip the certificate at build time"
// for images without a package manager.
func SystemRemediation(os OSInfo, facts SystemFacts) string {
	return systemRemediation(os, facts)
}

// KnownRuntimeBinary reports whether the executable at path is known to embed
// its own root store, and names the runtime ("Node.js", "Deno", "Bun",
// "Electron", "Chromium", "NSS builtin roots (libnssckbi)", "Dart", ...).
func KnownRuntimeBinary(path string) (runtime string, ok bool) {
	return knownRuntimeBinary(path)
}
