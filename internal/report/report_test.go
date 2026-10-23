package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Yanni8/emudhra-contaianer-scanner/internal/blocklist"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/certs"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/scan"
	"github.com/Yanni8/emudhra-contaianer-scanner/internal/stores"
)

func boolPtr(b bool) *bool { return &b }

// sampleResult is a result with every rendering path the text report has:
// long package rows with notes and paths, a store path longer than the
// table width, a compromised-key and an anchor finding in one file with
// different remediations, an issued-by finding, an SPKI-only finding,
// purpose-limited trust, a parser note with repeated offsets, a collapsible
// source directory, an unreadable keystore and more than twenty warnings.
func sampleResult() *scan.Result {
	bundle := stores.Classify("/etc/ssl/certs/ca-certificates.crt", nil)
	node := stores.Classify("/usr/local/bin/node", []byte{0x7f, 'E', 'L', 'F'})
	blocklistDir := stores.Classify("/etc/pki/ca-trust/source/blocklist/em.pem", nil)
	source := stores.Classify("/usr/share/ca-certificates/mozilla/A.crt", nil)
	loose := stores.Classify("/opt/app/server.pem", nil)
	warnings := []string{"/opt/app/keystore.p12: pkcs12: none of the 4 supplied passwords opened the file: SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: incorrect password"}
	for i := 1; i <= 24; i++ {
		warnings = append(warnings, fmt.Sprintf("/opt/fixtures/broken-%02d.pem: PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser", i))
	}
	return &scan.Result{
		Scanner: scan.Scanner{Name: "emudhra-container-scanner", Version: "1.2.3", BlocklistVersion: "2026-10-22"},
		Image:   scan.ImageInfo{Reference: "index.docker.io/library/python:3.12-slim", Digest: "sha256:abc", Platform: "linux/amd64", Layers: 5, CompressedSize: 50 << 20},
		OS:      stores.OSInfo{ID: "debian", VersionID: "12", PrettyName: "Debian GNU/Linux 12 (bookworm)"},
		Packages: []scan.PackageStatus{
			{Name: "ca-certificates", Version: "20230311", Manager: "dpkg", FixedVersion: "20250419~deb12u2", Outdated: boolPtr(true), Reference: "https://example.invalid/dsa"},
			{Name: "openssl", Version: "3.0.15", Manager: "dpkg"},
			{Name: "java (Eclipse Adoptium)", Version: "17.0.12", Manager: "jre", FixedVersion: "17.0.21.0.2", Outdated: boolPtr(true), Path: "/opt/java/openjdk"},
			{Name: "node", Version: "20.20.2", Manager: "node", Outdated: boolPtr(true), Note: "Node.js 20 is end-of-life with no fixed release: use 22.23.4, 24.22.1 or 26.12.1", Path: "/usr/local/include/node/node_version.h"},
			{Name: "pip", Version: "25.0.1", Manager: "pip", FixedVersion: "26.2.2", Outdated: boolPtr(true), Path: "/usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info"},
			{Name: "certifi", Version: "2026.10.18", Manager: "pip", FixedVersion: "2026.10.18", Outdated: boolPtr(false), Note: "2026.10.19 recommended: it restores the unaffected emSign G1/C1/C3 roots"},
		},
		EnvHints: []stores.EnvHint{
			{Variable: "SSL_CERT_FILE", Value: "/etc/ssl/certs/ca-certificates.crt", Path: "/etc/ssl/certs/ca-certificates.crt", Ecosystem: "system", Description: "OpenSSL loads this file"},
			{Variable: "NODE_TLS_REJECT_UNAUTHORIZED", Value: "0", Ecosystem: "node", Description: "Node.js does not verify TLS certificates at all", Warning: true},
		},
		Stores: []scan.StoreSummary{
			{Path: "/etc/ssl/certs/ca-certificates.crt", Class: bundle.Class, Name: bundle.Name, Ecosystem: "system", Aliases: []string{"/etc/ssl/cert.pem"}, Certificates: 140, Duplicates: 2, Findings: 2},
			{Path: "/usr/local/bin/node", Class: node.Class, Name: node.Name, Ecosystem: "node", Certificates: 130, Findings: 1},
			{Path: "/etc/pki/ca-trust/source/blocklist/em.pem", Class: blocklistDir.Class, Name: blocklistDir.Name, Ecosystem: "system", Certificates: 1, Findings: 1},
			{Path: "/opt/other/bundle.pem", Class: stores.ClassLooseFile, Name: "x", Ecosystem: "other", Certificates: 3},
			{Path: "/etc/pki/ca-trust/extracted/pem/directory-hash/emSign_ECC_Root_CA_-_G3.pem", Class: stores.ClassSystemBundle, Name: "hash dir", Ecosystem: "system", Certificates: 1, Findings: 1,
				Aliases: []string{"/etc/pki/ca-trust/extracted/pem/directory-hash/14bc7599.0", "/etc/pki/ca-trust/extracted/pem/directory-hash/emSign_ECC_Root_CA_-_G3.pem.0", "/etc/pki/tls/certs/emSign_ECC_Root_CA_-_G3.pem"}},
			{Path: "/usr/share/ca-certificates/mozilla/A.crt", Class: source.Class, Name: source.Name, Ecosystem: "system", Certificates: 1, Aliases: []string{"/etc/ssl/certs/A.pem"}},
			{Path: "/usr/share/ca-certificates/mozilla/B.crt", Class: source.Class, Name: source.Name, Ecosystem: "system", Certificates: 1, Aliases: []string{"/etc/ssl/certs/B.pem"}},
			{Path: "/usr/share/ca-certificates/mozilla/C.crt", Class: source.Class, Name: source.Name, Ecosystem: "system", Certificates: 1},
			{Path: "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", Class: source.Class, Name: source.Name, Ecosystem: "system", Certificates: 1, Findings: 1},
			{Path: "/srv/bundle.crt", Class: bundle.Class, Name: bundle.Name, Ecosystem: "system", ClassifiedBy: "/etc/ssl/certs/ca-bundle.crt", Aliases: []string{"/etc/ssl/certs/ca-bundle.crt"}, Certificates: 2},
			{Path: "/opt/app/server.pem", Class: loose.Class, Name: loose.Name, Ecosystem: "other", Certificates: 1, Findings: 1},
			{Path: "/opt/app/keystore.p12", Class: stores.ClassJavaKeystore, Name: "Java truststore (PKCS#12)", Ecosystem: "java"},
		},
		Findings: []scan.Finding{
			{Severity: blocklist.SeverityCritical, Category: blocklist.CategoryCompromisedKey, Match: blocklist.MatchFingerprint, EntryID: "em-dv-tls-ca-g3b", EntryName: "EM DV TLS CA - G3B", Path: "/etc/ssl/certs/ca-certificates.crt", Aliases: []string{"/etc/ssl/cert.pem"}, Store: bundle,
				Certificate: scan.CertInfo{Subject: "CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL", SHA256: strings.Repeat("42", 32), SPKISHA256: strings.Repeat("eb", 32), NotBefore: time.Date(2025, 4, 30, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 4, 28, 0, 0, 0, 0, time.UTC), Kind: certs.KindPEM, Offset: 859},
				Trust:       scan.TrustInfo{State: scan.TrustTrusted, Detail: "bundle"},
				Explanation: `This is byte-for-byte the listed certificate "EM DV TLS CA - G3B" (compromised-key). The entry matters because its private key is public knowledge. Trust: trusted (bundle). The same certificate appears again at offset 2100, 3000 of this file. Parser note: pkcs12 opened with password "changeit".`,
				Remediation: "Remove it.", References: []string{"https://example.invalid/bug", "https://example.invalid/advisory"}},
			{Severity: blocklist.SeverityHigh, Category: blocklist.CategoryAnchor, Match: blocklist.MatchFingerprint, EntryID: "emsign-ecc-root-ca-g3", EntryName: "emSign ECC Root CA - G3", Path: "/etc/ssl/certs/ca-certificates.crt", Aliases: []string{"/etc/ssl/cert.pem"}, Store: bundle,
				Certificate: scan.CertInfo{Subject: "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN", SHA256: strings.Repeat("ab", 32), SPKISHA256: strings.Repeat("cd", 32), NotBefore: time.Date(2018, 2, 18, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2043, 2, 18, 0, 0, 0, 0, time.UTC), Kind: certs.KindPEM, Offset: 1234},
				Trust:       scan.TrustInfo{State: scan.TrustTrusted, Detail: "selected by SSL_CERT_FILE", Purposes: []string{"serverAuth", "clientAuth"}},
				Explanation: "This is byte-for-byte the listed certificate. Trust: trusted (selected by SSL_CERT_FILE).", Remediation: "Upgrade ca-certificates.", References: []string{"https://example.invalid/bug"}},
			{Severity: blocklist.SeverityHigh, Category: blocklist.CategoryAnchor, Match: blocklist.MatchFingerprint, EntryID: "emsign-ecc-root-ca-g3", EntryName: "emSign ECC Root CA - G3", Path: "/usr/local/bin/node", Store: node,
				Certificate: scan.CertInfo{Subject: "CN=emSign ECC Root CA - G3", SHA256: strings.Repeat("ab", 32), Kind: certs.KindDER, Offset: 99},
				Trust:       scan.TrustInfo{State: scan.TrustEmbedded, Detail: "compiled into Node.js"}, Explanation: "x", Remediation: "Upgrade Node.js."},
			{Severity: blocklist.SeverityMedium, Category: blocklist.CategoryIssuedBy, Match: blocklist.MatchIssuedBy, EntryID: "em-dv-tls-ca-g3b", EntryName: "api.example.com", IssuerEntryID: "em-dv-tls-ca-g3b", IssuerEntryName: "EM DV TLS CA - G3B", Path: "/opt/app/server.pem", Store: loose,
				Certificate: scan.CertInfo{Subject: "CN=api.example.com", SHA256: strings.Repeat("77", 32), Kind: certs.KindPEM, Offset: 0},
				Trust:       scan.TrustInfo{State: scan.TrustTrusted, Detail: "loose file", Purposes: []string{}}, Explanation: "issued by a compromised CA. Trust: trusted (loose file).", Remediation: "Replace it."},
			{Severity: blocklist.SeverityLow, Category: blocklist.CategoryRelated, Match: blocklist.MatchFingerprint, EntryID: "emsign-root-ca-g1", EntryName: "emSign Root CA - G1", Path: "/etc/ssl/certs/ca-certificates.crt", Store: bundle,
				Certificate: scan.CertInfo{Subject: "CN=emSign Root CA - G1", SHA256: strings.Repeat("ef", 32), Kind: certs.KindPEM, Offset: 5678},
				Trust:       scan.TrustInfo{State: scan.TrustTrusted, Detail: "bundle"}, Explanation: "related", Remediation: "none"},
			{Severity: blocklist.SeverityInfo, Category: blocklist.CategoryCompromisedKey, Match: blocklist.MatchSPKI, EntryID: "em-dv-tls-ca-g3b", EntryName: "EM DV TLS CA - G3B", Path: "/etc/pki/ca-trust/source/blocklist/em.pem", Store: blocklistDir,
				Certificate: scan.CertInfo{Subject: "CN=EM DV TLS CA - G3B", SPKISHA256: strings.Repeat("12", 32), Kind: certs.KindSPKI, Offset: 2010},
				Trust:       scan.TrustInfo{State: scan.TrustDistrusted, Detail: "blocklist directory"}, Explanation: "distrusted", Remediation: "No action needed."},
		},
		Summary: scan.Summary{FilesScanned: 1200, BytesScanned: 123456789, CertificatesFound: 274, AffectedCertificates: 4,
			FindingsBySeverity: map[string]int{"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1}, MaxSeverity: "critical",
			SystemBundleFound: true, PackageDatabase: "dpkg", DurationMS: 1500},
		Warnings: warnings,
	}
}

func TestWriteText(t *testing.T) {
	r := sampleResult()
	var buf bytes.Buffer
	if err := WriteText(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"emudhra-container-scanner 1.2.3 (blocklist 2026-10-22)",
		"Image:     index.docker.io/library/python:3.12-slim",
		"Digest:    sha256:abc",
		"Platform:  linux/amd64 (5 layers, 50 MiB compressed)",
		"OS:        Debian GNU/Linux 12 (bookworm)\n",
		"Packages (dpkg):\n",
		// Rows share one set of columns, whatever their length; the verdict
		// column reads ok / OUTDATED / no fix tracked, and notes and paths
		// follow on continuation lines.
		"  ca-certificates          20230311    dpkg  OUTDATED: fixed in 20250419~deb12u2\n",
		"  openssl                  3.0.15      dpkg  no fix tracked\n",
		"  java (Eclipse Adoptium)  17.0.12     jre   OUTDATED: fixed in 17.0.21.0.2\n      from: /opt/java/openjdk\n",
		"  node                     20.20.2     node  OUTDATED: no fixed release in this line\n      note: Node.js 20 is end-of-life with no fixed release: use 22.23.4, 24.22.1 or 26.12.1\n      from: /usr/local/include/node/node_version.h\n",
		"  pip                      25.0.1      pip   OUTDATED: fixed in 26.2.2\n      from: /usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info\n",
		"  certifi                  2026.10.18  pip   ok (fixed in 2026.10.18)\n      note: 2026.10.19 recommended: it restores the unaffected emSign G1/C1/C3 roots\n",
		"WARNING NODE_TLS_REJECT_UNAUTHORIZED=0",
		"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"Findings (1 critical, 2 high, 1 medium, 1 low, 1 info; 4 distinct certificates):",
		"/etc/ssl/certs/ca-certificates.crt\n  [CRITICAL] EM DV TLS CA - G3B (compromised-key, fingerprint match)",
		"         found:   pem at offset 859 (also at offset 2100, 3000)\n",
		"         note:    pkcs12 opened with password \"changeit\"\n",
		"  [HIGH] emSign ECC Root CA - G3 (anchor, fingerprint match)",
		"sha256:  " + strings.Repeat("ab", 32),
		"trust:   trusted - selected by SSL_CERT_FILE",
		"         trusted for: serverAuth, clientAuth\n",
		"valid:   2018-02-18 to 2043-02-18",
		"found:   pem at offset 1234\n",
		"aliases: /etc/ssl/cert.pem",
		"store: Debian/Ubuntu/Alpine OpenSSL CA bundle (system-bundle, system); consumers: OpenSSL",
		"\n         wget, Go (crypto/x509)",
		// Two findings in one file with different advice: both are printed.
		"  remediation for EM DV TLS CA - G3B: Remove it.\n  remediation for emSign ECC Root CA - G3: Upgrade ca-certificates.\n",
		"/usr/local/bin/node\n  [HIGH]",
		"trust:   embedded - compiled into Node.js",
		"found:   der at offset 99\n",
		"  remediation: Upgrade Node.js.\n",
		"/opt/app/server.pem\n  [MEDIUM] api.example.com issued by EM DV TLS CA - G3B (issued-by, issued-by match)",
		"         trusted for: none of the standard purposes\n",
		"Low/info findings (related roots, distrusted or disabled copies, heuristics; run with --verbose for details):",
		"  [LOW] emSign Root CA - G1 (related) in /etc/ssl/certs/ca-certificates.crt (trusted)\n",
		"  [INFO] EM DV TLS CA - G3B (compromised-key) in /etc/pki/ca-trust/source/blocklist/em.pem (distrusted, spki match)\n",
		"Summary:", "critical  1", "high      2", "medium    1", "low       1", "info      1",
		"274 certificates in 1200 files scanned (117.7 MiB), 11 stores with certificates, 1500 ms",
		// Counts first, so the variable-length path never breaks the columns.
		"Stores with findings:\n  certificates  findings  class             path\n",
		"             1         1  system-blocklist  /etc/pki/ca-trust/source/blocklist/em.pem\n",
		"             1         1  system-bundle     /etc/pki/ca-trust/extracted/pem/directory-hash/emSign_ECC_Root_CA_-_G3.pem\n                          also: /etc/pki/ca-trust/extracted/pem/directory-hash/14bc7599.0,\n",
		"      140 (+2)         2  system-bundle     /etc/ssl/certs/ca-certificates.crt\n                          also: /etc/ssl/cert.pem\n",
		"           130         1  embedded-runtime  /usr/local/bin/node\n",
		"             1         1  system-source     /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt\n",
		"  (+N): further copies of the same certificates in the file\n",
		"Warnings (25):", "  - /opt/app/keystore.p12: pkcs12: none of the 4 supplied passwords",
		"  - /opt/fixtures/broken-19.pem", "  ... 5 more (run with --verbose)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"\x1b[", "/opt/other/bundle.pem", "why:", "refs:", "/opt/fixtures/broken-24.pem", "Note:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("non-verbose text report contains %q\n%s", unwanted, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 120 {
			t.Errorf("line too long (%d): %s", len(line), line)
		}
	}

	buf.Reset()
	if err := WriteText(&buf, r, true); err != nil {
		t.Fatal(err)
	}
	verbose := buf.String()
	for _, want := range []string{
		"      ref:  https://example.invalid/dsa\n",
		"         why:     This is byte-for-byte the listed certificate \"EM DV TLS CA - G3B\" (compromised-key). The\n                  entry matters because its private key is public knowledge.\n",
		"         refs:    https://example.invalid/bug, https://example.invalid/advisory\n",
		"         why:     x\n",
		"Low/info findings (related roots, distrusted or disabled copies, heuristics):\n",
		"  [LOW] emSign Root CA - G1 (related, fingerprint match)",
		"  [INFO] EM DV TLS CA - G3B (compromised-key, spki match)\n         subject: CN=EM DV TLS CA - G3B\n         spki:    " + strings.Repeat("12", 32) + " (public key only)\n         trust:   distrusted - blocklist directory\n         found:   spki at offset 2010\n",
		"Stores scanned (11 with certificates):\n  certificates  findings  class             path\n",
		"             3         0  loose-file        /opt/other/bundle.pem\n",
		"             0         0  java-keystore     /opt/app/keystore.p12\n",
		"             2         0  system-bundle     /srv/bundle.crt\n                          classified by link name: /etc/ssl/certs/ca-bundle.crt\n                          also: /etc/ssl/certs/ca-bundle.crt\n",
		// Source files without findings collapse into one row per directory;
		// the one with a finding keeps its own row.
		"             3         0  system-source     /usr/share/ca-certificates/mozilla/ (3 files)\n",
		"             1         1  system-source     /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt\n",
		"Warnings (25):", "  - /opt/fixtures/broken-24.pem",
	} {
		if !strings.Contains(verbose, want) {
			t.Errorf("verbose report lacks %q\n%s", want, verbose)
		}
	}
	for _, unwanted := range []string{"/usr/share/ca-certificates/mozilla/A.crt", "/etc/ssl/certs/A.pem", "... 5 more"} {
		if strings.Contains(verbose, unwanted) {
			t.Errorf("verbose report contains %q\n%s", unwanted, verbose)
		}
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	r := &scan.Result{
		Scanner: scan.Scanner{Name: "x", Version: "v", BlocklistVersion: "b"},
		Summary: scan.Summary{FindingsBySeverity: map[string]int{}, PackageDatabase: "none", FilesScanned: 2587},
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"OS:        unknown (no os-release)",
		"Packages:  none found (no dpkg, apk or rpm database in the image; package versions were not determined)",
		"Findings: none. No certificate at all was found in the image.",
		"Note: the image carries no system CA bundle (no ca-certificates package). Programs in it cannot verify TLS\n      peers unless they bring their own trust store.\n",
		"Stores with findings: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	if got := ExitLine(r, blocklist.SeverityHigh, true); got != "Exit code: 0 (no findings)" {
		t.Errorf("ExitLine = %q", got)
	}
	s := sampleResult()
	if got := ExitLine(s, blocklist.SeverityHigh, true); !strings.HasPrefix(got, "Exit code: 2 (findings at or above high; highest is critical)") {
		t.Errorf("ExitLine = %q", got)
	}
	if got := ExitLine(s, blocklist.SeverityCritical, true); got != "Exit code: 2 (findings at or above critical; highest is critical)" {
		t.Errorf("ExitLine = %q", got)
	}
	s.Findings[0].Severity = blocklist.SeverityHigh
	if got := ExitLine(s, blocklist.SeverityCritical, true); !strings.HasPrefix(got, "Exit code: 0 (no findings at or above critical") {
		t.Errorf("ExitLine = %q", got)
	}
	if got := ExitLine(s, blocklist.SeverityInfo, false); got != "Exit code: 0 (--fail-on never)" {
		t.Errorf("ExitLine = %q", got)
	}

	// Verbose: an empty store list is not "nothing examined".
	buf.Reset()
	if err := WriteText(&buf, r, true); err != nil {
		t.Fatal(err)
	}
	if want := "Stores scanned: no file holding certificates among the 2587 files examined"; !strings.Contains(buf.String(), want) {
		t.Errorf("verbose report lacks %q\n%s", want, buf.String())
	}
}

func TestNoFindingsWording(t *testing.T) {
	ubuntu := stores.OSInfo{ID: "ubuntu", VersionID: "24.04", PrettyName: "Ubuntu 24.04.3 LTS"}
	fix, ok := stores.CACertificatesFix(ubuntu)
	if !ok || fix.FixedVersion == "" {
		t.Fatalf("no fixed ca-certificates for %+v", ubuntu)
	}
	store := scan.StoreSummary{Path: "/opt/app/truststore.p12", Class: stores.ClassJavaKeystore, Name: "Java truststore (PKCS#12)", Ecosystem: "java", Certificates: 5}
	keystoreWarning := "/opt/app/keystore.p12: pkcs12: none of the 4 supplied passwords opened the file: SafeContents #0 (encrypted, PBES2 with AES-256-CBC) could not be read: incorrect password"
	caPackage := scan.PackageStatus{Name: "ca-certificates", Version: "20240203", Manager: "dpkg", FixedVersion: fix.FixedVersion, Outdated: boolPtr(true)}
	tests := []struct {
		name     string
		result   *scan.Result
		want     []string
		unwanted []string
	}{
		{
			name:   "no store, no package: names the version to add",
			result: &scan.Result{OS: ubuntu, Summary: scan.Summary{PackageDatabase: "dpkg"}, Packages: []scan.PackageStatus{{Name: "libssl3t64", Version: "3.0.13", Manager: "dpkg"}}},
			want: []string{
				"Packages (dpkg):\n  libssl3t64  3.0.13  dpkg  no fix tracked\n",
				"Findings: none. No certificate at all was found in the image.",
				"Note: the image carries no system CA bundle (no ca-certificates package). Programs in it cannot verify TLS\n      peers unless they bring their own trust store. If one is added, use " + fix.Component + "\n      " + fix.FixedVersion + " or later.\n",
			},
		},
		{
			name:     "package installed but no bundle file",
			result:   &scan.Result{OS: ubuntu, Summary: scan.Summary{PackageDatabase: "dpkg"}, Packages: []scan.PackageStatus{caPackage}},
			want:     []string{"Note: no system CA bundle was found although ca-certificates 20240203 (dpkg) is installed: the bundle file is\n      missing or lives at a path the scanner does not know. Programs in it cannot verify TLS peers unless they\n      bring their own trust store.\n"},
			unwanted: []string{"If one is added"},
		},
		{
			name:     "bundle found: no note",
			result:   &scan.Result{OS: ubuntu, Summary: scan.Summary{PackageDatabase: "dpkg", SystemBundleFound: true}, Stores: []scan.StoreSummary{store}},
			want:     []string{"Findings: none. No certificate affected by the eMudhra compromise was found in any of the 1 store that hold\n          certificates.\n"},
			unwanted: []string{"Note:"},
		},
		{
			name:   "unreadable keystore counted",
			result: &scan.Result{OS: ubuntu, Summary: scan.Summary{SystemBundleFound: true, PackageDatabase: "dpkg"}, Stores: []scan.StoreSummary{store, {Path: "/opt/app/keystore.p12", Class: stores.ClassJavaKeystore}}, Warnings: []string{keystoreWarning, keystoreWarning}},
			want:   []string{"Findings: none in the 1 store that could be read; 1 file could not be inspected (see Warnings).\n", "Warnings (2):"},
		},
		{
			name:   "nothing readable at all",
			result: &scan.Result{OS: ubuntu, Summary: scan.Summary{SystemBundleFound: true}, Warnings: []string{keystoreWarning, "/opt/big.p12: file is larger than the whole-file parser limit; only carving it for DER certificates", "/opt/x.pem: PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser"}},
			want:   []string{"Findings: none in the files that could be read; 2 files could not be inspected (see Warnings).\n"},
		},
		{
			name:   "rpm database not parsed",
			result: &scan.Result{OS: stores.OSInfo{ID: "fedora", VersionID: "41", PrettyName: "Fedora Linux 41 (Container Image)"}, Summary: scan.Summary{SystemBundleFound: true, PackageDatabase: "rpm (sqlite, not parsed: /var/lib/rpm/rpmdb.sqlite is larger than the 256.0 MiB limit)"}},
			want:   []string{"OS:        Fedora Linux 41 (Container Image)\n", "Packages:  not determined: rpm (sqlite, not parsed: /var/lib/rpm/rpmdb.sqlite is larger than the 256.0 MiB\n           limit)\n"},
		},
		{
			name:   "database read but no trust package",
			result: &scan.Result{OS: ubuntu, Summary: scan.Summary{SystemBundleFound: true, PackageDatabase: "apk"}},
			want:   []string{"Packages:  no trust-relevant package is installed (database: apk)\n"},
		},
		{
			name:   "runtime rows without a package database",
			result: &scan.Result{OS: ubuntu, Summary: scan.Summary{SystemBundleFound: true, PackageDatabase: "none"}, Packages: []scan.PackageStatus{{Name: "deno", Version: "2.9.8", Manager: "deno", FixedVersion: "2.9.8", Outdated: boolPtr(false), Path: "DENO_VERSION (image environment)"}}},
			want:   []string{"Packages (no dpkg, apk or rpm database in the image; runtime versions only):\n  deno  2.9.8  deno  ok (fixed in 2.9.8)\n      from: DENO_VERSION (image environment)\n"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.Summary.FindingsBySeverity == nil {
				tt.result.Summary.FindingsBySeverity = map[string]int{}
			}
			var buf bytes.Buffer
			if err := WriteText(&buf, tt.result, false); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("report lacks %q\n%s", want, out)
				}
			}
			for _, unwanted := range tt.unwanted {
				if strings.Contains(out, unwanted) {
					t.Errorf("report contains %q\n%s", unwanted, out)
				}
			}
		})
	}
}

func TestBundleNoteWithFindings(t *testing.T) {
	// The note is an image-level fact, printed with or without findings.
	r := sampleResult()
	r.Summary.SystemBundleFound = false
	r.Packages = nil
	var buf bytes.Buffer
	if err := WriteText(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if want := "Findings (1 critical, 2 high, 1 medium, 1 low, 1 info; 4 distinct certificates):\nNote: the image carries no system CA bundle (no ca-certificates package)."; !strings.Contains(out, want) {
		t.Errorf("report lacks %q\n%s", want, out)
	}
}

func TestOSLine(t *testing.T) {
	tests := []struct {
		os   stores.OSInfo
		want string
	}{
		{stores.OSInfo{}, "unknown (no os-release)"},
		{stores.OSInfo{ID: "debian", VersionID: "12"}, "debian 12"},
		{stores.OSInfo{PrettyName: "Something"}, "Something"},
		{stores.OSInfo{ID: "debian", VersionID: "12", PrettyName: "Debian GNU/Linux 12 (bookworm)"}, "Debian GNU/Linux 12 (bookworm)"},
		{stores.OSInfo{ID: "ubuntu", VersionID: "26.04", PrettyName: "Ubuntu 26.04.1 LTS"}, "Ubuntu 26.04.1 LTS"},
		{stores.OSInfo{ID: "debian", VersionID: "12", PrettyName: "Distroless"}, "Distroless (debian 12)"},
		{stores.OSInfo{ID: "alpine", VersionID: "3.20.10", PrettyName: "Alpine Linux v3.20"}, "Alpine Linux v3.20 (alpine 3.20.10)"},
		{stores.OSInfo{ID: "amzn", VersionID: "2023", PrettyName: "Amazon Linux 2023.9.20261010"}, "Amazon Linux 2023.9.20261010 (amzn 2023)"},
		{stores.OSInfo{ID: "wolfi", VersionID: "20230201", PrettyName: "Wolfi"}, "Wolfi (wolfi 20230201)"},
		{stores.OSInfo{ID: "rhel", PrettyName: "Red Hat Enterprise Linux 9.6 (Plow)"}, "Red Hat Enterprise Linux 9.6 (Plow) (rhel)"},
	}
	for _, tt := range tests {
		if got := osLine(tt.os); got != tt.want {
			t.Errorf("osLine(%+v) = %q, want %q", tt.os, got, tt.want)
		}
	}
}

func TestPackageVerdict(t *testing.T) {
	tests := []struct {
		name string
		pk   scan.PackageStatus
		want string
	}{
		{"outdated", scan.PackageStatus{FixedVersion: "2", Outdated: boolPtr(true)}, "OUTDATED: fixed in 2"},
		{"ok", scan.PackageStatus{FixedVersion: "2", Outdated: boolPtr(false)}, "ok (fixed in 2)"},
		{"ok without version", scan.PackageStatus{Outdated: boolPtr(false)}, "ok"},
		{"EOL line", scan.PackageStatus{Outdated: boolPtr(true), Note: "Node.js 20 is end-of-life"}, "OUTDATED: no fixed release in this line"},
		{"Java 8", scan.PackageStatus{Outdated: boolPtr(true), Note: "no fixed 8u release as of 2026-10-23"}, "OUTDATED: no fixed release in this line"},
		{"no fix data", scan.PackageStatus{}, "no fix tracked"},
		{"pending", scan.PackageStatus{Note: "pending (not released as of 2026-10-23, RHSB-2026-012)"}, "pending (not released as of 2026-10-23, RHSB-2026-012)"},
		{"unknown Java line", scan.PackageStatus{Note: "no fix data for the Java 9 release line"}, "no fix data for the Java 9 release line"},
		{"not compared", scan.PackageStatus{FixedVersion: "2"}, "not compared (fix: 2)"},
	}
	for _, tt := range tests {
		if got := packageVerdict(tt.pk); got != tt.want {
			t.Errorf("%s: packageVerdict = %q, want %q", tt.name, got, tt.want)
		}
	}
	// The note is a continuation line only when it is not the verdict.
	if got := packageExtras(scan.PackageStatus{Note: "pending"}, true); len(got) != 0 {
		t.Errorf("extras for a note-only verdict = %+v", got)
	}
	got := packageExtras(scan.PackageStatus{Outdated: boolPtr(true), Note: "n", Path: "/p", Reference: "https://r"}, true)
	if len(got) != 3 || got[0].text != "n" || got[1].text != "/p" || got[2].text != "https://r" {
		t.Errorf("extras = %+v", got)
	}
	if got := packageExtras(scan.PackageStatus{Outdated: boolPtr(true), Reference: "https://r"}, false); len(got) != 0 {
		t.Errorf("non-verbose extras show the reference: %+v", got)
	}
}

func TestSplitExplanation(t *testing.T) {
	tests := []struct {
		name string
		f    scan.Finding
		want explanation
	}{
		{
			name: "all parts",
			f:    scan.Finding{Trust: scan.TrustInfo{State: "trusted"}, Explanation: `This is it. Notes: Trust: matters. Trust: trusted (detail (with parens)). The same certificate appears again at offset 10, 20 of this file. Parser note: pkcs12 opened with password "changeit".`},
			want: explanation{why: "This is it. Notes: Trust: matters.", alsoAt: "10, 20", note: `pkcs12 opened with password "changeit"`},
		},
		{
			name: "trust sentence only",
			f:    scan.Finding{Trust: scan.TrustInfo{State: "embedded"}, Explanation: "Reason. Trust: embedded (compiled in)."},
			want: explanation{why: "Reason."},
		},
		{
			name: "note without duplicates",
			f:    scan.Finding{Trust: scan.TrustInfo{State: "unknown"}, Explanation: "Reason. Trust: unknown (loose). Parser note: carved from a region of the keystore that could not be parsed."},
			want: explanation{why: "Reason.", note: "carved from a region of the keystore that could not be parsed"},
		},
		{
			name: "foreign text without markers",
			f:    scan.Finding{Trust: scan.TrustInfo{State: "trusted"}, Explanation: "  just prose  "},
			want: explanation{why: "just prose"},
		},
		{
			name: "markers without a trust sentence",
			f:    scan.Finding{Explanation: "Reason. The same certificate appears again at offset 5 of this file. Parser note: x."},
			want: explanation{why: "Reason.", alsoAt: "5", note: "x"},
		},
		{
			name: "empty",
			f:    scan.Finding{},
			want: explanation{},
		},
	}
	for _, tt := range tests {
		if got := splitExplanation(tt.f); got != tt.want {
			t.Errorf("%s: splitExplanation = %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestUnreadableFiles(t *testing.T) {
	tests := []struct {
		name     string
		warnings []string
		want     int
	}{
		{"none", nil, 0},
		{"parser rejections do not count", []string{"/a.pem: PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser"}, 0},
		{"pkcs12", []string{"/k.p12: pkcs12: no passwords were supplied for the encrypted parts: SafeContents #0 (encrypted, x)"}, 1},
		{"jks", []string{"/k.jks: jks: keystore is truncated (unexpected EOF); 3 entries read"}, 1},
		{"too large", []string{"/big: file is larger than the whole-file parser limit; only carving it for DER certificates"}, 1},
		{"long object", []string{"/x: object at offset 28487822 is longer than the buffer limit of 67108864 bytes and was skipped"}, 1},
		{"same file twice", []string{"/k.p12: pkcs12: a", "/k.p12: pkcs12: b"}, 1},
		{"rpm database is not a store", []string{"/var/lib/rpm/rpmdb.sqlite: rpm database not read: rpmdb: sqlite: bad magic"}, 0},
		{"mixed", []string{"/k.p12: pkcs12: a", "/j.jks: jks: b", "/a.pem: PEM CERTIFICATE block at offset 0 was rejected by the strict X.509 parser"}, 2},
	}
	for _, tt := range tests {
		if got := unreadableFiles(tt.warnings); got != tt.want {
			t.Errorf("%s: unreadableFiles = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestCollapseStores(t *testing.T) {
	src := stores.Classify("/usr/share/ca-certificates/mozilla/A.crt", nil)
	all := []scan.StoreSummary{
		{Path: "/usr/share/ca-certificates/mozilla/A.crt", Class: src.Class, Name: src.Name, Certificates: 1, Aliases: []string{"/etc/ssl/certs/A.pem"}},
		{Path: "/usr/share/ca-certificates/mozilla/B.crt", Class: src.Class, Name: src.Name, Certificates: 1, Duplicates: 1},
		{Path: "/usr/share/ca-certificates/mozilla/X.crt", Class: src.Class, Name: src.Name, Certificates: 1, Findings: 1},
		{Path: "/usr/share/ca-certificates/other/C.crt", Class: src.Class, Name: src.Name, Certificates: 1},
		{Path: "/usr/share/ca-certificates/mozilla/odd.pem", Class: stores.ClassLooseFile, Name: "loose", Certificates: 2},
	}
	rows := collapseStores(all)
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4: %+v", len(rows), rows)
	}
	merged := rows[0]
	if merged.path != "/usr/share/ca-certificates/mozilla/" || merged.files != 2 || merged.certificates != 2 || merged.duplicates != 1 || merged.findings != 0 || merged.aliases != nil {
		t.Errorf("merged row = %+v", merged)
	}
	if rows[1].path != "/usr/share/ca-certificates/mozilla/X.crt" || rows[1].files != 1 || rows[1].findings != 1 {
		t.Errorf("finding row = %+v", rows[1])
	}
	if rows[2].path != "/usr/share/ca-certificates/other/C.crt" || rows[2].files != 1 {
		t.Errorf("lone row = %+v", rows[2])
	}
	if rows[3].path != "/usr/share/ca-certificates/mozilla/odd.pem" || rows[3].class != stores.ClassLooseFile {
		t.Errorf("other class row = %+v", rows[3])
	}
}

func TestCountsText(t *testing.T) {
	r := &scan.Result{Summary: scan.Summary{FindingsBySeverity: map[string]int{"high": 1, "low": 2}}}
	if got := countsText(r); got != "1 high, 2 low" {
		t.Errorf("countsText = %q", got)
	}
	r.Summary.AffectedCertificates = 1
	if got := countsText(r); got != "1 high, 2 low; 1 distinct certificate" {
		t.Errorf("countsText = %q", got)
	}
	if got := countsText(&scan.Result{}); got != "none" {
		t.Errorf("countsText = %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	r := sampleResult()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"severity": "high"`, `"category": "anchor"`, `"match": "fingerprint"`, `"blocklist_version": "2026-10-22"`, `"findings_by_severity"`, `"trusted_by_default": true`, `"state": "trusted"`, `"outdated": true`, `"outdated": null`, `"issuer_entry_name": "EM DV TLS CA - G3B"`, `"purposes": [`, `"affected_certificates": 4`, `"system_bundle_found": true`, `"package_database": "dpkg"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON lacks %s", want)
		}
	}
	if strings.Contains(out, `"exit"`) {
		t.Error("JSON carries an exit block although none was recorded")
	}
	var back scan.Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != 6 || back.Findings[0].Severity != blocklist.SeverityCritical || back.Findings[5].Trust.State != scan.TrustDistrusted || back.Summary.FindingsBySeverity["high"] != 2 || back.Packages[0].Outdated == nil || !*back.Packages[0].Outdated || back.MaxSeverity() != blocklist.SeverityCritical {
		t.Errorf("round trip differs: %+v", back.Summary)
	}
	if !back.Findings[5].Certificate.NotAfter.IsZero() {
		t.Errorf("SPKI finding gained a validity: %v", back.Findings[5].Certificate.NotAfter)
	}

	r.Exit = scan.Exit{FailOn: "high", Code: 2, ExtraBlocklists: []string{"extra.pem"}}
	buf.Reset()
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\"exit\": {\n    \"fail_on\": \"high\",\n    \"code\": 2,\n    \"extra_blocklists\": [\n      \"extra.pem\"\n    ]\n  }"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("JSON lacks %s\n%s", want, buf.String())
		}
	}
}

func TestWrap(t *testing.T) {
	lines := wrap("aaaa bbbb cccc dddd eeee ffff gggg", 20)
	if strings.Join(lines, "|") != "aaaa bbbb cccc dddd|eeee ffff gggg" {
		t.Errorf("wrap = %v", lines)
	}
	if got := wrap("", 10); len(got) != 0 {
		t.Errorf("wrap empty = %v", got)
	}
	if got := wrap(strings.Repeat("x", 50), 10); len(got) != 1 {
		t.Errorf("long word = %v", got)
	}
}

func TestHang(t *testing.T) {
	var buf bytes.Buffer
	p := &printer{w: &buf}
	words := strings.Repeat("word ", 40)
	p.hang("  remediation for A, B: ", 4, words)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "  remediation for A, B: word") {
		t.Fatalf("hang output = %q", buf.String())
	}
	for i, l := range lines {
		if len(l) > width {
			t.Errorf("line %d too long: %q", i, l)
		}
		if i > 0 && !strings.HasPrefix(l, "    word") {
			t.Errorf("continuation %d not indented by 4: %q", i, l)
		}
	}
	// An empty text leaves no trailing space behind the label.
	buf.Reset()
	p.hang("  remediation: ", 4, "")
	if got := buf.String(); got != "  remediation:\n" {
		t.Errorf("empty hang = %q", got)
	}
	// A padded table prefix is never re-spaced.
	buf.Reset()
	p.hang("  name      1.0   dpkg  ", 24, "ok")
	if got := buf.String(); got != "  name      1.0   dpkg  ok\n" {
		t.Errorf("short hang = %q", got)
	}
	buf.Reset()
	p.hang("  name      1.0   dpkg  ", 24, strings.Repeat("verdict ", 20))
	if got := buf.String(); !strings.HasPrefix(got, "  name      1.0   dpkg  verdict verdict") || !strings.Contains(got, "\n"+strings.Repeat(" ", 24)+"verdict") {
		t.Errorf("long hang = %q", got)
	}
}
